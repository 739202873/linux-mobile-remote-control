#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=scripts/linux/common.sh
source "${SCRIPT_DIR}/common.sh"

NO_PULL=0
if [ "${1:-}" = "--no-pull" ]; then
    NO_PULL=1
fi

echo -e "${MRC_CYAN}====================================================${MRC_NC}"
echo -e "${MRC_CYAN}   Mobile-RC (Remote Control) - Updater             ${MRC_NC}"
echo -e "${MRC_CYAN}====================================================${MRC_NC}"

mrc_require_root "sudo ./update.sh"

INSTALL_DIR="${MRC_DEFAULT_INSTALL_DIR}"
SERVER_SRC="${REPO_ROOT}/fallback/server.py"

if [ -e /etc/NIXOS ] && [ ! -f "${INSTALL_DIR}/server.py" ]; then
    echo -e "${MRC_YELLOW}Detected declarative NixOS installation.${MRC_NC}"
    echo -e "Update with: nix flake update && sudo nixos-rebuild switch"
    exit 0
fi

if [ ! -d "${INSTALL_DIR}" ] || [ ! -f "${INSTALL_DIR}/server.py" ]; then
    echo -e "${MRC_YELLOW}Mobile-RC is not installed in ${INSTALL_DIR} yet.${MRC_NC}"
    echo -e "Running full installation instead..."
    exec bash "${SCRIPT_DIR}/install.sh"
fi

if [ ! -f "${SERVER_SRC}" ]; then
    echo -e "${MRC_RED}Error: Source file ${SERVER_SRC} not found!${MRC_NC}"
    exit 1
fi

CALLER_USER="${SUDO_USER:-${DOAS_USER:-}}"

if [ "${NO_PULL}" -eq 0 ] && [ -d "${REPO_ROOT}/.git" ] && command -v git >/dev/null 2>&1; then
    echo -e "${MRC_BLUE}1. Checking for remote updates via git...${MRC_NC}"
    REMOTES="$(mrc_run_as_repo_owner "${CALLER_USER}" git -C "${REPO_ROOT}" remote 2>/dev/null || true)"
    if [ -n "${REMOTES}" ]; then
        SELF_HASH_BEFORE="$(cat "${BASH_SOURCE[0]}" "${SCRIPT_DIR}/common.sh" 2>/dev/null | sha256sum | awk '{print $1}' || true)"
        if ! mrc_run_as_repo_owner "${CALLER_USER}" git -C "${REPO_ROOT}" pull --ff-only; then
            echo -e "${MRC_YELLOW}   Note: git pull skipped or failed; continuing with local source files.${MRC_NC}"
        fi
        SELF_HASH_AFTER="$(cat "${BASH_SOURCE[0]}" "${SCRIPT_DIR}/common.sh" 2>/dev/null | sha256sum | awk '{print $1}' || true)"
        if [ -n "${SELF_HASH_BEFORE}" ] && [ "${SELF_HASH_BEFORE}" != "${SELF_HASH_AFTER}" ]; then
            echo -e "${MRC_BLUE}   Updater script itself was updated; reloading new updater...${MRC_NC}"
            exec bash "${SCRIPT_DIR}/update.sh" --no-pull
        fi
    else
        echo -e "   (No git remote configured yet; using local source files)"
    fi
else
    echo -e "${MRC_BLUE}1. Using local source files in ${REPO_ROOT}...${MRC_NC}"
fi

PYTHON_BIN="$(mrc_find_python)"

echo -e "${MRC_BLUE}2. Validating new code syntax (without modifying repo)...${MRC_NC}"
if ! mrc_verify_python_syntax "${PYTHON_BIN}" "${SERVER_SRC}"; then
    echo -e "${MRC_RED}Error: Syntax check failed on ${SERVER_SRC}! Aborting update to protect running service.${MRC_NC}"
    exit 1
fi
echo -e "${MRC_GREEN}[OK] Syntax check passed.${MRC_NC}"

echo -e "${MRC_BLUE}3. Updating server core files & hardening permissions...${MRC_NC}"
chmod 700 "${INSTALL_DIR}"
cp -f "${INSTALL_DIR}/server.py" "${INSTALL_DIR}/server.py.bak" 2>/dev/null || true
[ -f "${INSTALL_DIR}/server.py.bak" ] && chmod 700 "${INSTALL_DIR}/server.py.bak"

HAD_OLD_RUST=0
if [ -x "${INSTALL_DIR}/mobile-rc" ]; then
    HAD_OLD_RUST=1
    cp -f "${INSTALL_DIR}/mobile-rc" "${INSTALL_DIR}/mobile-rc.bak" 2>/dev/null || true
    [ -f "${INSTALL_DIR}/mobile-rc.bak" ] && chmod 700 "${INSTALL_DIR}/mobile-rc.bak"
fi

OLD_RUNTIME=""
if [ -f "${INSTALL_DIR}/.runtime" ]; then
    OLD_RUNTIME="$(cat "${INSTALL_DIR}/.runtime" 2>/dev/null || true)"
fi

mrc_copy_support_files "${REPO_ROOT}" "${INSTALL_DIR}"

if ! mrc_resolve_runtime "${REPO_ROOT}" "${INSTALL_DIR}" "${PYTHON_BIN}" "${CALLER_USER}"; then
    if [ -f "${INSTALL_DIR}/server.py.bak" ]; then
        mv -f "${INSTALL_DIR}/server.py.bak" "${INSTALL_DIR}/server.py"
        chmod 700 "${INSTALL_DIR}/server.py"
    fi
    if [ "${HAD_OLD_RUST}" -eq 1 ] && [ -f "${INSTALL_DIR}/mobile-rc.bak" ]; then
        mv -f "${INSTALL_DIR}/mobile-rc.bak" "${INSTALL_DIR}/mobile-rc"
        chmod 700 "${INSTALL_DIR}/mobile-rc"
    fi
    exit 1
fi
echo -e "${MRC_GREEN}[OK] Core server and CLI helper files updated.${MRC_NC}"

META_OUT="$(mrc_sync_metadata "${PYTHON_BIN}" "${INSTALL_DIR}")"
TARGET_USER="$(printf '%s\n' "${META_OUT}" | sed -n '1p')"
NTFY_TOPIC="$(printf '%s\n' "${META_OUT}" | sed -n '2p')"
PIN_MODE="$(printf '%s\n' "${META_OUT}" | sed -n '3p')"
PIN_VAL="$(printf '%s\n' "${META_OUT}" | sed -n '4p')"

echo -e "${MRC_BLUE}4. Restarting & verifying Mobile-RC service...${MRC_NC}"
SVC_MODE="$(mrc_detect_installed_init)"
SVC_FILE="$(mrc_resolve_service_file "${SVC_MODE}")"
if [ -n "${SVC_FILE}" ] && [ -f "${SVC_FILE}" ]; then
    cp -f "${SVC_FILE}" "${SVC_FILE}.bak" 2>/dev/null || true
fi

mrc_stop_service "${SVC_MODE}" "${INSTALL_DIR}"
mrc_write_runtime_marker "${INSTALL_DIR}" "${MRC_ACTIVE_NAME}"
if [ "${SVC_MODE}" != "nohup" ]; then
    mrc_write_service_unit "${SVC_MODE}" "${MRC_ACTIVE_BIN}" "${MRC_ACTIVE_ARGS}" "${TARGET_USER}"
fi

if ! mrc_restart_service "${MRC_ACTIVE_BIN}" "${MRC_ACTIVE_ARGS}" "${INSTALL_DIR}" "${TARGET_USER}" "${SVC_MODE}"; then
    echo -e "${MRC_RED}Error: Mobile-RC failed to stay running after update! Rolling back...${MRC_NC}"
    mrc_stop_service "${SVC_MODE}" "${INSTALL_DIR}"
    if [ -f "${INSTALL_DIR}/server.py.bak" ]; then
        mv -f "${INSTALL_DIR}/server.py.bak" "${INSTALL_DIR}/server.py"
        chmod 700 "${INSTALL_DIR}/server.py"
    fi
    if [ "${HAD_OLD_RUST}" -eq 1 ] && [ -f "${INSTALL_DIR}/mobile-rc.bak" ]; then
        mv -f "${INSTALL_DIR}/mobile-rc.bak" "${INSTALL_DIR}/mobile-rc"
        chmod 700 "${INSTALL_DIR}/mobile-rc"
    else
        rm -f "${INSTALL_DIR}/mobile-rc" "${INSTALL_DIR}/mobile-rc.bak"
    fi
    if [ -n "${OLD_RUNTIME}" ]; then
        mrc_write_runtime_marker "${INSTALL_DIR}" "${OLD_RUNTIME}"
    else
        rm -f "${INSTALL_DIR}/.runtime"
    fi
    if [ -n "${SVC_FILE}" ] && [ -f "${SVC_FILE}.bak" ]; then
        mv -f "${SVC_FILE}.bak" "${SVC_FILE}"
    if { [ "${SVC_MODE}" = "openrc" ] || [ "${SVC_MODE}" = "runit" ]; } && [ -n "${SVC_FILE}" ]; then
        chmod 755 "${SVC_FILE}"
    fi
        [ "${SVC_MODE}" = "systemd" ] && systemctl daemon-reload || true
    fi
    if [ "${HAD_OLD_RUST}" -eq 1 ] && [ -x "${INSTALL_DIR}/mobile-rc" ] && [ "${OLD_RUNTIME}" != "python" ]; then
        mrc_restart_service "${INSTALL_DIR}/mobile-rc" "" "${INSTALL_DIR}" "${TARGET_USER}" "${SVC_MODE}" || true
    else
        mrc_restart_service "${PYTHON_BIN}" "${INSTALL_DIR}/server.py" "${INSTALL_DIR}" "${TARGET_USER}" "${SVC_MODE}" || true
    fi
    exit 1
fi

rm -f "${INSTALL_DIR}/server.py.bak" "${INSTALL_DIR}/mobile-rc.bak"
[ -n "${SVC_FILE}" ] && rm -f "${SVC_FILE}.bak"
echo -e "${MRC_GREEN}[OK] Mobile-RC restarted (${SVC_MODE}, ${MRC_ACTIVE_LABEL}) and verified running.${MRC_NC}"

rm -f /tmp/mrc_raw.png /tmp/mrc_live_shot.jpg 2>/dev/null || true

ACTIVE_PORT="${MRC_PORT:-8000}"
echo -e "\n${MRC_CYAN}====================================================${MRC_NC}"
echo -e "${MRC_GREEN}   Mobile-RC has been successfully updated!         ${MRC_NC}"
echo -e "${MRC_CYAN}====================================================${MRC_NC}"
echo -e " Runtime Engine           : ${MRC_CYAN}${MRC_ACTIVE_LABEL}${MRC_NC}"
echo -e " Access Code Mode         : ${MRC_YELLOW}${PIN_MODE} (${PIN_VAL})${MRC_NC}"
echo -e " Generate Code on PC      : ${MRC_CYAN}sudo control-access${MRC_NC}"
echo -e " Show Termux Setup Cmd    : ${MRC_CYAN}sudo control-access --setup-termux${MRC_NC}"
echo -e " Configure Email OTP      : ${MRC_CYAN}sudo control-access --setup-email${MRC_NC}"
echo -e " Local Dashboard URL      : ${MRC_CYAN}http://localhost:${ACTIVE_PORT}${MRC_NC}"
mrc_print_lan_urls "${ACTIVE_PORT}"
if [ -n "${NTFY_TOPIC}" ]; then
    echo -e " Remote ntfy.sh Topic     : ${MRC_CYAN}https://ntfy.sh/${NTFY_TOPIC}${MRC_NC}"
fi
echo -e "${MRC_CYAN}====================================================${MRC_NC}\n"

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=scripts/linux/common.sh
source "${SCRIPT_DIR}/common.sh"

echo -e "${MRC_CYAN}====================================================${MRC_NC}"
echo -e "${MRC_CYAN}     Mobile-RC (Remote Control) - Installer         ${MRC_NC}"
echo -e "${MRC_CYAN}====================================================${MRC_NC}"

mrc_require_root "sudo ./install.sh"

if [ -e /etc/NIXOS ]; then
    echo -e "${MRC_YELLOW}Detected NixOS (declarative immutable /etc).${MRC_NC}"
    echo -e "Use the included Nix Flake / NixOS module instead of this FHS installer:"
    echo -e "  services.mobile-rc.enable = true;"
    echo -e "See flake.nix and README.md (NixOS section) in this repository."
    exit 0
fi

INSTALL_DIR="${MRC_DEFAULT_INSTALL_DIR}"
SERVER_SRC="${REPO_ROOT}/fallback/server.py"
if [ ! -f "${SERVER_SRC}" ]; then
    echo -e "${MRC_RED}Error: Fallback server ${SERVER_SRC} not found!${MRC_NC}"
    exit 1
fi

echo -e "${MRC_BLUE}1. Checking Python 3...${MRC_NC}"
PYTHON_BIN="$(mrc_find_python)"
echo -e "${MRC_GREEN}[OK] Python 3 found at: ${PYTHON_BIN} ($("${PYTHON_BIN}" --version))${MRC_NC}"

echo -e "${MRC_BLUE}2. Detecting target desktop user...${MRC_NC}"
TARGET_USER="$(mrc_detect_target_user "${PYTHON_BIN}")"
echo -e "${MRC_GREEN}[OK] Target desktop user configured: ${TARGET_USER}${MRC_NC}"

echo -e "${MRC_BLUE}3. Installing application files to ${INSTALL_DIR}...${MRC_NC}"
if ! mrc_verify_python_syntax "${PYTHON_BIN}" "${SERVER_SRC}"; then
    echo -e "${MRC_RED}Error: Syntax check failed on ${SERVER_SRC}!${MRC_NC}"
    exit 1
fi
mrc_copy_support_files "${REPO_ROOT}" "${INSTALL_DIR}"

CALLER_USER="${SUDO_USER:-${DOAS_USER:-}}"
if ! mrc_resolve_runtime "${REPO_ROOT}" "${INSTALL_DIR}" "${PYTHON_BIN}" "${CALLER_USER}"; then
    exit 1
fi
mrc_write_runtime_marker "${INSTALL_DIR}" "${MRC_ACTIVE_NAME}"

META_OUT="$(mrc_sync_metadata "${PYTHON_BIN}" "${INSTALL_DIR}" "${TARGET_USER}")"
NTFY_TOPIC="$(printf '%s\n' "${META_OUT}" | sed -n '2p')"
PIN_MODE="$(printf '%s\n' "${META_OUT}" | sed -n '3p')"
echo -e "${MRC_GREEN}[OK] Secure configuration & Termux pairing token initialized (mode: ${PIN_MODE}).${MRC_NC}"

if ! command -v ssh >/dev/null 2>&1 || ! command -v ssh-keygen >/dev/null 2>&1; then
    echo -e "${MRC_YELLOW}Note: OpenSSH client (ssh/ssh-keygen) not found. Optional remote internet tunnel will require openssh.${MRC_NC}"
fi

echo -e "${MRC_BLUE}4. Configuring Autostart Service...${MRC_NC}"
SVC_MODE="$(mrc_detect_system_init)"
echo -e "   -> Detected init system: ${MRC_CYAN}${SVC_MODE}${MRC_NC}"
mrc_stop_service "${SVC_MODE}" "${INSTALL_DIR}"
if [ "${SVC_MODE}" != "nohup" ]; then
    mrc_write_service_unit "${SVC_MODE}" "${MRC_ACTIVE_BIN}" "${MRC_ACTIVE_ARGS}" "${TARGET_USER}"
fi
if mrc_enable_and_start_service "${SVC_MODE}" "${MRC_ACTIVE_BIN}" "${MRC_ACTIVE_ARGS}" "${INSTALL_DIR}" "${TARGET_USER}"; then
    echo -e "${MRC_GREEN}[OK] mobile-rc service enabled and started via ${SVC_MODE}!${MRC_NC}"
else
    echo -e "${MRC_YELLOW}Warning: service start verification failed on ${SVC_MODE}; check logs at /var/log/mobile-rc.log.${MRC_NC}"
fi

ACTIVE_PORT="${MRC_PORT:-8000}"
echo ""
echo -e "${MRC_GREEN}====================================================${MRC_NC}"
echo -e "${MRC_GREEN}   Installation Complete & Dashboard Ready!         ${MRC_NC}"
echo -e "${MRC_GREEN}====================================================${MRC_NC}"
echo -e "  Local Dashboard URL      : ${MRC_CYAN}http://localhost:${ACTIVE_PORT}${MRC_NC}"
mrc_print_lan_urls "${ACTIVE_PORT}"
echo -e "  Runtime Engine           : ${MRC_CYAN}${MRC_ACTIVE_LABEL}${MRC_NC}"
echo -e "  Access Code Mode         : ${MRC_YELLOW}${PIN_MODE}${MRC_NC}"
echo -e "  Generate Code on PC      : ${MRC_YELLOW}sudo control-access${MRC_NC}"
echo -e "  Show Termux Setup Cmd    : ${MRC_YELLOW}sudo control-access --setup-termux${MRC_NC}"
echo -e "  Setup Online Email OTP   : ${MRC_YELLOW}sudo control-access --setup-email${MRC_NC}"
if [ -n "${NTFY_TOPIC}" ]; then
    echo -e "  Remote ntfy.sh Portal    : ${MRC_CYAN}https://ntfy.sh/${NTFY_TOPIC}${MRC_NC}"
fi
echo -e "${MRC_GREEN}====================================================${MRC_NC}"
if [ -x /usr/local/bin/control-access ]; then
    /usr/local/bin/control-access --setup-termux || true
fi

#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
# Mobile-RC - Updater Script
# Safely updates server.py and restarts the background service
# while preserving your existing PIN, config, and SSH keys.
# ==========================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

run_as_repo_owner() {
    local owner_user="$1"
    shift
    if [ -n "${owner_user}" ] && [ "${owner_user}" != "root" ]; then
        if command -v runuser >/dev/null 2>&1; then
            runuser -u "${owner_user}" -- "$@"
        elif command -v sudo >/dev/null 2>&1; then
            sudo -u "${owner_user}" "$@"
        else
            su -s /bin/sh "${owner_user}" -c "$(printf '%q ' "$@")"
        fi
    else
        "$@"
    fi
}

print_lan_urls() {
    local port="$1"
    local printed=0
    if command -v ip >/dev/null 2>&1; then
        while IFS= read -r ip_addr; do
            if [ -n "${ip_addr}" ] && [[ ! "${ip_addr}" =~ ^127\. ]]; then
                echo -e "                            ${CYAN}http://${ip_addr}:${port}${NC}"
                printed=1
            fi
        done < <(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
    fi
    if [ "${printed}" -eq 0 ] && command -v hostname >/dev/null 2>&1; then
        for ip_addr in $(hostname -I 2>/dev/null || true); do
            if [[ "${ip_addr}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ ! "${ip_addr}" =~ ^127\. ]]; then
                echo -e "                            ${CYAN}http://${ip_addr}:${port}${NC}"
            fi
        done
    fi
}

restart_service() {
    local python_bin="$1"
    local install_dir="$2"
    local target_user="$3"
    local mode="$4"

    case "${mode}" in
        systemd)
            systemctl restart mobile-rc.service
            sleep 1
            systemctl is-active --quiet mobile-rc.service
            ;;
        openrc)
            rc-service mobile-rc restart
            sleep 1
            rc-service mobile-rc status >/dev/null 2>&1
            ;;
        nohup)
            pkill -f "${install_dir}/server.py" 2>/dev/null || true
            sleep 1
            nohup env MRC_USER="${target_user}" "${python_bin}" "${install_dir}/server.py" >/var/log/mobile-rc.log 2>&1 &
            sleep 1
            pgrep -f "${install_dir}/server.py" >/dev/null 2>&1
            ;;
    esac
}

main() {
    local no_pull=0
    if [ "${1:-}" = "--no-pull" ]; then
        no_pull=1
    fi

    echo -e "${CYAN}====================================================${NC}"
    echo -e "${CYAN}   🔄 Mobile-RC (Remote Control) - Updater           ${NC}"
    echo -e "${CYAN}====================================================${NC}"

    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}Error: This updater must be run as root (use sudo).${NC}"
        echo -e "Usage: sudo ./update.sh"
        exit 1
    fi

    local script_dir install_dir server_src
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    install_dir="/opt/mobile-rc"
    server_src="${script_dir}/server.py"

    if [ ! -d "${install_dir}" ] || [ ! -f "${install_dir}/server.py" ]; then
        echo -e "${YELLOW}Mobile-RC is not installed in ${install_dir} yet.${NC}"
        echo -e "Running full installation instead..."
        exec bash "${script_dir}/install.sh"
    fi

    if [ ! -f "${server_src}" ]; then
        echo -e "${RED}Error: Source file ${server_src} not found!${NC}"
        exit 1
    fi

    local caller_user="${SUDO_USER:-${DOAS_USER:-}}"

    # Optional git pull if inside a git repository with a remote configured
    if [ "${no_pull}" -eq 0 ] && [ -d "${script_dir}/.git" ] && command -v git >/dev/null 2>&1; then
        echo -e "${BLUE}1. Checking for remote updates via git...${NC}"
        local remotes
        remotes="$(run_as_repo_owner "${caller_user}" git -C "${script_dir}" remote 2>/dev/null || true)"
        if [ -n "${remotes}" ]; then
            local self_hash_before self_hash_after
            self_hash_before="$(sha256sum "${BASH_SOURCE[0]}" 2>/dev/null | awk '{print $1}' || true)"
            if ! run_as_repo_owner "${caller_user}" git -C "${script_dir}" pull --ff-only; then
                echo -e "${YELLOW}   Note: git pull skipped or failed; continuing with local source files.${NC}"
            fi
            self_hash_after="$(sha256sum "${BASH_SOURCE[0]}" 2>/dev/null | awk '{print $1}' || true)"
            if [ -n "${self_hash_before}" ] && [ "${self_hash_before}" != "${self_hash_after}" ]; then
                echo -e "${BLUE}   Updater script itself was updated; reloading new updater...${NC}"
                exec bash "${script_dir}/update.sh" --no-pull
            fi
        else
            echo -e "   (No git remote configured yet; using local source files)"
        fi
    else
        echo -e "${BLUE}1. Using local source files in ${script_dir}...${NC}"
    fi

    local python_bin
    python_bin="$(command -v python3 || true)"
    if [ -z "${python_bin}" ]; then
        echo -e "${RED}Error: Python 3 not found! Please install python3.${NC}"
        exit 1
    fi

    echo -e "${BLUE}2. Validating new code syntax (without modifying repo)...${NC}"
    local tmp_pyc
    tmp_pyc="$(mktemp /tmp/mrc_syntax.XXXXXX.pyc)"
    if ! "${python_bin}" -B -c '
import py_compile, sys
py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True)
' "${server_src}" "${tmp_pyc}"; then
        rm -f "${tmp_pyc}"
        echo -e "${RED}Error: Syntax check failed on ${server_src}! Aborting update to protect running service.${NC}"
        exit 1
    fi
    rm -f "${tmp_pyc}"
    echo -e "${GREEN}✓ Syntax check passed.${NC}"

    echo -e "${BLUE}3. Updating server core files & hardening permissions...${NC}"
    chmod 700 "${install_dir}"
    cp -f "${install_dir}/server.py" "${install_dir}/server.py.bak" 2>/dev/null || true
    [ -f "${install_dir}/server.py.bak" ] && chmod 700 "${install_dir}/server.py.bak"
    cp -f "${server_src}" "${install_dir}/server.py"
    chmod 700 "${install_dir}/server.py"
    if [ -f "${script_dir}/termux/control-access" ]; then
        cp -f "${script_dir}/termux/control-access" "${install_dir}/termux-control-access.sh"
        chmod 644 "${install_dir}/termux-control-access.sh"
    fi
    if [ -f "${script_dir}/bin/control-access" ]; then
        mkdir -p /usr/local/bin
        cp -f "${script_dir}/bin/control-access" /usr/local/bin/control-access
        chmod 755 /usr/local/bin/control-access
    fi
    rm -f /usr/local/bin/kontrol-laptop "${install_dir}/termux-kontrol-laptop.sh"
    echo -e "${GREEN}✓ Core server and CLI helper files updated.${NC}"

    # Migrate legacy keys cleanly, initialize termux_token / pin_mode if absent, & read metadata
    local meta_out target_user ntfy_topic pin_mode pin_val
    meta_out="$("${python_bin}" -B - "${install_dir}/config.json" "${install_dir}/pin.txt" << 'PYEOF'
import json, os, secrets, sys

cfg_path, pin_path = sys.argv[1], sys.argv[2]
cfg = {}
if os.path.exists(cfg_path):
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                cfg = data
    except Exception:
        cfg = {}

changed = False
if "user" in cfg:
    if not cfg.get("target_user"):
        cfg["target_user"] = cfg["user"]
    cfg.pop("user", None)
    changed = True
if not cfg.get("pin_mode"):
    cfg["pin_mode"] = "on_demand"
    changed = True
if not cfg.get("termux_token"):
    cfg["termux_token"] = secrets.token_urlsafe(32)
    changed = True

if changed:
    fd = os.open(cfg_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")
    os.chmod(cfg_path, 0o600)

pin = "(On-Demand via control-access)"
if cfg.get("pin_mode") == "on_demand" and os.path.exists(pin_path):
    try:
        os.remove(pin_path)
    except OSError:
        pass
elif cfg.get("pin_mode") == "static" and os.path.exists(pin_path):
    try:
        with open(pin_path, "r", encoding="utf-8") as f:
            val = f.read().strip()
            if val:
                pin = val
    except Exception:
        pass

print(str(cfg.get("target_user") or "root"))
print(str(cfg.get("ntfy_topic") or ""))
print(str(cfg.get("pin_mode") or "on_demand"))
print(pin)
PYEOF
)"
    target_user="$(printf '%s\n' "${meta_out}" | sed -n '1p')"
    ntfy_topic="$(printf '%s\n' "${meta_out}" | sed -n '2p')"
    pin_mode="$(printf '%s\n' "${meta_out}" | sed -n '3p')"
    pin_val="$(printf '%s\n' "${meta_out}" | sed -n '4p')"

    for f in \
        "${install_dir}/config.json" \
        "${install_dir}/pin.txt" \
        "${install_dir}/ssh_id_ed25519" \
        "${install_dir}/ssh_known_hosts" \
        "${install_dir}/tunnel_url.txt"; do
        if [ -f "${f}" ]; then
            chmod 0600 "${f}"
        fi
    done

    echo -e "${BLUE}4. Restarting & verifying Mobile-RC service...${NC}"
    local svc_mode="nohup"
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        if systemctl is-active --quiet mobile-rc.service 2>/dev/null || systemctl is-enabled --quiet mobile-rc.service 2>/dev/null; then
            svc_mode="systemd"
        fi
    elif command -v rc-service >/dev/null 2>&1 && [ -f /etc/init.d/mobile-rc ]; then
        svc_mode="openrc"
    fi

    if ! restart_service "${python_bin}" "${install_dir}" "${target_user}" "${svc_mode}"; then
        echo -e "${RED}Error: Mobile-RC failed to stay running after update! Rolling back...${NC}"
        if [ -f "${install_dir}/server.py.bak" ]; then
            mv -f "${install_dir}/server.py.bak" "${install_dir}/server.py"
            chmod 700 "${install_dir}/server.py"
            restart_service "${python_bin}" "${install_dir}" "${target_user}" "${svc_mode}" || true
        fi
        exit 1
    fi

    rm -f "${install_dir}/server.py.bak"
    echo -e "${GREEN}✓ Mobile-RC restarted (${svc_mode}) and verified running.${NC}"

    rm -f /tmp/mrc_raw.png /tmp/mrc_live_shot.jpg 2>/dev/null || true

    local active_port="${MRC_PORT:-8000}"
    echo -e "\n${CYAN}====================================================${NC}"
    echo -e "${GREEN}   ✅ Mobile-RC has been successfully updated!      ${NC}"
    echo -e "${CYAN}====================================================${NC}"
    echo -e " 🔑 Access Code Mode       : ${YELLOW}${pin_mode} (${pin_val})${NC}"
    echo -e " 💻 Generate Code on PC    : ${CYAN}sudo control-access${NC}"
    echo -e " 📱 Show Termux Setup Cmd  : ${CYAN}sudo control-access --setup-termux${NC}"
    echo -e " 📧 Configure Email OTP    : ${CYAN}sudo control-access --setup-email${NC}"
    echo -e " 🌐 Local Dashboard URL    : ${CYAN}http://localhost:${active_port}${NC}"
    print_lan_urls "${active_port}"
    if [ -n "${ntfy_topic}" ]; then
        echo -e " 📡 Remote ntfy.sh Topic   : ${CYAN}https://ntfy.sh/${ntfy_topic}${NC}"
    fi
    echo -e "${CYAN}====================================================${NC}\n"
}

main "$@"

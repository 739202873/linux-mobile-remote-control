#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
# Mobile-RC - Universal Linux Remote Control Center
# Supports: Arch, CachyOS, Gentoo, NixOS (flake), Void, Artix, etc.
# Init Systems: systemd, OpenRC, dinit & runit
# ==========================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}====================================================${NC}"
echo -e "${CYAN}     Mobile-RC (Remote Control) - Installer         ${NC}"
echo -e "${CYAN}====================================================${NC}"

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Error: This installer must be run as root (use sudo).${NC}"
    exit 1
fi

if [ -e /etc/NIXOS ]; then
    echo -e "${YELLOW}Detected NixOS (declarative immutable /etc).${NC}"
    echo -e "Use the included Nix Flake / NixOS module instead of this FHS installer:"
    echo -e "  services.mobile-rc.enable = true;"
    echo -e "See flake.nix and README.md (NixOS section) in this repository."
    exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/mobile-rc"

echo -e "${BLUE}1. Checking Python 3...${NC}"
if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${RED}Error: Python 3 is not installed on this system! Please install python3 first.${NC}"
    exit 1
fi

PYTHON_BIN="$(command -v python3)"
echo -e "${GREEN}✓ Python 3 found at: ${PYTHON_BIN} ($("${PYTHON_BIN}" --version))${NC}"

echo -e "${BLUE}2. Detecting target desktop user...${NC}"
TARGET_USER="$("${PYTHON_BIN}" - "${SUDO_USER:-}" "$(logname 2>/dev/null || true)" << 'PYEOF'
import os, pwd, sys

candidates = [sys.argv[1], sys.argv[2]]
for cand in candidates:
    if cand and cand != "root":
        try:
            p = pwd.getpwnam(cand)
            if p.pw_uid >= 1000:
                print(p.pw_name)
                sys.exit(0)
        except KeyError:
            pass

# Check active desktop/login sessions in /run/user
if os.path.exists("/run/user"):
    for entry in sorted(os.scandir("/run/user"), key=lambda e: e.stat().st_mtime, reverse=True):
        if entry.name.isdigit() and 1000 <= int(entry.name) < 60000:
            try:
                p = pwd.getpwuid(int(entry.name))
                if p.pw_name != "nobody":
                    print(p.pw_name)
                    sys.exit(0)
            except KeyError:
                pass

# Fallback to first standard non-system user
for p in pwd.getpwall():
    if 1000 <= p.pw_uid < 60000 and p.pw_name != "nobody":
        print(p.pw_name)
        sys.exit(0)

print("root")
PYEOF
)"
echo -e "${GREEN}✓ Target desktop user configured: ${TARGET_USER}${NC}"

echo -e "${BLUE}3. Installing application files to ${INSTALL_DIR}...${NC}"
mkdir -p -m 700 "${INSTALL_DIR}"
chmod 700 "${INSTALL_DIR}"
cp -f "${SCRIPT_DIR}/server.py" "${INSTALL_DIR}/server.py"
chmod 700 "${INSTALL_DIR}/server.py"
if [ -f "${SCRIPT_DIR}/termux/control-access" ]; then
    cp -f "${SCRIPT_DIR}/termux/control-access" "${INSTALL_DIR}/termux-control-access.sh"
    chmod 644 "${INSTALL_DIR}/termux-control-access.sh"
fi
if [ -f "${SCRIPT_DIR}/bin/control-access" ]; then
    mkdir -p /usr/local/bin
    cp -f "${SCRIPT_DIR}/bin/control-access" /usr/local/bin/control-access
    chmod 755 /usr/local/bin/control-access
fi

# Metode C (Hybrid Runtime Resolution for optional Fase 3 Rust daemon)
RUNTIME_BIN="${PYTHON_BIN}"
RUNTIME_ARGS="${INSTALL_DIR}/server.py"
ARCH_RAW="$(uname -m)"
if [ "${MRC_RUNTIME:-auto}" = "rust" ] || [ "${MRC_USE_RUST:-0}" = "1" ]; then
    if [ -x "${SCRIPT_DIR}/daemon-rs/target/release/mobile-rc" ]; then
        cp -f "${SCRIPT_DIR}/daemon-rs/target/release/mobile-rc" "${INSTALL_DIR}/mobile-rc"
    elif [ -f "${SCRIPT_DIR}/daemon-rs/Cargo.toml" ] && command -v cargo >/dev/null 2>&1; then
        echo -e "${BLUE}   Building Rust daemon from source (cargo build --release)...${NC}"
        cargo build --release --manifest-path "${SCRIPT_DIR}/daemon-rs/Cargo.toml" || true
        [ -x "${SCRIPT_DIR}/daemon-rs/target/release/mobile-rc" ] && cp -f "${SCRIPT_DIR}/daemon-rs/target/release/mobile-rc" "${INSTALL_DIR}/mobile-rc"
    elif command -v curl >/dev/null 2>&1; then
        case "${ARCH_RAW}" in
            x86_64|amd64) RUST_ASSET="mobile-rc-linux-x86_64" ;;
            aarch64|arm64) RUST_ASSET="mobile-rc-linux-aarch64" ;;
            *) RUST_ASSET="" ;;
        esac
        if [ -n "${RUST_ASSET}" ]; then
            curl -fsSL "https://github.com/739202873/linux-mobile-remote-control/releases/latest/download/${RUST_ASSET}" -o "${INSTALL_DIR}/mobile-rc.tmp" 2>/dev/null && mv -f "${INSTALL_DIR}/mobile-rc.tmp" "${INSTALL_DIR}/mobile-rc" || rm -f "${INSTALL_DIR}/mobile-rc.tmp"
        fi
    fi
    if [ -f "${INSTALL_DIR}/mobile-rc" ]; then
        chmod 700 "${INSTALL_DIR}/mobile-rc"
        RUNTIME_BIN="${INSTALL_DIR}/mobile-rc"
        RUNTIME_ARGS=""
        echo -e "${GREEN}   Using Hybrid native runtime: ${RUNTIME_BIN}${NC}"
    else
        echo -e "${YELLOW}   Native Rust binary not available yet; using Python server.py runtime.${NC}"
    fi
fi
RUNTIME_CMD="${RUNTIME_BIN}${RUNTIME_ARGS:+ ${RUNTIME_ARGS}}"

CONFIG_FILE="${INSTALL_DIR}/config.json"
PIN_FILE="${INSTALL_DIR}/pin.txt"

# Safely initialize config.json with 0600 permissions (on-demand random code mode)
INIT_OUT="$("${PYTHON_BIN}" -B - "${CONFIG_FILE}" "${PIN_FILE}" "${TARGET_USER}" << 'PYEOF'
import json, os, secrets, sys

cfg_path, pin_path, target_user = sys.argv[1], sys.argv[2], sys.argv[3]

cfg = {}
if os.path.exists(cfg_path):
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                cfg = data
    except Exception:
        cfg = {}

if not cfg.get("ntfy_topic"):
    cfg["ntfy_topic"] = f"mobile-rc-{secrets.token_hex(12)}"
cfg["target_user"] = target_user
cfg.pop("user", None)
if "auto_tunnel" not in cfg:
    cfg["auto_tunnel"] = False
if "pin_mode" not in cfg:
    cfg["pin_mode"] = "on_demand"
if not cfg.get("termux_token"):
    cfg["termux_token"] = secrets.token_urlsafe(32)

fd = os.open(cfg_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
os.chmod(cfg_path, 0o600)

if cfg["pin_mode"] == "on_demand" and os.path.exists(pin_path):
    try:
        os.remove(pin_path)
    except OSError:
        pass

print(cfg["ntfy_topic"])
print(cfg["termux_token"])
print(cfg["pin_mode"])
PYEOF
)"

NTFY_TOPIC="$(printf '%s\n' "${INIT_OUT}" | sed -n '1p')"
TERMUX_TOKEN="$(printf '%s\n' "${INIT_OUT}" | sed -n '2p')"
PIN_MODE="$(printf '%s\n' "${INIT_OUT}" | sed -n '3p')"
echo -e "${GREEN}✓ Secure configuration & Termux pairing token initialized (mode: ${PIN_MODE}).${NC}"

if ! command -v ssh >/dev/null 2>&1 || ! command -v ssh-keygen >/dev/null 2>&1; then
    echo -e "${YELLOW}Note: OpenSSH client (ssh/ssh-keygen) not found. Optional remote internet tunnel will require openssh.${NC}"
fi

echo -e "${BLUE}4. Configuring Autostart Service...${NC}"
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    echo -e "   -> Detected init system: ${CYAN}systemd${NC}"
    cat << EOF > /etc/systemd/system/mobile-rc.service
[Unit]
Description=Mobile-RC Remote Control Center
After=network.target network-online.target

[Service]
Type=simple
User=root
Environment="MRC_USER=${TARGET_USER}"
ExecStart=${RUNTIME_CMD}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now mobile-rc.service
    systemctl restart mobile-rc.service
    echo -e "${GREEN}✓ mobile-rc.service successfully enabled and started via systemd!${NC}"

elif command -v rc-service >/dev/null 2>&1 && [ -d /etc/init.d ]; then
    echo -e "   -> Detected init system: ${CYAN}OpenRC${NC}"
    cat << EOF > /etc/init.d/mobile-rc
#!/sbin/openrc-run
name="Mobile-RC"
description="Universal Cross-Platform Remote Web Dashboard"
command="${RUNTIME_BIN}"
command_args="${RUNTIME_ARGS}"
command_background=true
pidfile="/run/\${RC_SVCNAME}.pid"
export MRC_USER="${TARGET_USER}"

depend() {
    need net
}
EOF
    chmod 755 /etc/init.d/mobile-rc
    rc-update add mobile-rc default 2>/dev/null || true
    rc-service mobile-rc restart 2>/dev/null || rc-service mobile-rc start
    echo -e "${GREEN}✓ mobile-rc service successfully enabled and started via OpenRC!${NC}"

elif command -v dinitctl >/dev/null 2>&1 && [ -d /etc/dinit.d ] && dinitctl list >/dev/null 2>&1; then
    echo -e "   -> Detected init system: ${CYAN}dinit${NC}"
    ENV_BIN="$(command -v env || echo /usr/bin/env)"
    cat << EOF > /etc/dinit.d/mobile-rc
type = process
command = ${ENV_BIN} MRC_USER=${TARGET_USER} ${RUNTIME_CMD}
restart = true
smooth-recovery = true
logfile = /var/log/mobile-rc.log
EOF
    chmod 644 /etc/dinit.d/mobile-rc
    dinitctl enable mobile-rc 2>/dev/null || true
    dinitctl restart mobile-rc 2>/dev/null || dinitctl start mobile-rc
    echo -e "${GREEN}mobile-rc service successfully enabled and started via dinit!${NC}"

elif command -v sv >/dev/null 2>&1 && { [ -d /var/service ] || [ -d /run/runit/service ] || [ -d /etc/service ]; }; then
    echo -e "   -> Detected init system: ${CYAN}runit${NC}"
    RUNIT_SV_BASE="/etc/sv"
    if [ -d /etc/runit/sv ] && [ ! -d /etc/sv ]; then
        RUNIT_SV_BASE="/etc/runit/sv"
    fi
    if [ -d /var/service ]; then
        RUNIT_SVC_BASE="/var/service"
    elif [ -d /run/runit/service ]; then
        RUNIT_SVC_BASE="/run/runit/service"
    else
        RUNIT_SVC_BASE="/etc/service"
    fi
    mkdir -p "${RUNIT_SV_BASE}/mobile-rc"
    rm -f "${RUNIT_SV_BASE}/mobile-rc/down"
    cat << EOF > "${RUNIT_SV_BASE}/mobile-rc/run"
#!/bin/sh
exec 2>&1
export MRC_USER="${TARGET_USER}"
exec ${RUNTIME_CMD} >>/var/log/mobile-rc.log
EOF
    chmod 755 "${RUNIT_SV_BASE}/mobile-rc/run"
    ln -sfn "${RUNIT_SV_BASE}/mobile-rc" "${RUNIT_SVC_BASE}/mobile-rc"
    for _ in 1 2 3 4 5 6 7 8; do
        [ -d "${RUNIT_SVC_BASE}/mobile-rc/supervise" ] && break
        sleep 0.5
    done
    sv restart "${RUNIT_SVC_BASE}/mobile-rc" >/dev/null 2>&1 || sv up "${RUNIT_SVC_BASE}/mobile-rc" >/dev/null 2>&1 || true
    echo -e "${GREEN}mobile-rc service successfully enabled and started via runit!${NC}"

else
    echo -e "${YELLOW}Warning: Unrecognized init system. Launching background process via nohup.${NC}"
    pkill -f "/opt/mobile-rc/server.py" 2>/dev/null || true
    pkill -f "/opt/mobile-rc/mobile-rc" 2>/dev/null || true
    sleep 1
    if [ -n "${RUNTIME_ARGS}" ]; then
        MRC_USER="${TARGET_USER}" nohup "${RUNTIME_BIN}" "${RUNTIME_ARGS}" >/var/log/mobile-rc.log 2>&1 &
    else
        MRC_USER="${TARGET_USER}" nohup "${RUNTIME_BIN}" >/var/log/mobile-rc.log 2>&1 &
    fi
fi

IP_LOCAL=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n 1 || hostname -I 2>/dev/null | awk '{print $1}' || true)

echo ""
echo -e "${GREEN}====================================================${NC}"
echo -e "${GREEN}   🎉 Installation Complete & Dashboard Ready!      ${NC}"
echo -e "${GREEN}====================================================${NC}"
echo -e "  Local Network Access (from phone browser):"
echo -e "  👉 ${CYAN}http://${IP_LOCAL:-127.0.0.1}:8000${NC}"
echo ""
echo -e "  One-Time Random Code Mode (${PIN_MODE}):"
echo -e "  🔑 Generate code on PC     : ${YELLOW}sudo control-access${NC}"
echo -e "  📱 Show Termux pairing cmd : ${YELLOW}sudo control-access --setup-termux${NC}"
echo -e "  📧 Setup Online Email OTP  : ${YELLOW}sudo control-access --setup-email${NC}"
echo ""
echo -e "  Remote Internet Portal (Disabled by default; toggle in Net & Feed tab):"
echo -e "  👉 ${CYAN}https://ntfy.sh/${NTFY_TOPIC}${NC}"
echo -e "${GREEN}====================================================${NC}"
if [ -x /usr/local/bin/control-access ]; then
    /usr/local/bin/control-access --setup-termux || true
fi

#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
# Mobile-RC - Uninstaller
# ==========================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Error: This uninstaller must be run as root (use sudo).${NC}"
    exit 1
fi

echo -e "${RED}Stopping and removing Mobile-RC...${NC}"

if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now mobile-rc.service 2>/dev/null || true
    rm -f /etc/systemd/system/mobile-rc.service
    systemctl daemon-reload 2>/dev/null || true
fi

if command -v rc-service >/dev/null 2>&1; then
    rc-service mobile-rc stop 2>/dev/null || true
    rc-update del mobile-rc default 2>/dev/null || true
    rm -f /etc/init.d/mobile-rc
fi

pkill -f "/opt/mobile-rc/server.py" 2>/dev/null || true
rm -rf /opt/mobile-rc /usr/local/bin/control-access /usr/local/bin/kontrol-laptop
rm -rf /tmp/mrc_shot_* /tmp/mrc_raw.png /tmp/mrc_live_shot.jpg /var/log/mobile-rc.log

echo -e "${GREEN}✓ Mobile-RC has been successfully uninstalled from the system.${NC}"

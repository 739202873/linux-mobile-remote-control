#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/linux/common.sh
source "${SCRIPT_DIR}/common.sh"

mrc_require_root "sudo ./uninstall.sh"

echo -e "${MRC_RED}Stopping and removing Mobile-RC...${MRC_NC}"

mrc_remove_all_services

rm -rf /opt/mobile-rc /usr/local/bin/control-access /usr/local/bin/kontrol-laptop
rm -rf /tmp/mrc_shot_* /tmp/mrc_raw.png /tmp/mrc_live_shot.jpg /var/log/mobile-rc.log

echo -e "${MRC_GREEN}[OK] Mobile-RC has been successfully uninstalled from the system.${MRC_NC}"

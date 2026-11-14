#!/usr/bin/env bash
# Shared helper functions for Mobile-RC Linux install, update, and uninstall scripts.

MRC_RED='\033[0;31m'
MRC_GREEN='\033[0;32m'
MRC_BLUE='\033[0;34m'
MRC_YELLOW='\033[1;33m'
MRC_CYAN='\033[0;36m'
MRC_NC='\033[0m'

MRC_DEFAULT_INSTALL_DIR="/opt/mobile-rc"
MRC_RELEASE_BASE_URL="https://github.com/739202873/linux-mobile-remote-control/releases/latest/download"

mrc_require_root() {
    local usage_hint="${1:-sudo ./install.sh}"
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${MRC_RED}Error: This script must be run as root (use sudo).${MRC_NC}"
        echo -e "Usage: ${usage_hint}"
        exit 1
    fi
}

mrc_find_python() {
    local py_bin
    py_bin="$(command -v python3 2>/dev/null || true)"
    if [ -z "${py_bin}" ]; then
        echo -e "${MRC_RED}Error: Python 3 is not installed! Please install python3 first.${MRC_NC}" >&2
        return 1
    fi
    printf '%s\n' "${py_bin}"
}

mrc_run_as_repo_owner() {
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

mrc_detect_target_user() {
    local python_bin="$1"
    "${python_bin}" -B - "${SUDO_USER:-}" "$(logname 2>/dev/null || true)" << 'PYEOF'
import os, pwd, sys

for cand in (sys.argv[1], sys.argv[2]):
    if cand and cand != "root":
        try:
            p = pwd.getpwnam(cand)
            if p.pw_uid >= 1000:
                print(p.pw_name)
                sys.exit(0)
        except KeyError:
            pass

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

for p in pwd.getpwall():
    if 1000 <= p.pw_uid < 60000 and p.pw_name != "nobody":
        print(p.pw_name)
        sys.exit(0)

print("root")
PYEOF
}

mrc_verify_python_syntax() {
    local python_bin="$1"
    local server_src="$2"
    local tmp_pyc
    tmp_pyc="$(mktemp /tmp/mrc_syntax.XXXXXX.pyc)"
    if ! "${python_bin}" -B -c '
import py_compile, sys
py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True)
' "${server_src}" "${tmp_pyc}"; then
        rm -f "${tmp_pyc}"
        return 1
    fi
    rm -f "${tmp_pyc}"
    return 0
}

mrc_sha256_file() {
    local target_file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${target_file}" 2>/dev/null | awk '{print tolower($1)}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "${target_file}" 2>/dev/null | awk '{print tolower($1)}'
    elif command -v python3 >/dev/null 2>&1; then
        python3 -B -c '
import hashlib, sys
h = hashlib.sha256()
with open(sys.argv[1], "rb") as f:
    for chunk in iter(lambda: f.read(65536), b""):
        h.update(chunk)
print(h.hexdigest().lower())
' "${target_file}"
    else
        return 1
    fi
}

mrc_print_lan_urls() {
    local port="${1:-8000}"
    local printed=0
    if command -v ip >/dev/null 2>&1; then
        while IFS= read -r ip_addr; do
            if [ -n "${ip_addr}" ] && [[ ! "${ip_addr}" =~ ^127\. ]]; then
                echo -e "                            ${MRC_CYAN}http://${ip_addr}:${port}${MRC_NC}"
                printed=1
            fi
        done < <(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
    fi
    if [ "${printed}" -eq 0 ] && command -v hostname >/dev/null 2>&1; then
        for ip_addr in $(hostname -I 2>/dev/null || true); do
            if [[ "${ip_addr}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ ! "${ip_addr}" =~ ^127\. ]]; then
                echo -e "                            ${MRC_CYAN}http://${ip_addr}:${port}${MRC_NC}"
            fi
        done
    fi
}

mrc_copy_support_files() {
    local repo_root="$1"
    local install_dir="$2"
    local server_src="${repo_root}/fallback/server.py"

    mkdir -p -m 700 "${install_dir}"
    chmod 700 "${install_dir}"
    cp -f "${server_src}" "${install_dir}/server.py"
    chmod 700 "${install_dir}/server.py"

    if [ -f "${repo_root}/termux/control-access" ]; then
        cp -f "${repo_root}/termux/control-access" "${install_dir}/termux-control-access.sh"
        chmod 644 "${install_dir}/termux-control-access.sh"
    fi
    if [ -f "${repo_root}/bin/control-access" ]; then
        mkdir -p /usr/local/bin
        cp -f "${repo_root}/bin/control-access" /usr/local/bin/control-access
        chmod 755 /usr/local/bin/control-access
    fi
    rm -f /usr/local/bin/kontrol-laptop "${install_dir}/termux-kontrol-laptop.sh"
}

mrc_build_rust_as_owner() {
    local owner_user="$1"
    local manifest="$2"
    local cargo_path=""
    if [ -n "${owner_user}" ] && [ "${owner_user}" != "root" ]; then
        local owner_home=""
        owner_home="$(getent passwd "${owner_user}" 2>/dev/null | cut -d: -f6 || true)"
        local extra_path="${PATH}${owner_home:+:${owner_home}/.cargo/bin}"
        cargo_path="$(mrc_run_as_repo_owner "${owner_user}" env PATH="${extra_path}" sh -c 'command -v cargo 2>/dev/null || true' || true)"
        if [ -n "${cargo_path}" ]; then
            mrc_run_as_repo_owner "${owner_user}" env PATH="${extra_path}" "${cargo_path}" build --release --manifest-path "${manifest}"
            return $?
        fi
    fi
    cargo_path="$(command -v cargo 2>/dev/null || true)"
    if [ -n "${cargo_path}" ]; then
        "${cargo_path}" build --release --manifest-path "${manifest}"
        return $?
    fi
    return 1
}

mrc_download_rust_release() {
    local install_dir="$1"
    command -v curl >/dev/null 2>&1 || return 1

    local arch_raw rust_asset=""
    arch_raw="$(uname -m)"
    case "${arch_raw}" in
        x86_64|amd64)  rust_asset="mobile-rc-linux-x86_64" ;;
        aarch64|arm64) rust_asset="mobile-rc-linux-aarch64" ;;
        *) return 1 ;;
    esac

    local tmp_dir tmp_bin tmp_sums expected_hash actual_hash
    tmp_dir="$(mktemp -d /tmp/mrc-release.XXXXXX)"
    tmp_bin="${tmp_dir}/${rust_asset}"
    tmp_sums="${tmp_dir}/SHA256SUMS.txt"

    if ! curl -fsSL --connect-timeout 8 --max-time 30 \
        "${MRC_RELEASE_BASE_URL}/${rust_asset}" -o "${tmp_bin}" 2>/dev/null; then
        rm -rf "${tmp_dir}"
        return 1
    fi

    if ! curl -fsSL --connect-timeout 8 --max-time 15 \
        "${MRC_RELEASE_BASE_URL}/SHA256SUMS.txt" -o "${tmp_sums}" 2>/dev/null; then
        echo -e "${MRC_YELLOW}   Warning: Could not fetch SHA256SUMS.txt; skipping unverified binary download.${MRC_NC}"
        rm -rf "${tmp_dir}"
        return 1
    fi

    expected_hash="$(awk -v target="${rust_asset}" '
        {
            name = $2
            sub(/^\*/, "", name)
            sub(/^.*\//, "", name)
            if (name == target) {
                print tolower($1)
                exit
            }
        }
    ' "${tmp_sums}")"

    if ! [[ "${expected_hash}" =~ ^[0-9a-f]{64}$ ]]; then
        echo -e "${MRC_YELLOW}   Warning: No valid SHA-256 entry for ${rust_asset} in SHA256SUMS.txt; skipping.${MRC_NC}"
        rm -rf "${tmp_dir}"
        return 1
    fi

    actual_hash="$(mrc_sha256_file "${tmp_bin}" || true)"
    if [ "${actual_hash}" != "${expected_hash}" ]; then
        echo -e "${MRC_RED}   Error: SHA-256 mismatch on downloaded ${rust_asset} (expected ${expected_hash}, got ${actual_hash}).${MRC_NC}"
        rm -rf "${tmp_dir}"
        return 1
    fi

    chmod 700 "${tmp_bin}"
    mv -f "${tmp_bin}" "${install_dir}/mobile-rc"
    rm -rf "${tmp_dir}"
    echo -e "${MRC_GREEN}   Verified GitHub Release binary checksum (SHA-256).${MRC_NC}"
    return 0
}

mrc_write_runtime_marker() {
    local install_dir="$1"
    local runtime_name="$2"
    local tmp_marker="${install_dir}/.runtime.tmp"
    printf '%s\n' "${runtime_name}" > "${tmp_marker}"
    chmod 644 "${tmp_marker}"
    mv -f "${tmp_marker}" "${install_dir}/.runtime"
}

mrc_resolve_runtime() {
    local repo_root="$1"
    local install_dir="$2"
    local python_bin="$3"
    local caller_user="$4"

    MRC_RUNTIME_MODE="${MRC_RUNTIME:-auto}"
    if [ -z "${MRC_RUNTIME:-}" ]; then
        [ "${MRC_USE_RUST:-}" = "0" ] && MRC_RUNTIME_MODE="python"
        [ "${MRC_USE_RUST:-}" = "1" ] && MRC_RUNTIME_MODE="rust"
    fi

    MRC_ACTIVE_BIN="${python_bin}"
    MRC_ACTIVE_ARGS="${install_dir}/server.py"
    MRC_ACTIVE_LABEL="Python 3 (${install_dir}/server.py)"
    MRC_ACTIVE_NAME="python"
    MRC_RUST_READY=0

    if [ "${MRC_RUNTIME_MODE}" != "python" ]; then
        local cargo_manifest="${repo_root}/daemon-rs/Cargo.toml"
        local cargo_bin_out="${repo_root}/daemon-rs/target/release/mobile-rc"

        if [ -f "${cargo_manifest}" ]; then
            echo -e "${MRC_BLUE}   Checking native Rust daemon build...${MRC_NC}"
            mrc_build_rust_as_owner "${caller_user}" "${cargo_manifest}" || true
            if [ -x "${cargo_bin_out}" ]; then
                cp -f "${cargo_bin_out}" "${install_dir}/mobile-rc.new"
                chmod 700 "${install_dir}/mobile-rc.new"
                mv -f "${install_dir}/mobile-rc.new" "${install_dir}/mobile-rc"
                MRC_RUST_READY=1
            fi
        fi
        if [ "${MRC_RUST_READY}" -eq 0 ] && [ -x "${cargo_bin_out}" ]; then
            cp -f "${cargo_bin_out}" "${install_dir}/mobile-rc.new"
            chmod 700 "${install_dir}/mobile-rc.new"
            mv -f "${install_dir}/mobile-rc.new" "${install_dir}/mobile-rc"
            MRC_RUST_READY=1
        fi
        if [ "${MRC_RUST_READY}" -eq 0 ]; then
            if mrc_download_rust_release "${install_dir}"; then
                MRC_RUST_READY=1
            fi
        fi

        if [ "${MRC_RUST_READY}" -eq 1 ] && [ -x "${install_dir}/mobile-rc" ]; then
            MRC_ACTIVE_BIN="${install_dir}/mobile-rc"
            MRC_ACTIVE_ARGS=""
            MRC_ACTIVE_LABEL="Native Rust (${MRC_ACTIVE_BIN})"
            MRC_ACTIVE_NAME="rust"
            echo -e "${MRC_GREEN}   Hybrid native runtime prepared: ${MRC_ACTIVE_BIN}${MRC_NC}"
        elif [ "${MRC_RUNTIME_MODE}" = "rust" ]; then
            echo -e "${MRC_RED}Error: MRC_RUNTIME=rust was explicitly requested, but native binary build/download failed.${MRC_NC}"
            return 1
        else
            echo -e "${MRC_YELLOW}   Native Rust binary unavailable; using Python server.py runtime.${MRC_NC}"
        fi
    else
        echo -e "${MRC_BLUE}   MRC_RUNTIME=python requested; keeping Python server.py runtime.${MRC_NC}"
    fi
    return 0
}

mrc_sync_metadata() {
    local python_bin="$1"
    local install_dir="$2"
    local forced_user="${3:-}"
    local out

    out="$("${python_bin}" -B - "${install_dir}/config.json" "${install_dir}/pin.txt" "${forced_user}" << 'PYEOF'
import json, os, secrets, sys

cfg_path, pin_path, forced_user = sys.argv[1], sys.argv[2], sys.argv[3].strip()
cfg = {}
if os.path.exists(cfg_path):
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                cfg = data
    except Exception:
        cfg = {}

if forced_user:
    cfg["target_user"] = forced_user
elif "user" in cfg and not cfg.get("target_user"):
    cfg["target_user"] = cfg["user"]
cfg.pop("user", None)

if not cfg.get("ntfy_topic"):
    cfg["ntfy_topic"] = f"mobile-rc-{secrets.token_hex(12)}"
if "auto_tunnel" not in cfg:
    cfg["auto_tunnel"] = False
if not cfg.get("pin_mode"):
    cfg["pin_mode"] = "on_demand"
if not cfg.get("termux_token"):
    cfg["termux_token"] = secrets.token_urlsafe(32)

fd = os.open(cfg_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
os.chmod(cfg_path, 0o600)

pin_val = "On-Demand via control-access"
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
                pin_val = val
    except Exception:
        pass

print(str(cfg.get("target_user") or "root"))
print(str(cfg.get("ntfy_topic") or ""))
print(str(cfg.get("pin_mode") or "on_demand"))
print(pin_val)
PYEOF
)"

    local f
    for f in \
        "${install_dir}/config.json" \
        "${install_dir}/pin.txt" \
        "${install_dir}/ssh_id_ed25519" \
        "${install_dir}/ssh_known_hosts" \
        "${install_dir}/tunnel_url.txt"; do
        [ -f "${f}" ] && chmod 0600 "${f}"
    done

    printf '%s\n' "${out}"
}

mrc_runit_dirs() {
    local sv_base="/etc/sv"
    local svc_base="/etc/service"
    if [ -d /etc/runit/sv ] && [ ! -d /etc/sv ]; then
        sv_base="/etc/runit/sv"
    fi
    if [ -d /var/service ]; then
        svc_base="/var/service"
    elif [ -d /run/runit/service ]; then
        svc_base="/run/runit/service"
    fi
    printf '%s\n%s\n' "${sv_base}" "${svc_base}"
}

mrc_detect_system_init() {
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        echo "systemd"
    elif command -v rc-service >/dev/null 2>&1 && [ -d /etc/init.d ]; then
        echo "openrc"
    elif command -v dinitctl >/dev/null 2>&1 && [ -d /etc/dinit.d ] && dinitctl list >/dev/null 2>&1; then
        echo "dinit"
    elif command -v sv >/dev/null 2>&1 && { [ -d /var/service ] || [ -d /run/runit/service ] || [ -d /etc/service ]; }; then
        echo "runit"
    else
        echo "nohup"
    fi
}

mrc_detect_installed_init() {
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        if systemctl is-active --quiet mobile-rc.service 2>/dev/null || systemctl is-enabled --quiet mobile-rc.service 2>/dev/null || [ -f /etc/systemd/system/mobile-rc.service ]; then
            echo "systemd"
            return
        fi
    fi
    if command -v rc-service >/dev/null 2>&1 && [ -f /etc/init.d/mobile-rc ]; then
        echo "openrc"
    elif command -v dinitctl >/dev/null 2>&1 && [ -f /etc/dinit.d/mobile-rc ]; then
        echo "dinit"
    elif command -v sv >/dev/null 2>&1 && { [ -e /var/service/mobile-rc ] || [ -e /run/runit/service/mobile-rc ] || [ -e /etc/service/mobile-rc ]; }; then
        echo "runit"
    else
        echo "nohup"
    fi
}

mrc_resolve_service_file() {
    local mode="$1"
    case "${mode}" in
        systemd) echo "/etc/systemd/system/mobile-rc.service" ;;
        openrc)  echo "/etc/init.d/mobile-rc" ;;
        dinit)   echo "/etc/dinit.d/mobile-rc" ;;
        runit)
            local svc_link="" real_dir=""
            for d in /var/service /run/runit/service /etc/service; do
                if [ -e "${d}/mobile-rc" ]; then
                    svc_link="${d}/mobile-rc"
                    break
                fi
            done
            if [ -n "${svc_link}" ]; then
                real_dir="$(readlink -f "${svc_link}" 2>/dev/null || echo "${svc_link}")"
                echo "${real_dir}/run"
            fi
            ;;
        *) echo "" ;;
    esac
}

mrc_stop_service() {
    local mode="$1"
    local install_dir="$2"
    case "${mode}" in
        systemd)
            systemctl stop mobile-rc.service >/dev/null 2>&1 || true
            ;;
        openrc)
            rc-service mobile-rc stop >/dev/null 2>&1 || true
            ;;
        dinit)
            dinitctl stop mobile-rc >/dev/null 2>&1 || true
            ;;
        runit)
            local svc_link=""
            for d in /var/service /run/runit/service /etc/service; do
                if [ -e "${d}/mobile-rc" ]; then
                    svc_link="${d}/mobile-rc"
                    break
                fi
            done
            [ -n "${svc_link}" ] && sv down "${svc_link}" >/dev/null 2>&1 || true
            ;;
        nohup)
            pkill -f "${install_dir}/server.py" 2>/dev/null || true
            pkill -f "${install_dir}/mobile-rc" 2>/dev/null || true
            ;;
    esac
    sleep 1
}

mrc_write_service_unit() {
    local mode="$1"
    local runtime_bin="$2"
    local runtime_args="$3"
    local target_user="$4"
    local runtime_cmd="${runtime_bin}${runtime_args:+ ${runtime_args}}"

    case "${mode}" in
        systemd)
            cat << EOF > /etc/systemd/system/mobile-rc.service
[Unit]
Description=Mobile-RC Remote Control Center
After=network.target network-online.target

[Service]
Type=simple
User=root
Environment="MRC_USER=${target_user}"
ExecStart=${runtime_cmd}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            ;;
        openrc)
            cat << EOF > /etc/init.d/mobile-rc
#!/sbin/openrc-run
name="Mobile-RC"
description="Universal Cross-Platform Remote Web Dashboard"
command="${runtime_bin}"
command_args="${runtime_args}"
command_background=true
pidfile="/run/\${RC_SVCNAME}.pid"
export MRC_USER="${target_user}"

depend() {
    need net
}
EOF
            chmod 755 /etc/init.d/mobile-rc
            ;;
        dinit)
            local env_bin
            env_bin="$(command -v env || echo /usr/bin/env)"
            cat << EOF > /etc/dinit.d/mobile-rc
type = process
command = ${env_bin} MRC_USER=${target_user} ${runtime_cmd}
restart = true
smooth-recovery = true
logfile = /var/log/mobile-rc.log
EOF
            chmod 644 /etc/dinit.d/mobile-rc
            ;;
        runit)
            local run_file
            run_file="$(mrc_resolve_service_file runit)"
            if [ -z "${run_file}" ]; then
                local rdirs sv_base svc_base
                rdirs="$(mrc_runit_dirs)"
                sv_base="$(printf '%s\n' "${rdirs}" | sed -n '1p')"
                svc_base="$(printf '%s\n' "${rdirs}" | sed -n '2p')"
                mkdir -p "${sv_base}/mobile-rc"
                rm -f "${sv_base}/mobile-rc/down"
                run_file="${sv_base}/mobile-rc/run"
                ln -sfn "${sv_base}/mobile-rc" "${svc_base}/mobile-rc"
            fi
            cat << EOF > "${run_file}"
#!/bin/sh
exec 2>&1
export MRC_USER="${target_user}"
exec ${runtime_cmd} >>/var/log/mobile-rc.log
EOF
            chmod 755 "${run_file}"
            ;;
    esac
}

mrc_enable_and_start_service() {
    local mode="$1"
    local runtime_bin="$2"
    local runtime_args="$3"
    local install_dir="$4"
    local target_user="$5"

    case "${mode}" in
        systemd)
            systemctl enable mobile-rc.service >/dev/null 2>&1 || true
            ;;
        openrc)
            rc-update add mobile-rc default 2>/dev/null || true
            ;;
        dinit)
            dinitctl enable mobile-rc 2>/dev/null || true
            ;;
        runit)
            local rdirs svc_base
            rdirs="$(mrc_runit_dirs)"
            svc_base="$(printf '%s\n' "${rdirs}" | sed -n '2p')"
            for _ in 1 2 3 4 5 6 7 8; do
                [ -d "${svc_base}/mobile-rc/supervise" ] && break
                sleep 0.5
            done
            ;;
    esac

    mrc_restart_service "${runtime_bin}" "${runtime_args}" "${install_dir}" "${target_user}" "${mode}"
}

mrc_restart_service() {
    local runtime_bin="$1"
    local runtime_args="$2"
    local install_dir="$3"
    local target_user="$4"
    local mode="$5"

    case "${mode}" in
        systemd)
            systemctl restart mobile-rc.service
            sleep 1
            systemctl is-active --quiet mobile-rc.service
            ;;
        openrc)
            rc-service mobile-rc restart 2>/dev/null || rc-service mobile-rc start
            sleep 1
            rc-service mobile-rc status >/dev/null 2>&1
            ;;
        dinit)
            dinitctl restart mobile-rc 2>/dev/null || dinitctl start mobile-rc
            sleep 1
            dinitctl status mobile-rc 2>/dev/null | grep -qiE "started|running"
            ;;
        runit)
            local svc_link=""
            for d in /var/service /run/runit/service /etc/service; do
                if [ -e "${d}/mobile-rc" ]; then
                    svc_link="${d}/mobile-rc"
                    break
                fi
            done
            [ -n "${svc_link}" ] || return 1
            sv restart "${svc_link}" 2>/dev/null || sv up "${svc_link}"
            sleep 1
            sv status "${svc_link}" 2>/dev/null | grep -q "^run:"
            ;;
        nohup)
            pkill -f "${install_dir}/server.py" 2>/dev/null || true
            pkill -f "${install_dir}/mobile-rc" 2>/dev/null || true
            sleep 1
            if [ -n "${runtime_args}" ]; then
                nohup env MRC_USER="${target_user}" "${runtime_bin}" "${runtime_args}" >/var/log/mobile-rc.log 2>&1 &
                sleep 1
                pgrep -f "${install_dir}/server.py" >/dev/null 2>&1
            else
                nohup env MRC_USER="${target_user}" "${runtime_bin}" >/var/log/mobile-rc.log 2>&1 &
                sleep 1
                pgrep -f "${install_dir}/mobile-rc" >/dev/null 2>&1
            fi
            ;;
    esac
}

mrc_remove_all_services() {
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
    if command -v dinitctl >/dev/null 2>&1; then
        dinitctl stop mobile-rc 2>/dev/null || true
        dinitctl disable mobile-rc 2>/dev/null || true
        rm -f /etc/dinit.d/mobile-rc /etc/dinit.d/boot.d/mobile-rc
    fi
    if command -v sv >/dev/null 2>&1 || [ -d /etc/sv/mobile-rc ] || [ -d /etc/runit/sv/mobile-rc ]; then
        local d
        for d in /var/service /run/runit/service /etc/service; do
            if [ -L "${d}/mobile-rc" ] || [ -e "${d}/mobile-rc" ]; then
                command -v sv >/dev/null 2>&1 && sv stop "${d}/mobile-rc" 2>/dev/null || true
                rm -f "${d}/mobile-rc"
            fi
        done
        rm -rf /etc/sv/mobile-rc /etc/runit/sv/mobile-rc
    fi
    pkill -f "/opt/mobile-rc/server.py" 2>/dev/null || true
    pkill -f "/opt/mobile-rc/mobile-rc" 2>/dev/null || true
}

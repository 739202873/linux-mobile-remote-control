#!/usr/bin/env python3
"""Mobile-RC (Linux Mobile Control Center) — Pure Python Stdlib Server."""

from email.message import EmailMessage
from http import HTTPStatus
import http.cookies
import http.server
import hmac
import ipaddress
import json
import mimetypes
import os
import platform
import pwd
import re
import secrets
import shutil
import smtplib
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

PORT = int(os.environ.get("MRC_PORT", "8000"))
CONFIG_DIR = os.environ.get("MRC_CONFIG_DIR", "/opt/mobile-rc")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
PIN_FILE = os.path.join(CONFIG_DIR, "pin.txt")
SSH_KEY_FILE = os.path.join(CONFIG_DIR, "ssh_id_ed25519")
SSH_KNOWN_HOSTS = os.path.join(CONFIG_DIR, "ssh_known_hosts")

MAX_JSON_BYTES = 1024 * 1024  # 1 MiB
MAX_UPLOAD_BYTES = int(os.environ.get("MRC_MAX_UPLOAD_MB", "500")) * 1024 * 1024
SESSION_TTL_SEC = 86400
CODE_TTL_SEC = max(30, min(600, int(os.environ.get("MRC_CODE_TTL", "180"))))
LOGIN_MAX_FAILS = 5
LOGIN_LOCKOUT_SEC = 120

LAUNCH_PRESETS = {
    "terminal": [
        ["konsole"],
        ["kitty"],
        ["alacritty"],
        ["foot"],
        ["wezterm"],
        ["gnome-terminal"],
        ["xterm"],
    ],
    "youtube": [["xdg-open", "https://youtube.com"]],
    "files": [["dolphin"], ["thunar"], ["nautilus"], ["nemo"], ["pcmanfm"]],
    "btop": [
        ["kitty", "-e", "btop"],
        ["konsole", "-e", "btop"],
        ["alacritty", "-e", "btop"],
        ["foot", "btop"],
        ["xterm", "-e", "top"],
    ],
}

HYPR_PRESETS = {
    "fullscreen": [
        ["hyprctl", "dispatch", "hl.dsp.window.fullscreen({ mode = 0 })"],
        ["hyprctl", "dispatch", "fullscreen", "0"],
        ["swaymsg", "fullscreen", "toggle"],
        ["xdotool", "key", "F11"],
    ],
    "killactive": [
        ["hyprctl", "dispatch", "hl.dsp.window.close()"],
        ["hyprctl", "dispatch", "killactive"],
        ["swaymsg", "kill"],
        ["xdotool", "getactivewindow", "windowclose"],
    ],
    "dpms_toggle": [
        ["hyprctl", "dispatch", 'hl.dsp.dpms({ action = "toggle" })'],
        ["hyprctl", "dispatch", "dpms", "toggle"],
        ["swaymsg", "output", "*", "dpms", "toggle"],
        ["wlopm", "--toggle", "*"],
        ["xset", "dpms", "force", "off"],
    ],
}

_CONFIG_LOCK = threading.Lock()
_AUTH_LOCK = threading.Lock()
_SESSIONS = {}  # token -> {"expires": float, "csrf": str, "ip": str}
_LOGIN_ATTEMPTS = {}  # ip -> {"fails": int, "locked_until": float}
_PAIRING_ATTEMPTS = {}  # ip -> {"fails": int, "locked_until": float}
_EMAIL_REQ_ATTEMPTS = {}  # ip -> {"fails": int, "locked_until": float}
_EMAIL_COOLDOWNS = {}  # key -> last_sent_ts
_EMAIL_HOURLY_TS = []  # recent send timestamps for global spam protection
_ACTIVE_CODE = None  # {"code": str, "expires": float, "source": str}

EMAIL_COOLDOWN_SEC = max(10, int(os.environ.get("MRC_EMAIL_COOLDOWN", "30")))
EMAIL_HOURLY_MAX = max(3, int(os.environ.get("MRC_EMAIL_HOURLY_MAX", "12")))
_EMAIL_RE = re.compile(r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$")

_TUNNEL_LOCK = threading.Lock()
_TUNNEL_PROC = None
_TUNNEL_URL = ""
_TUNNEL_STATUS = "stopped"
_TUNNEL_AUTO = None  # Initialized lazily from env / config.json

_LAST_CPU = None


class _PayloadTooLargeError(Exception):
    pass


class _BadRequestError(Exception):
    pass


def _ensure_config_dir():
    os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)
    try:
        os.chmod(CONFIG_DIR, 0o700)
    except OSError:
        pass


def _write_secure_file(path, content, mode=0o600):
    """Create or overwrite a file strictly with private permissions."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, mode=0o700, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(path, mode)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def get_config():
    with _CONFIG_LOCK:
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return data
        except Exception:
            pass
    return {}


def save_config(data):
    with _CONFIG_LOCK:
        try:
            _ensure_config_dir()
            _write_secure_file(CONFIG_FILE, json.dumps(data, indent=2) + "\n", 0o600)
        except Exception:
            pass


def _is_auto_tunnel_enabled():
    global _TUNNEL_AUTO
    if _TUNNEL_AUTO is not None:
        return _TUNNEL_AUTO
    env_val = os.environ.get("MRC_AUTO_TUNNEL", "").strip().lower()
    if env_val in ("1", "true", "yes"):
        _TUNNEL_AUTO = True
    elif env_val in ("0", "false", "no"):
        _TUNNEL_AUTO = False
    else:
        _TUNNEL_AUTO = bool(get_config().get("auto_tunnel", False))
    return _TUNNEL_AUTO


def get_target_user_info():
    """Return (username, uid, gid, home_dir) of the target non-root desktop user."""
    cfg = get_config()
    cfg_user = str(cfg.get("target_user") or cfg.get("user") or "").strip()
    candidates = [
        os.environ.get("MRC_USER", "").strip(),
        cfg_user,
        os.environ.get("SUDO_USER", "").strip(),
        os.environ.get("USER", "").strip(),
    ]
    for username in candidates:
        if not username or username == "root":
            continue
        try:
            pw = pwd.getpwnam(username)
            if pw.pw_uid != 0:
                return pw.pw_name, pw.pw_uid, pw.pw_gid, pw.pw_dir
        except KeyError:
            continue

    # Detect non-root user with a /home/<user> directory
    try:
        for entry in sorted(os.listdir("/home")):
            full = os.path.join("/home", entry)
            if not os.path.isdir(full):
                continue
            try:
                pw = pwd.getpwnam(entry)
                if pw.pw_uid >= 1000:
                    return pw.pw_name, pw.pw_uid, pw.pw_gid, pw.pw_dir
            except KeyError:
                continue
    except OSError:
        pass

    # Fallback: scan passwd for regular interactive human accounts
    try:
        for pw in pwd.getpwall():
            if 1000 <= pw.pw_uid < 60000 and not pw.pw_shell.endswith(("nologin", "false")):
                return pw.pw_name, pw.pw_uid, pw.pw_gid, pw.pw_dir
    except Exception:
        pass

    return "root", 0, 0, "/root"


def get_downloads_dir():
    """Locate the target user's Downloads directory cleanly."""
    _, uid, gid, home = get_target_user_info()
    xdg_file = os.path.join(home, ".config", "user-dirs.dirs")
    if os.path.exists(xdg_file):
        try:
            with open(xdg_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("XDG_DOWNLOAD_DIR="):
                        val = line.split("=", 1)[1].strip().strip('"').strip("'")
                        val = val.replace("$HOME", home)
                        if os.path.isdir(val):
                            return val
        except Exception:
            pass
    dl = os.path.join(home, "Downloads")
    try:
        os.makedirs(dl, exist_ok=True)
        if os.geteuid() == 0 and uid != 0:
            os.chown(dl, uid, gid)
    except Exception:
        pass
    return dl


def get_ntfy_topic():
    """Return a high-entropy random ntfy topic without leaking host identity."""
    env_topic = os.environ.get("MRC_NTFY_TOPIC", "").strip()
    if env_topic:
        return env_topic
    cfg = get_config()
    topic = str(cfg.get("ntfy_topic", "")).strip()
    if topic:
        return topic
    topic = f"mobile-rc-{secrets.token_hex(12)}"
    cfg["ntfy_topic"] = topic
    save_config(cfg)
    return topic


def get_pin_mode():
    """Return 'static' when MRC_PIN or config pin_mode='static' is set, else 'on_demand'."""
    if os.environ.get("MRC_PIN", "").strip():
        return "static"
    mode = str(get_config().get("pin_mode", "on_demand")).strip().lower()
    return "static" if mode == "static" else "on_demand"


def get_termux_token():
    """Return the paired Termux/CLI Bearer secret, generating a 256-bit token if unset."""
    env_tok = os.environ.get("MRC_TERMUX_TOKEN", "").strip()
    if env_tok:
        return env_tok
    cfg = get_config()
    tok = str(cfg.get("termux_token", "")).strip()
    if tok:
        return tok
    tok = secrets.token_urlsafe(32)
    cfg["termux_token"] = tok
    cfg.setdefault("pin_mode", "on_demand")
    save_config(cfg)
    return tok


def _normalize_email(val):
    """Validate and normalize an email address, rejecting header injection characters."""
    s = str(val or "").strip().lower()
    if not s or len(s) > 254 or any(ch in s for ch in ("\r", "\n", "\0", "<", ">", " ")):
        return ""
    return s if _EMAIL_RE.match(s) else ""


def get_email_otp_settings():
    """Return merged SMTP bot + allowed recipient configuration (env overrides config.json)."""
    cfg = get_config()
    sec = cfg.get("email_otp")
    if not isinstance(sec, dict):
        sec = {}

    enabled = sec.get("enabled", True)
    env_enabled = os.environ.get("MRC_EMAIL_OTP_ENABLED", "").strip().lower()
    if env_enabled in ("0", "false", "no"):
        enabled = False
    elif env_enabled in ("1", "true", "yes"):
        enabled = True

    smtp_host = (os.environ.get("MRC_SMTP_HOST") or sec.get("smtp_host") or "smtp.gmail.com").strip()
    raw_port = os.environ.get("MRC_SMTP_PORT") or sec.get("smtp_port") or 587
    try:
        smtp_port = max(1, min(65535, int(raw_port)))
    except (TypeError, ValueError):
        smtp_port = 587

    smtp_user = _normalize_email(os.environ.get("MRC_SMTP_USER") or sec.get("smtp_user") or "")
    smtp_pass = str(os.environ.get("MRC_SMTP_PASS") or sec.get("smtp_pass") or "").strip()
    if smtp_host.lower().endswith("gmail.com"):
        smtp_pass = smtp_pass.replace(" ", "")

    raw_allowed = os.environ.get("MRC_ALLOWED_EMAILS")
    if raw_allowed is not None:
        candidates = [x.strip() for x in raw_allowed.split(",")]
    else:
        cfg_allowed = sec.get("allowed_emails") or []
        if isinstance(cfg_allowed, str):
            candidates = [x.strip() for x in cfg_allowed.split(",")]
        elif isinstance(cfg_allowed, list):
            candidates = cfg_allowed
        else:
            candidates = []

    allowed_emails = []
    for item in candidates:
        norm = _normalize_email(item)
        if norm and norm not in allowed_emails:
            allowed_emails.append(norm)

    configured = bool(enabled and smtp_host and smtp_user and smtp_pass and allowed_emails)
    return {
        "configured": configured,
        "enabled": bool(enabled),
        "smtp_host": smtp_host,
        "smtp_port": smtp_port,
        "smtp_user": smtp_user,
        "smtp_pass": smtp_pass,
        "allowed_emails": allowed_emails,
    }


def _is_allowed_email(email_norm, allowed_list):
    """Constant-time allowlist check across normalized recipient addresses."""
    matched = False
    for candidate in allowed_list:
        if hmac.compare_digest(email_norm, candidate):
            matched = True
    return matched


def send_otp_email(to_email, code, ttl, client_hint="", settings=None):
    """Send a single-use 6-digit login code via configured SMTP server (e.g. Gmail App Password)."""
    cfg = settings or get_email_otp_settings()
    if not cfg.get("configured"):
        return False, "Email OTP is not configured on host"

    host_name = platform.node() or "Linux PC"
    msg = EmailMessage()
    msg["Subject"] = f"[Mobile-RC] Access Code: {code}"
    msg["From"] = cfg["smtp_user"]
    msg["To"] = to_email
    msg.set_content(
        f"Your Mobile-RC one-time access code for {host_name} is:\n\n"
        f"    {code}\n\n"
        f"Valid for {ttl} seconds (single-use).\n"
        f"Requested from: {client_hint or 'Remote browser'}\n\n"
        f"If you did not request this code, someone attempted to access your remote dashboard URL.\n"
    )

    try:
        ctx = ssl.create_default_context()
        if cfg["smtp_port"] == 465:
            with smtplib.SMTP_SSL(cfg["smtp_host"], cfg["smtp_port"], timeout=12, context=ctx) as srv:
                srv.login(cfg["smtp_user"], cfg["smtp_pass"])
                srv.send_message(msg)
        else:
            with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=12) as srv:
                srv.ehlo()
                srv.starttls(context=ctx)
                srv.ehlo()
                srv.login(cfg["smtp_user"], cfg["smtp_pass"])
                srv.send_message(msg)
        return True, ""
    except Exception as e:
        print(f"[Mobile-RC] Email OTP send error ({cfg['smtp_host']}:{cfg['smtp_port']}): {e}", file=sys.stderr)
        return False, str(e)


def _store_one_time_code(code, ttl=CODE_TTL_SEC, source="cli", email=""):
    global _ACTIVE_CODE
    with _AUTH_LOCK:
        _ACTIVE_CODE = {
            "code": code,
            "expires": time.time() + ttl,
            "source": source,
            "email": email,
        }


def issue_one_time_code(source="cli", email=""):
    """Generate and store a fresh single-use 6-digit random access code."""
    code = f"{secrets.randbelow(1000000):06d}"
    _store_one_time_code(code, CODE_TTL_SEC, source=source, email=email)
    return code, CODE_TTL_SEC


def _verify_login_code(supplied_pin):
    """Verify login code against active one-time code or static PIN."""
    global _ACTIVE_CODE
    now = time.time()
    if get_pin_mode() == "static":
        with _AUTH_LOCK:
            if _ACTIVE_CODE and _ACTIVE_CODE.get("source") == "email":
                if now >= _ACTIVE_CODE["expires"]:
                    _ACTIVE_CODE = None
                elif hmac.compare_digest(supplied_pin, _ACTIVE_CODE["code"]):
                    _ACTIVE_CODE = None
                    return True, "ok"
        ok = hmac.compare_digest(supplied_pin, get_pin())
        return ok, ("ok" if ok else "invalid")

    with _AUTH_LOCK:
        if not _ACTIVE_CODE:
            return False, "missing"
        if now >= _ACTIVE_CODE["expires"]:
            _ACTIVE_CODE = None
            return False, "expired"
        if hmac.compare_digest(supplied_pin, _ACTIVE_CODE["code"]):
            _ACTIVE_CODE = None
            return True, "ok"
        return False, "invalid"


def get_pin():
    """Return static access PIN (used only when pin_mode == 'static' or MRC_PIN is set)."""
    env_pin = os.environ.get("MRC_PIN", "").strip()
    if env_pin:
        return env_pin
    try:
        if os.path.exists(PIN_FILE):
            with open(PIN_FILE, "r", encoding="utf-8") as f:
                pin = f.read().strip()
            if pin:
                try:
                    os.chmod(PIN_FILE, 0o600)
                except OSError:
                    pass
                return pin
    except Exception:
        pass

    pin = f"{secrets.randbelow(1000000):06d}"
    try:
        _ensure_config_dir()
        _write_secure_file(PIN_FILE, pin + "\n", 0o600)
        print(f"[Mobile-RC] Generated static 6-digit access PIN in {PIN_FILE}")
    except Exception as e:
        print(f"[Mobile-RC] Warning: could not persist PIN file ({e}); using ephemeral PIN")
    return pin


def set_pin(new_pin):
    pin = str(new_pin).strip()
    if not pin:
        raise ValueError("PIN must not be empty")
    _ensure_config_dir()
    _write_secure_file(PIN_FILE, pin + "\n", 0o600)


def run_cmd(cmd, timeout=8, shell=False):
    """Execute a system command cleanly without unintended shell expansion."""
    try:
        env = os.environ.copy()
        env["LC_ALL"] = "C"
        res = subprocess.run(
            cmd,
            shell=shell,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except Exception as e:
        return 1, "", str(e)


def run_first_system_cmd(cmd_variants, timeout=8):
    """Run the first available root/system command variant using list args."""
    for cmd in cmd_variants:
        if shutil.which(cmd[0]):
            rc, out, err = run_cmd(cmd, timeout=timeout, shell=False)
            if rc == 0:
                return rc, out, err
    return 1, "", "No supported system utility found"


def get_desktop_env():
    """Inspect active processes strictly owned by the target user for GUI session env."""
    username, uid, _, home = get_target_user_info()
    env = {
        "HOME": home,
        "USER": username,
        "LOGNAME": username,
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:" + os.path.join(home, ".local/bin"),
        "LC_ALL": "C",
    }

    keys_to_grab = (
        "DISPLAY=",
        "WAYLAND_DISPLAY=",
        "XDG_RUNTIME_DIR=",
        "DBUS_SESSION_BUS_ADDRESS=",
        "HYPRLAND_INSTANCE_SIGNATURE=",
        "SWAYSOCK=",
        "XDG_CURRENT_DESKTOP=",
        "KDE_FULL_SESSION=",
    )
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            proc_dir = f"/proc/{pid}"
            try:
                st = os.stat(proc_dir)
                if st.st_uid != uid:
                    continue
                with open(f"{proc_dir}/environ", "rb") as f:
                    raw = f.read().decode("utf-8", errors="ignore")
                for item in raw.split("\0"):
                    if item.startswith(keys_to_grab):
                        k, _, v = item.partition("=")
                        if v and k not in env:
                            env[k] = v
            except Exception:
                continue
    except Exception:
        pass

    runtime_dir = env.get("XDG_RUNTIME_DIR") or f"/run/user/{uid}"
    if os.path.isdir(runtime_dir):
        env.setdefault("XDG_RUNTIME_DIR", runtime_dir)
        bus_sock = os.path.join(runtime_dir, "bus")
        if os.path.exists(bus_sock):
            env.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path={bus_sock}")
        if "WAYLAND_DISPLAY" not in env:
            try:
                for name in sorted(os.listdir(runtime_dir)):
                    if name.startswith("wayland-") and not name.endswith(".lock"):
                        env["WAYLAND_DISPLAY"] = name
                        break
            except OSError:
                pass
        hypr_dir = os.path.join(runtime_dir, "hypr")
        cur_his = env.get("HYPRLAND_INSTANCE_SIGNATURE", "")
        if os.path.isdir(hypr_dir) and (
            not cur_his or not os.path.exists(os.path.join(hypr_dir, cur_his, ".socket.sock"))
        ):
            try:
                for sig in sorted(os.listdir(hypr_dir), reverse=True):
                    if os.path.exists(os.path.join(hypr_dir, sig, ".socket.sock")):
                        env["HYPRLAND_INSTANCE_SIGNATURE"] = sig
                        break
            except OSError:
                pass
    env.setdefault("DISPLAY", ":0")
    return env


def run_as_user(cmd, timeout=10, shell=False, input_text=None, background=False, discard_output=False):
    """Run a command dropped to the target desktop user's UID and GID."""
    _, uid, gid, home = get_target_user_info()
    env = get_desktop_env()
    kwargs = {"cwd": home if os.path.isdir(home) else "/"}
    if os.geteuid() == 0 and uid != 0:
        kwargs["user"] = uid
        kwargs["group"] = gid

    try:
        if background:
            subprocess.Popen(
                cmd,
                shell=shell,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                **kwargs,
            )
            return 0, "", ""

        stdout_target = subprocess.DEVNULL if discard_output else subprocess.PIPE
        stderr_target = subprocess.DEVNULL if discard_output else subprocess.PIPE
        res = subprocess.run(
            cmd,
            shell=shell,
            env=env,
            input=input_text,
            stdin=None if input_text is not None else subprocess.DEVNULL,
            stdout=stdout_target,
            stderr=stderr_target,
            text=True,
            timeout=timeout,
            **kwargs,
        )
        out = "" if discard_output or res.stdout is None else res.stdout.strip()
        err = "" if discard_output or res.stderr is None else res.stderr.strip()
        return res.returncode, out, err
    except Exception as e:
        return 1, "", str(e)


def run_first_available(cmd_variants, timeout=8, input_text=None, background=False, discard_output=False):
    """Execute the first available desktop command variant without shell expansion."""
    last_err = ""
    for cmd in cmd_variants:
        if not shutil.which(cmd[0]):
            continue
        rc, out, err = run_as_user(
            cmd,
            timeout=timeout,
            shell=False,
            input_text=input_text,
            background=background,
            discard_output=discard_output,
        )
        first_line = (out or "").lstrip().splitlines()[0].lower() if out and out.strip() else ""
        bad_out = first_line.startswith((
            "error:",
            "invalid dispatcher",
            "no such dispatcher",
            "unknown request",
            "couldn't connect",
        ))
        if rc == 0 and not bad_out:
            return rc, out, err
        last_err = err or out or f"Exit code {rc}"
    return 1, "", last_err or "No supported desktop tool succeeded"


# === SYSTEM TELEMETRY HELPERS ===

def get_cpu_percent():
    global _LAST_CPU
    try:
        with open("/proc/stat", "r", encoding="utf-8") as f:
            line = f.readline()
        parts = [int(x) for x in line.split()[1:8]]
        idle = parts[3] + parts[4]
        total = sum(parts)
        if _LAST_CPU is None:
            _LAST_CPU = (idle, total)
            return 0.0
        prev_idle, prev_total = _LAST_CPU
        _LAST_CPU = (idle, total)
        diff_total = total - prev_total
        diff_idle = idle - prev_idle
        if diff_total <= 0:
            return 0.0
        return round(100.0 * (1.0 - (diff_idle / diff_total)), 1)
    except Exception:
        return 0.0


def get_cpu_temp():
    temps = []
    try:
        hwmon_root = "/sys/class/hwmon"
        if os.path.isdir(hwmon_root):
            for hw in os.listdir(hwmon_root):
                path = os.path.join(hwmon_root, hw)
                name_file = os.path.join(path, "name")
                name = ""
                if os.path.exists(name_file):
                    with open(name_file, "r", encoding="utf-8", errors="ignore") as f:
                        name = f.read().strip().lower()
                if any(k in name for k in ("k10temp", "coretemp", "zenpower", "cpu", "acpitz", "thinkpad")):
                    for fn in os.listdir(path):
                        if fn.startswith("temp") and fn.endswith("_input"):
                            with open(os.path.join(path, fn), "r", encoding="utf-8") as f:
                                val = int(f.read().strip())
                            if 5000 < val < 130000:
                                temps.append(val / 1000.0)
        if not temps and os.path.isdir("/sys/class/thermal"):
            for tz in os.listdir("/sys/class/thermal"):
                if tz.startswith("thermal_zone"):
                    tf = os.path.join("/sys/class/thermal", tz, "temp")
                    if os.path.exists(tf):
                        with open(tf, "r", encoding="utf-8") as f:
                            val = int(f.read().strip())
                        if 5000 < val < 130000:
                            temps.append(val / 1000.0)
    except Exception:
        pass
    return round(max(temps), 1) if temps else 0.0


def get_os_info():
    os_name = platform.system()
    try:
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        os_name = line.split("=", 1)[1].strip().strip("\"'")
                        break
    except Exception:
        pass

    uptime_str = "-"
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as f:
            sec = int(float(f.read().split()[0]))
        h, m = sec // 3600, (sec % 3600) // 60
        uptime_str = f"{h}h {m}m" if h else f"{m}m"
    except Exception:
        pass

    return {
        "name": os_name,
        "hostname": socket.gethostname(),
        "kernel": platform.release(),
        "uptime": uptime_str,
    }


def get_memory_info():
    mem = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                k, _, v = line.partition(":")
                mem[k.strip()] = int(v.strip().split()[0]) * 1024
        total = mem.get("MemTotal", 0)
        avail = mem.get("MemAvailable", mem.get("MemFree", 0))
        used = max(0, total - avail)
        pct = round((used / total) * 100.0, 1) if total > 0 else 0.0
        return {
            "total_gb": round(total / (1024 ** 3), 1),
            "used_gb": round(used / (1024 ** 3), 1),
            "percent": pct,
        }
    except Exception:
        return {"total_gb": 0.0, "used_gb": 0.0, "percent": 0.0}


def get_battery_info():
    try:
        ps_dir = "/sys/class/power_supply"
        if os.path.isdir(ps_dir):
            for dev in sorted(os.listdir(ps_dir)):
                if dev.startswith("BAT"):
                    base = os.path.join(ps_dir, dev)
                    cap_file = os.path.join(base, "capacity")
                    st_file = os.path.join(base, "status")
                    if os.path.exists(cap_file):
                        with open(cap_file, "r", encoding="utf-8") as f:
                            cap = int(f.read().strip())
                        status = "Unknown"
                        if os.path.exists(st_file):
                            with open(st_file, "r", encoding="utf-8") as f:
                                status = f.read().strip()
                        plugged = status.lower() in ("charging", "full", "not charging")
                        return {"percent": cap, "status": status, "plugged": plugged}
    except Exception:
        pass
    return {"percent": 100, "status": "AC Power", "plugged": True}


def get_media_and_display():
    vol = 50
    muted = False
    brightness = 50
    media_status = "Stopped"
    media_title = "Nothing playing"

    if shutil.which("wpctl"):
        rc, out, _ = run_as_user(["wpctl", "get-volume", "@DEFAULT_AUDIO_SINK@"])
        if rc == 0 and out:
            m = re.search(r"Volume:\s*([0-9.]+)", out)
            if m:
                vol = int(round(float(m.group(1)) * 100))
            muted = "[MUTED]" in out
    elif shutil.which("pactl"):
        rc, out, _ = run_as_user(["pactl", "get-sink-volume", "@DEFAULT_SINK@"])
        if rc == 0 and out:
            m = re.search(r"(\d+)%", out)
            if m:
                vol = int(m.group(1))
        rc_m, out_m, _ = run_as_user(["pactl", "get-sink-mute", "@DEFAULT_SINK@"])
        if rc_m == 0:
            muted = "yes" in out_m.lower()

    if shutil.which("brightnessctl"):
        rc_b, out_b, _ = run_cmd(["brightnessctl", "-m"])
        if rc_b == 0 and out_b:
            m = re.search(r",(\d+)%,", out_b)
            if m:
                brightness = int(m.group(1))

    if shutil.which("playerctl"):
        rc_s, out_s, _ = run_as_user(["playerctl", "status"])
        if rc_s == 0 and out_s:
            media_status = out_s
        rc_t, out_t, _ = run_as_user(["playerctl", "metadata", "--format", "{{artist}} - {{title}}"])
        if rc_t == 0 and out_t:
            cleaned = out_t.strip(" -")
            if cleaned:
                media_title = cleaned

    return {
        "volume": vol,
        "muted": muted,
        "brightness": brightness,
        "media_status": media_status,
        "media_title": media_title,
    }


def get_workspaces_info():
    """Return active desktop workspaces sorted numerically for Hyprland, Sway, or X11."""
    if shutil.which("hyprctl"):
        rc_ws, out_ws, _ = run_as_user(["hyprctl", "workspaces", "-j"], timeout=3)
        if rc_ws == 0 and out_ws:
            try:
                raw_ws = json.loads(out_ws)
                active_id = None
                rc_aw, out_aw, _ = run_as_user(["hyprctl", "activeworkspace", "-j"], timeout=3)
                if rc_aw == 0 and out_aw:
                    aw = json.loads(out_aw)
                    if isinstance(aw, dict) and isinstance(aw.get("id"), int):
                        active_id = aw["id"]

                by_id = {}
                if isinstance(raw_ws, list):
                    for w in raw_ws:
                        if not isinstance(w, dict):
                            continue
                        wid = w.get("id")
                        wtype = str(w.get("type") or "").lower()
                        if not isinstance(wid, int) or wid <= 0 or wtype == "special":
                            continue
                        by_id[wid] = {
                            "id": wid,
                            "name": str(w.get("name") or wid),
                            "active": wid == active_id,
                            "windows": int(w.get("windows") or 0),
                        }
                if isinstance(active_id, int) and active_id > 0 and active_id not in by_id:
                    by_id[active_id] = {
                        "id": active_id,
                        "name": str(active_id),
                        "active": True,
                        "windows": 0,
                    }
                if by_id:
                    return [by_id[k] for k in sorted(by_id)]
            except Exception:
                pass

    if shutil.which("swaymsg"):
        rc_sw, out_sw, _ = run_as_user(["swaymsg", "-t", "get_workspaces", "-r"], timeout=3)
        if rc_sw == 0 and out_sw:
            try:
                raw_sw = json.loads(out_sw)
                items = []
                if isinstance(raw_sw, list):
                    for w in raw_sw:
                        if not isinstance(w, dict):
                            continue
                        num = w.get("num")
                        if not isinstance(num, int) or num <= 0:
                            continue
                        items.append({
                            "id": num,
                            "name": str(w.get("name") or num),
                            "active": bool(w.get("focused")),
                            "windows": 0,
                        })
                if items:
                    return sorted(items, key=lambda item: item["id"])
            except Exception:
                pass

    if shutil.which("wmctrl"):
        rc_wm, out_wm, _ = run_as_user(["wmctrl", "-d"], timeout=3)
        if rc_wm == 0 and out_wm:
            items = []
            for line in out_wm.splitlines():
                parts = line.split(None, 2)
                if not parts or not parts[0].isdigit():
                    continue
                idx = int(parts[0]) + 1
                is_active = len(parts) > 1 and parts[1] == "*"
                items.append({"id": idx, "name": str(idx), "active": is_active, "windows": 0})
            if items:
                return items

    if shutil.which("xdotool"):
        rc_n, out_n, _ = run_as_user(["xdotool", "get_num_desktops"], timeout=3)
        rc_c, out_c, _ = run_as_user(["xdotool", "get_desktop"], timeout=3)
        if rc_n == 0 and out_n.strip().isdigit():
            count = max(1, min(20, int(out_n.strip())))
            cur = int(out_c.strip()) + 1 if rc_c == 0 and out_c.strip().isdigit() else 1
            return [{"id": i, "name": str(i), "active": i == cur, "windows": 0} for i in range(1, count + 1)]

    return [{"id": i, "name": str(i), "active": i == 1, "windows": 0} for i in range(1, 5)]


def _collect_disk_nodes(nodes, out_list):
    for node in nodes:
        if not isinstance(node, dict):
            continue
        name = str(node.get("name", ""))
        ntype = str(node.get("type", ""))
        fstype = str(node.get("fstype") or "")
        children = node.get("children") or []

        is_virtual = name.startswith(("zram", "loop")) or ntype in ("zram", "loop", "rom")
        if not is_virtual and fstype and fstype.lower() != "swap":
            mount = node.get("mountpoint")
            label = node.get("label") or node.get("partlabel") or mount or name
            size = str(node.get("size") or "-")
            use_pct = str(node.get("fsuse%") or "-")
            out_list.append({
                "part": name,
                "label": str(label),
                "fstype": fstype,
                "size": size,
                "use_pct": use_pct,
                "mounted": bool(mount),
            })

        if children:
            _collect_disk_nodes(children, out_list)


def get_disks_info():
    disks = []
    if shutil.which("lsblk"):
        rc, out, _ = run_cmd([
            "lsblk",
            "-J",
            "-o",
            "NAME,TYPE,LABEL,PARTLABEL,SIZE,FSTYPE,FSUSED,FSUSE%,MOUNTPOINT",
        ])
        if rc == 0 and out:
            try:
                parsed = json.loads(out)
                _collect_disk_nodes(parsed.get("blockdevices", []), disks)
            except Exception:
                pass
    return disks


def get_boot_entries():
    entries = []
    if shutil.which("efibootmgr"):
        rc, out, _ = run_cmd(["efibootmgr"])
        if rc == 0 and out:
            for line in out.splitlines():
                m = re.match(r"^Boot([0-9A-Fa-f]{4})\*?\s+(.+)$", line)
                if not m:
                    continue
                num = m.group(1).upper()
                raw_name = m.group(2).split("\t", 1)[0].strip()
                skip_terms = ("efi ", "cdrom", "cd/dvd", "removable", "network", "pxe", "usb")
                if any(skip in raw_name.lower() for skip in skip_terms):
                    continue
                entries.append({"num": num, "name": raw_name})
    return entries


def get_local_ips():
    ips = []
    if shutil.which("ip"):
        try:
            rc, out, _ = run_cmd(["ip", "-4", "-o", "addr", "show", "scope", "global"])
            if rc == 0 and out:
                for line in out.splitlines():
                    parts = line.split()
                    if "inet" in parts:
                        idx = parts.index("inet") + 1
                        if idx < len(parts):
                            ip_addr = parts[idx].split("/", 1)[0]
                            if ip_addr and not ip_addr.startswith("127.") and ip_addr not in ips:
                                ips.append(ip_addr)
        except Exception:
            pass
    if not ips and shutil.which("hostname"):
        try:
            rc, out, _ = run_cmd(["hostname", "-I"])
            if rc == 0 and out:
                for tok in out.split():
                    if "." in tok and not tok.startswith("127.") and tok not in ips:
                        ips.append(tok)
        except Exception:
            pass
    if not ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip_addr = s.getsockname()[0]
            if ip_addr not in ips:
                ips.append(ip_addr)
            s.close()
        except Exception:
            pass
    return ips


# === OPT-IN TUNNEL & NTFY HELPERS ===

def _publish_ntfy(url):
    """Notify user of tunnel availability without transmitting secrets/PIN."""
    topic = get_ntfy_topic()
    if not topic:
        return
    try:
        endpoint = f"https://ntfy.sh/{urllib.parse.quote(topic, safe='')}"
        body = (
            f"Remote dashboard is reachable at:\n{url}\n\n"
            f"Sign in using the PIN stored on your PC."
        ).encode("utf-8")
        headers = {
            "Title": f"{socket.gethostname()} - Mobile-RC Online",
            "Tags": "computer,globe_with_meridians",
            "Click": url,
            "Content-Type": "text/plain; charset=utf-8",
        }
        req = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except Exception:
        pass


def _ensure_ssh_keypair():
    _ensure_config_dir()
    if not os.path.exists(SSH_KEY_FILE) and shutil.which("ssh-keygen"):
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", SSH_KEY_FILE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    if os.path.exists(SSH_KEY_FILE):
        try:
            os.chmod(SSH_KEY_FILE, 0o600)
        except OSError:
            pass


def _tunnel_reader(proc):
    global _TUNNEL_URL, _TUNNEL_STATUS
    try:
        if not proc.stdout:
            return
        for raw_line in iter(proc.stdout.readline, ""):
            line = raw_line.strip()
            if not line:
                continue
            m = re.search(r"(https://[a-zA-Z0-9._-]+\.(?:lhr\.life|localhost\.run))", line)
            if m:
                url = m.group(1)
                with _TUNNEL_LOCK:
                    if _TUNNEL_PROC is not proc:
                        return
                    _TUNNEL_URL = url
                    _TUNNEL_STATUS = "online"
                try:
                    _ensure_config_dir()
                    _write_secure_file(os.path.join(CONFIG_DIR, "tunnel_url.txt"), url + "\n", 0o600)
                except Exception:
                    pass
                threading.Thread(target=_publish_ntfy, args=(url,), daemon=True).start()
    except Exception:
        pass
    finally:
        with _TUNNEL_LOCK:
            if _TUNNEL_PROC is proc:
                _TUNNEL_URL = ""
                _TUNNEL_STATUS = "stopped"


def start_tunnel():
    global _TUNNEL_PROC, _TUNNEL_URL, _TUNNEL_STATUS
    if not shutil.which("ssh"):
        with _TUNNEL_LOCK:
            _TUNNEL_STATUS = "unavailable (ssh not installed)"
        return get_tunnel_info()

    with _TUNNEL_LOCK:
        if _TUNNEL_PROC and _TUNNEL_PROC.poll() is None:
            return get_tunnel_info()
        _ensure_ssh_keypair()
        _TUNNEL_URL = ""
        _TUNNEL_STATUS = "starting"
        cmd = [
            "ssh",
            "-T",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={SSH_KNOWN_HOSTS}",
            "-o", "ExitOnForwardFailure=yes",
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=3",
            "-R", f"80:localhost:{PORT}",
        ]
        if os.path.exists(SSH_KEY_FILE):
            cmd.extend(["-i", SSH_KEY_FILE])
        cmd.append("nokey@localhost.run")

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        _TUNNEL_PROC = proc
        threading.Thread(target=_tunnel_reader, args=(proc,), daemon=True).start()

    # Wait briefly for localhost.run URL emission
    for _ in range(25):
        time.sleep(0.2)
        info = get_tunnel_info()
        if info["url"] or info["status"] == "stopped":
            return info
    return get_tunnel_info()


def stop_tunnel():
    global _TUNNEL_PROC, _TUNNEL_URL, _TUNNEL_STATUS
    with _TUNNEL_LOCK:
        proc = _TUNNEL_PROC
        _TUNNEL_PROC = None
        _TUNNEL_URL = ""
        _TUNNEL_STATUS = "stopped"
    if proc and proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    return get_tunnel_info()


def get_tunnel_info():
    with _TUNNEL_LOCK:
        active = bool(_TUNNEL_PROC and _TUNNEL_PROC.poll() is None)
        if not active and _TUNNEL_STATUS != "unavailable (ssh not installed)":
            status = "stopped"
            url = ""
        else:
            status = _TUNNEL_STATUS
            url = _TUNNEL_URL
    return {
        "active": active,
        "status": status,
        "url": url,
        "auto": bool(_is_auto_tunnel_enabled()),
        "topic": get_ntfy_topic(),
    }


def _tunnel_watchdog():
    """Keep tunnel online ONLY when opt-in auto_tunnel is enabled."""
    while True:
        try:
            if _is_auto_tunnel_enabled():
                with _TUNNEL_LOCK:
                    alive = bool(_TUNNEL_PROC and _TUNNEL_PROC.poll() is None)
                if not alive:
                    start_tunnel()
            time.sleep(10)
        except Exception:
            time.sleep(10)


def _delayed_power(cmd_variants):
    """Run poweroff/reboot command after HTTP response flushes."""
    time.sleep(0.8)
    run_first_system_cmd(cmd_variants)


# === FRONTEND UI ===

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<meta name="theme-color" content="#0b0f19">
<title>Mobile-RC • Linux Control Center</title>
<style>
  :root {
    --bg: #0b0f19;
    --card: rgba(20, 27, 45, 0.85);
    --border: rgba(255, 255, 255, 0.09);
    --accent: #38bdf8;
    --accent2: #818cf8;
    --text: #f1f5f9;
    --muted: #94a3b8;
    --danger: #f43f5e;
    --success: #10b981;
    --warning: #f59e0b;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; -webkit-tap-highlight-color: transparent; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, sans-serif;
    background: radial-gradient(circle at top right, #1e1b4b, #0b0f19 60%);
    color: var(--text);
    min-height: 100vh;
    padding-bottom: 84px;
  }
  .container { max-width: 540px; margin: 0 auto; padding: 14px; }

  .header {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 16px;
    margin-bottom: 14px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    backdrop-filter: blur(12px);
  }
  .os-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: rgba(56, 189, 248, 0.15);
    color: var(--accent);
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 6px;
  }
  .dot { width: 7px; height: 7px; background: var(--accent); border-radius: 50%; box-shadow: 0 0 8px var(--accent); }
  .title { font-size: 19px; font-weight: 800; letter-spacing: -0.3px; }
  .subtitle { font-size: 12px; color: var(--muted); margin-top: 2px; }

  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  .grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }
  .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; }
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 14px;
    margin-bottom: 12px;
    backdrop-filter: blur(12px);
  }
  .card-title {
    font-size: 13px;
    font-weight: 700;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.6px;
    margin-bottom: 12px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .stat-box {
    background: rgba(15, 23, 42, 0.7);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 12px;
  }
  .stat-label { font-size: 11px; color: var(--muted); font-weight: 600; margin-bottom: 4px; }
  .stat-val { font-size: 20px; font-weight: 800; color: var(--text); }
  .bar-bg { background: rgba(255, 255, 255, 0.08); height: 6px; border-radius: 3px; overflow: hidden; margin-top: 6px; }
  .bar-fill { height: 100%; background: linear-gradient(90deg, var(--accent), var(--accent2)); border-radius: 3px; transition: width 0.4s ease; }

  .shot-wrap {
    position: relative;
    border-radius: 12px;
    overflow: hidden;
    background: #000;
    margin-bottom: 10px;
    border: 1px solid var(--border);
    aspect-ratio: 16/10;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
  }
  .shot-wrap img { width: 100%; height: 100%; object-fit: contain; display: block; }
  .shot-placeholder { font-size: 12px; color: var(--muted); padding: 12px; text-align: center; }

  button, .btn {
    appearance: none;
    background: rgba(255, 255, 255, 0.08);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 11px 14px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    transition: all 0.15s ease;
    text-decoration: none;
  }
  button:active, .btn:active { transform: scale(0.97); background: rgba(255, 255, 255, 0.14); }
  .btn-primary { background: linear-gradient(135deg, var(--accent), var(--accent2)); color: #fff; border: none; font-weight: 700; }
  .btn-danger { background: rgba(244, 63, 94, 0.15); color: var(--danger); border-color: rgba(244, 63, 94, 0.3); }
  .btn-success { background: rgba(16, 185, 129, 0.15); color: var(--success); border-color: rgba(16, 185, 129, 0.3); }

  .btn-os { background: rgba(56, 189, 248, 0.12); border-color: rgba(56, 189, 248, 0.3); color: var(--accent); }
  .btn-arch { background: rgba(23, 147, 209, 0.15); border-color: rgba(23, 147, 209, 0.4); color: #38bdf8; }
  .btn-garuda { background: rgba(240, 98, 146, 0.15); border-color: rgba(240, 98, 146, 0.4); color: #f472b6; }
  .btn-gentoo { background: rgba(168, 85, 247, 0.15); border-color: rgba(168, 85, 247, 0.4); color: #c084fc; }

  input[type="range"] {
    width: 100%;
    accent-color: var(--accent);
    margin: 10px 0;
  }
  input[type="text"], input[type="password"] {
    width: 100%;
    background: rgba(15, 23, 42, 0.8);
    border: 1px solid var(--border);
    border-radius: 12px;
    color: #fff;
    padding: 10px 14px;
    font-size: 13px;
    outline: none;
  }
  input[type="text"]:focus, input[type="password"]:focus { border-color: var(--accent); }

  .file-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 10px;
    background: rgba(255, 255, 255, 0.03);
    border-radius: 10px;
    margin-bottom: 6px;
    font-size: 13px;
  }
  .file-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 65%; }

  .bottom-nav {
    position: fixed;
    bottom: 0;
    left: 0;
    right: 0;
    background: rgba(11, 15, 25, 0.95);
    border-top: 1px solid var(--border);
    display: flex;
    justify-content: space-around;
    padding: 8px 6px;
    backdrop-filter: blur(16px);
    z-index: 100;
  }
  .nav-item {
    background: transparent;
    border: none;
    color: var(--muted);
    font-size: 10px;
    font-weight: 700;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 3px;
    padding: 6px 10px;
    border-radius: 10px;
  }
  .nav-item.active { color: var(--accent); }
  .tab-pane { display: none; }
  .tab-pane.active { display: block; animation: fadeIn 0.2s ease; }
  @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }

  #toast {
    position: fixed;
    top: 16px;
    left: 50%;
    transform: translateX(-50%);
    background: rgba(15, 23, 42, 0.95);
    border: 1px solid var(--accent);
    color: #fff;
    padding: 9px 18px;
    border-radius: 30px;
    font-size: 12px;
    font-weight: 700;
    display: none;
    z-index: 1200;
    box-shadow: 0 10px 25px rgba(0,0,0,0.5);
  }
  pre.term {
    background: #020617;
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 10px;
    font-size: 11px;
    color: #38bdf8;
    max-height: 180px;
    overflow-y: auto;
    white-space: pre-wrap;
    margin-top: 10px;
  }

  /* Authentication Overlay */
  #login-overlay {
    position: fixed;
    inset: 0;
    background: rgba(11, 15, 25, 0.96);
    backdrop-filter: blur(16px);
    z-index: 1100;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
  }
  .login-card {
    width: 100%;
    max-width: 380px;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 24px;
    text-align: center;
  }
  .login-err {
    color: var(--danger);
    font-size: 12px;
    min-height: 18px;
    margin: 10px 0 6px;
  }
</style>
</head>
<body>

<div id="toast"></div>

<div id="login-overlay">
  <div class="login-card">
    <div class="os-badge" style="margin-bottom:10px"><span class="dot"></span> <span id="login-badge-text">Mobile-RC Locked</span></div>
    <div class="title" style="margin-bottom:6px">Enter Access Code</div>
    <div class="subtitle" id="login-hint" style="margin-bottom:14px">Type <code>control-access</code> in Termux (or <code>sudo control-access</code> on your PC) to generate a random 6-digit one-time code.</div>
    <div id="email-otp-box" style="display:none;margin-bottom:12px;padding-bottom:12px;border-bottom:1px solid var(--border)">
      <input type="email" id="email-input" placeholder="Registered email address" autocomplete="email" style="margin-bottom:8px" onkeydown="if(event.key==='Enter')requestEmailCode()">
      <button id="send-email-btn" onclick="requestEmailCode()" style="width:100%;margin-bottom:6px">📧 Send Code to Email</button>
      <div id="email-otp-status" class="subtitle" style="min-height:16px"></div>
    </div>
    <input type="password" id="pin-input" inputmode="numeric" maxlength="16" placeholder="6-digit code" autocomplete="current-password" style="text-align:center;font-size:18px;letter-spacing:4px;margin-bottom:8px" onkeydown="if(event.key==='Enter')submitLogin()">
    <div class="login-err" id="login-err"></div>
    <button class="btn-primary" style="width:100%" onclick="submitLogin()">🔓 Unlock Dashboard</button>
  </div>
</div>

<div class="container">
  <!-- HEADER -->
  <div class="header">
    <div>
      <div class="os-badge" id="os-badge"><span class="dot"></span> <span id="os-name">Loading...</span></div>
      <div class="title" id="hostname">Mobile-RC</div>
      <div class="subtitle" id="kernel-uptime">Kernel - • Uptime -</div>
    </div>
    <div style="text-align:right">
      <div style="font-size:22px;font-weight:800" id="bat-top">--%</div>
      <div class="subtitle" id="bat-status">Battery</div>
      <button id="logout-btn" onclick="doLogout()" style="margin-top:6px;padding:4px 9px;font-size:11px">🔒 Lock</button>
    </div>
  </div>

  <!-- TAB 1: MONITOR & SCREEN -->
  <div id="tab-monitor" class="tab-pane active">
    <div class="grid-2" style="margin-bottom:14px">
      <div class="stat-box">
        <div class="stat-label">CPU LOAD</div>
        <div class="stat-val" id="cpu-val">0%</div>
        <div class="bar-bg"><div class="bar-fill" id="cpu-bar" style="width:0%"></div></div>
      </div>
      <div class="stat-box">
        <div class="stat-label">CPU TEMPERATURE</div>
        <div class="stat-val" id="temp-val">0°C</div>
        <div class="bar-bg"><div class="bar-fill" id="temp-bar" style="width:0%"></div></div>
      </div>
      <div class="stat-box">
        <div class="stat-label">RAM USAGE</div>
        <div class="stat-val" id="ram-val">0 GB</div>
        <div class="bar-bg"><div class="bar-fill" id="ram-bar" style="width:0%"></div></div>
      </div>
      <div class="stat-box">
        <div class="stat-label">BATTERY LEVEL</div>
        <div class="stat-val" id="bat-val">0%</div>
        <div class="bar-bg"><div class="bar-fill" id="bat-bar" style="width:0%"></div></div>
      </div>
    </div>

    <div class="card">
      <div class="card-title">
        <span>🖥️ Live Desktop Screen Preview</span>
        <div style="display:flex;gap:6px;align-items:center">
          <button id="live-btn" onclick="toggleLiveMonitor()" style="padding:5px 10px;font-size:11px;border-color:rgba(16,185,129,0.5);color:var(--success)">● Live ON</button>
          <button onclick="refreshScreenshot()" style="padding:5px 10px;font-size:11px">📸 Refresh</button>
        </div>
      </div>
      <div class="shot-wrap" onclick="refreshScreenshot()">
        <span class="shot-placeholder" id="shot-placeholder">Loading live desktop screen...</span>
        <img id="live-shot" alt="Live desktop screen" style="display:none">
      </div>
      <div id="ws-list" class="grid-4" style="margin-bottom:8px"></div>
      <div class="grid-3">
        <button onclick="doAction('hypr', 'fullscreen')">⛶ Fullscreen</button>
        <button onclick="doAction('hypr', 'dpms_toggle')">💡 Screen On/Off</button>
        <button class="btn-danger" onclick="doAction('hypr', 'killactive')">✖ Close App</button>
      </div>
    </div>

    <div class="card">
      <div class="card-title"><span>💾 Disk Partitions & Storage</span></div>
      <div id="disk-list"></div>
    </div>
  </div>

  <!-- TAB 2: MEDIA, VOLUME & DISPLAY -->
  <div id="tab-media" class="tab-pane">
    <div class="card">
      <div class="card-title"><span>🎵 Now Playing</span> <span id="media-st" style="color:var(--accent)">-</span></div>
      <div style="font-size:16px;font-weight:700;margin-bottom:14px" id="media-title">-</div>
      <div class="grid-3">
        <button onclick="doMedia('prev')">⏮ Prev</button>
        <button class="btn-primary" onclick="doMedia('play-pause')">⏯ Play/Pause</button>
        <button onclick="doMedia('next')">⏭ Next</button>
      </div>
    </div>

    <div class="card">
      <div class="card-title">
        <span>🔊 Audio Volume</span>
        <span id="vol-label" style="color:var(--accent);font-weight:800">50%</span>
      </div>
      <input type="range" id="vol-slider" min="0" max="150" value="50" onchange="doMedia('vol_set', this.value)" oninput="document.getElementById('vol-label').innerText=this.value+'%'">
      <div class="grid-3">
        <button onclick="doMedia('vol_down')">🔉 -5%</button>
        <button onclick="doMedia('mute')">🔇 Mute</button>
        <button onclick="doMedia('vol_up')">🔊 +5%</button>
      </div>
    </div>

    <div class="card">
      <div class="card-title">
        <span>☀️ Display Brightness</span>
        <span id="bright-label" style="color:var(--warning);font-weight:800">50%</span>
      </div>
      <input type="range" id="bright-slider" min="5" max="100" value="50" onchange="doMedia('bright_set', this.value)" oninput="document.getElementById('bright-label').innerText=this.value+'%'">
      <div class="grid-2">
        <button onclick="doMedia('bright_down')">🔅 Dim (-10%)</button>
        <button onclick="doMedia('bright_up')">🔆 Brighten (+10%)</button>
      </div>
    </div>
  </div>

  <!-- TAB 3: MULTI-BOOT & POWER -->
  <div id="tab-boot" class="tab-pane">
    <div class="card">
      <div class="card-title"><span>🚀 Multi-Boot OS Switcher (UEFI BootNext)</span></div>
      <div id="boot-list" style="display:flex;flex-direction:column;gap:10px">
        <div style="color:var(--muted);font-size:13px">Scanning UEFI boot entries...</div>
      </div>
    </div>

    <div class="card">
      <div class="card-title"><span>⚡ Power & Session Controls</span></div>
      <div class="grid-2">
        <button onclick="doPower('lock')">🔒 Lock Screen</button>
        <button onclick="doPower('suspend')">🌙 Sleep / Suspend</button>
        <button class="btn-primary" onclick="confirmBoot('reboot', 'Reboot Current System')">🔄 Reboot</button>
        <button class="btn-danger" onclick="confirmBoot('poweroff', 'Shutdown System')">⏻ Shutdown</button>
      </div>
    </div>
  </div>

  <!-- TAB 4: REMOTE APPS, MESSAGES & TERMINAL -->
  <div id="tab-remote" class="tab-pane">
    <div class="card">
      <div class="card-title"><span>💬 Send Notification / Clipboard to PC</span></div>
      <input type="text" id="msg-input" placeholder="Type message, text snippet, or URL..." style="margin-bottom:10px">
      <div class="grid-3">
        <button class="btn-primary" onclick="sendInput('notify')">🔔 Notify</button>
        <button onclick="sendInput('clipboard')">📋 Copy to PC</button>
        <button onclick="sendInput('open_url')">🌐 Open URL</button>
      </div>
    </div>

    <div class="card">
      <div class="card-title"><span>🚀 Quick Application Launcher</span></div>
      <div class="grid-2">
        <button onclick="doAction('launch', 'terminal')">💻 Open Terminal</button>
        <button onclick="doAction('launch', 'youtube')">▶️ Open YouTube</button>
        <button onclick="doAction('launch', 'files')">📁 File Manager</button>
        <button onclick="doAction('launch', 'btop')">📊 Open Btop Monitor</button>
      </div>
    </div>

    <div class="card">
      <div class="card-title"><span>⌨️ Quick Web Terminal</span></div>
      <div style="display:flex;gap:8px">
        <input type="text" id="cmd-input" placeholder="Example: fastfetch, df -h, sensors..." onkeydown="if(event.key==='Enter')runTerminal()">
        <button class="btn-primary" onclick="runTerminal()">Run</button>
      </div>
      <pre class="term" id="term-out">Ready to execute commands on remote machine...</pre>
    </div>
  </div>

  <!-- TAB 5: FILE SHARING & REMOTE ACCESS -->
  <div id="tab-network" class="tab-pane">
    <div class="card">
      <div class="card-title"><span>🌍 Remote Access (Opt-In HTTPS Tunnel)</span></div>
      <p style="font-size:12px;color:var(--muted);margin-bottom:12px">
        Disabled by default. Start only when you need access outside your local Wi-Fi network; PIN authentication remains enforced.
      </p>
      <div id="tunnel-box" style="background:rgba(15,23,42,0.85);padding:12px;border-radius:12px;border:1px solid var(--border);margin-bottom:12px;word-break:break-all;font-size:13px">
        Status: <b id="tunnel-status">Checking...</b>
        <div id="tunnel-url-wrap" style="margin-top:6px;display:none">
          Public URL: <a id="tunnel-link" href="#" target="_blank" rel="noopener noreferrer" style="color:var(--accent);font-weight:700"></a>
        </div>
      </div>
      <div class="grid-2">
        <button class="btn-success" onclick="toggleTunnel('start')">🌐 Start Internet Tunnel</button>
        <button class="btn-danger" onclick="toggleTunnel('stop')">⏹ Stop Tunnel</button>
      </div>
    </div>

    <div class="card">
      <div class="card-title"><span>📤 Upload File to PC (~/Downloads)</span></div>
      <input type="file" id="file-upload" style="margin-bottom:10px;width:100%;font-size:12px">
      <button class="btn-primary" style="width:100%" onclick="uploadFile()">⬆️ Upload to PC Now</button>
    </div>

    <div class="card">
      <div class="card-title">
        <span>📥 Download Files from PC (~/Downloads)</span>
        <button onclick="loadFiles()" style="padding:4px 10px;font-size:11px">🔄 Refresh</button>
      </div>
      <div id="file-list">Loading files...</div>
    </div>
  </div>
</div>

<!-- BOTTOM NAV -->
<div class="bottom-nav">
  <button class="nav-item active" onclick="switchTab('monitor', this)"><span>📊</span><span>Monitor</span></button>
  <button class="nav-item" onclick="switchTab('media', this)"><span>🎵</span><span>Media</span></button>
  <button class="nav-item" onclick="switchTab('boot', this)"><span>🚀</span><span>Multi-Boot</span></button>
  <button class="nav-item" onclick="switchTab('remote', this)"><span>⌨️</span><span>Remote</span></button>
  <button class="nav-item" onclick="switchTab('network', this)"><span>🌍</span><span>Files &amp; Net</span></button>
</div>

<script>
let _csrfToken = '';
let _authenticated = false;
let _pollTimer = null;
let _liveTimer = null;
let _liveEnabled = true;
let _shotInFlight = false;
let _liveShotUrl = '';
let _activeTab = 'monitor';
let _lastWsSig = '';
let _cachedBootEntries = null;

function toast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.style.display = 'block';
  clearTimeout(window._toastTimer);
  window._toastTimer = setTimeout(() => { t.style.display = 'none'; }, 2600);
}

function showLogin(msg = '') {
  _authenticated = false;
  _csrfToken = '';
  if (_pollTimer) {
    clearInterval(_pollTimer);
    _pollTimer = null;
  }
  if (_liveTimer) {
    clearTimeout(_liveTimer);
    _liveTimer = null;
  }
  _shotInFlight = false;
  const shotImg = document.getElementById('live-shot');
  const shotPh = document.getElementById('shot-placeholder');
  if (shotImg) {
    shotImg.removeAttribute('src');
    shotImg.style.display = 'none';
  }
  if (shotPh) {
    shotPh.textContent = 'Loading live desktop screen...';
    shotPh.style.display = 'block';
  }
  if (_liveShotUrl) {
    URL.revokeObjectURL(_liveShotUrl);
    _liveShotUrl = '';
  }
  const pinEl = document.getElementById('pin-input');
  if (pinEl) pinEl.value = '';
  const emailSt = document.getElementById('email-otp-status');
  if (emailSt) emailSt.textContent = '';
  document.getElementById('login-err').textContent = msg;
  document.getElementById('login-overlay').style.display = 'flex';
  const emailBox = document.getElementById('email-otp-box');
  const emailEl = document.getElementById('email-input');
  if (emailBox && emailBox.style.display !== 'none' && emailEl && !emailEl.value.trim()) {
    emailEl.focus();
  } else if (pinEl) {
    pinEl.focus();
  }
}

function hideLogin() {
  _authenticated = true;
  _lastWsSig = '';
  document.getElementById('login-err').textContent = '';
  document.getElementById('pin-input').value = '';
  document.getElementById('login-overlay').style.display = 'none';
  if (!_pollTimer) {
    _pollTimer = setInterval(refreshStatus, 3500);
  }
  updateLiveButton();
  refreshStatus();
  refreshScreenshot(true);
}

async function initAuth() {
  try {
    const r = await fetch('/api/auth/status', { credentials: 'same-origin' });
    const d = await r.json();
    const hint = document.getElementById('login-hint');
    const badge = document.getElementById('login-badge-text');
    const emailBox = document.getElementById('email-otp-box');
    const emailStatus = document.getElementById('email-otp-status');
    if (d && d.is_non_local) {
      if (badge) badge.textContent = 'Mobile-RC • Online Access';
      if (d.email_otp_enabled) {
        if (emailBox) emailBox.style.display = 'block';
        if (hint) hint.textContent = 'Remote access detected. Enter your registered email to receive a 6-digit OTP code, or enter a code generated on your PC/Termux.';
      } else {
        if (emailBox) emailBox.style.display = 'none';
        if (hint) hint.innerHTML = 'Remote access detected. Enter a code from <code>control-access</code> (or run <code>sudo control-access --setup-email</code> on PC to enable Email OTP).';
      }
    } else {
      if (badge) badge.textContent = 'Mobile-RC • Local LAN';
      if (emailBox) emailBox.style.display = 'none';
      if (hint && d && d.pin_mode === 'static') {
        hint.innerHTML = 'Enter the configured PIN stored in <code>/opt/mobile-rc/pin.txt</code> on your PC.';
      }
    }
    if (emailStatus) emailStatus.textContent = '';
    if (d && d.authenticated && d.csrf_token) {
      _csrfToken = d.csrf_token;
      hideLogin();
      return;
    }
  } catch (e) {}
  showLogin('');
}

async function requestEmailCode() {
  const emailEl = document.getElementById('email-input');
  const statusEl = document.getElementById('email-otp-status');
  const btn = document.getElementById('send-email-btn');
  const email = (emailEl ? emailEl.value : '').trim();
  if (!email || !email.includes('@')) {
    if (statusEl) {
      statusEl.style.color = '#fca5a5';
      statusEl.textContent = 'Please enter a valid email address.';
    }
    return;
  }
  if (btn) btn.disabled = true;
  if (statusEl) {
    statusEl.style.color = 'var(--muted)';
    statusEl.textContent = 'Sending verification code...';
  }
  try {
    const r = await fetch('/api/pairing/email-code', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    const d = await r.json();
    if (r.ok && d.ok) {
      if (statusEl) {
        statusEl.style.color = 'var(--success)';
        statusEl.textContent = d.message || 'Check your inbox for the 6-digit code.';
      }
      const pinInp = document.getElementById('pin-input');
      if (pinInp) pinInp.focus();
    } else if (statusEl) {
      statusEl.style.color = '#fca5a5';
      statusEl.textContent = d.message || 'Could not send email code.';
    }
  } catch (e) {
    if (statusEl) {
      statusEl.style.color = '#fca5a5';
      statusEl.textContent = 'Connection error while sending email code.';
    }
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function submitLogin() {
  const pin = document.getElementById('pin-input').value.trim();
  const errEl = document.getElementById('login-err');
  if (!pin) {
    errEl.textContent = 'Please enter your access PIN.';
    return;
  }
  errEl.textContent = 'Verifying...';
  try {
    const r = await fetch('/api/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pin }),
    });
    const d = await r.json();
    if (r.ok && d.ok && d.csrf_token) {
      _csrfToken = d.csrf_token;
      hideLogin();
      toast('Unlocked!');
    } else {
      errEl.textContent = d.message || 'Authentication failed';
    }
  } catch (e) {
    errEl.textContent = 'Connection error';
  }
}

async function doLogout() {
  try {
    await api('/api/logout', 'POST', {});
  } catch (e) {}
  _cachedBootEntries = null;
  showLogin('Locked');
}

function switchTab(name, btn) {
  _activeTab = name;
  document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active');
  if (name === 'monitor') {
    if (_liveEnabled && _authenticated) refreshScreenshot(true);
  } else if (_liveTimer) {
    clearTimeout(_liveTimer);
    _liveTimer = null;
  }
  if (name === 'network') loadFiles();
}

document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    if (_liveTimer) {
      clearTimeout(_liveTimer);
      _liveTimer = null;
    }
  } else if (_authenticated && _activeTab === 'monitor' && _liveEnabled) {
    refreshScreenshot(true);
  }
});

async function api(path, method = 'GET', body = null) {
  const opts = { method, credentials: 'same-origin', headers: {} };
  if (method !== 'GET' && _csrfToken) {
    opts.headers['X-CSRF-Token'] = _csrfToken;
  }
  if (body !== null) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(path, opts);
  if (r.status === 401) {
    showLogin('Session expired. Enter PIN again.');
    throw new Error('Unauthorized');
  }
  return await r.json();
}

async function refreshStatus() {
  if (!_authenticated) return;
  try {
    const d = await api('/api/status');
    document.getElementById('os-name').textContent = d.os.name;
    document.getElementById('hostname').textContent = d.os.hostname;
    document.getElementById('kernel-uptime').textContent = `${d.os.kernel} • Up ${d.os.uptime}`;

    document.getElementById('cpu-val').textContent = d.cpu_pct + '%';
    document.getElementById('cpu-bar').style.width = Math.min(100, d.cpu_pct) + '%';

    document.getElementById('temp-val').textContent = d.cpu_temp + '°C';
    document.getElementById('temp-bar').style.width = Math.min(100, d.cpu_temp) + '%';

    document.getElementById('ram-val').textContent = `${d.ram.used_gb}/${d.ram.total_gb} GB`;
    document.getElementById('ram-bar').style.width = d.ram.percent + '%';

    document.getElementById('bat-val').textContent = d.battery.percent + '%';
    document.getElementById('bat-bar').style.width = d.battery.percent + '%';
    document.getElementById('bat-top').textContent = (d.battery.plugged ? '⚡' : '') + d.battery.percent + '%';
    document.getElementById('bat-status').textContent = d.battery.status;

    document.getElementById('vol-label').textContent = (d.media.muted ? '🔇 ' : '') + d.media.volume + '%';
    document.getElementById('vol-slider').value = d.media.volume;
    document.getElementById('bright-label').textContent = d.media.brightness + '%';
    document.getElementById('bright-slider').value = d.media.brightness;
    document.getElementById('media-st').textContent = d.media.media_status;
    document.getElementById('media-title').textContent = d.media.media_title;

    // Render Workspaces dynamically matching laptop workspaces (wraps to new rows after 4)
    const wsEl = document.getElementById('ws-list');
    if (wsEl) {
      const wsList = Array.isArray(d.workspaces) && d.workspaces.length
        ? d.workspaces
        : [
            { id: 1, name: '1', active: true },
            { id: 2, name: '2', active: false },
            { id: 3, name: '3', active: false },
            { id: 4, name: '4', active: false },
          ];
      const wsSig = wsList.map(w => `${w.id}:${w.name || w.id}:${w.active ? 1 : 0}`).join('|');
      if (wsSig !== _lastWsSig) {
        _lastWsSig = wsSig;
        const cols = wsList.length <= 4 ? wsList.length : 4;
        wsEl.style.gridTemplateColumns = `repeat(${cols}, 1fr)`;
        wsEl.textContent = '';
        for (const w of wsList) {
          const b = document.createElement('button');
          if (w.active) b.className = 'btn-primary';
          const label = w.name && String(w.name) !== String(w.id) ? `WS ${w.id} (${w.name})` : `WS ${w.id}`;
          b.textContent = label;
          b.addEventListener('click', () => doAction('ws', String(w.id)));
          wsEl.appendChild(b);
        }
      }
    }

    // Render Disks safely via DOM nodes
    const dl = document.getElementById('disk-list');
    dl.textContent = '';
    if (d.disks && d.disks.length) {
      for (const x of d.disks) {
        const row = document.createElement('div');
        row.className = 'file-item';

        const left = document.createElement('div');
        const bLabel = document.createElement('b');
        bLabel.textContent = x.label;
        const meta = document.createElement('span');
        meta.style.cssText = 'color:var(--muted);font-size:11px';
        meta.textContent = ` (/dev/${x.part} • ${x.fstype})`;
        left.appendChild(bLabel);
        left.appendChild(meta);

        const right = document.createElement('div');
        right.style.cssText = `font-size:12px;color:${x.mounted ? 'var(--success)' : 'var(--muted)'}`;
        right.appendChild(document.createTextNode(`${x.size} • `));
        const bUse = document.createElement('b');
        bUse.textContent = x.use_pct;
        right.appendChild(bUse);

        row.appendChild(left);
        row.appendChild(right);
        dl.appendChild(row);
      }
    } else {
      const empty = document.createElement('div');
      empty.style.cssText = 'color:var(--muted);font-size:12px';
      empty.textContent = 'No block storage detected.';
      dl.appendChild(empty);
    }

    // Render Multi-Boot entries safely via DOM nodes + addEventListener
    if (!_cachedBootEntries && d.boot_entries) {
      _cachedBootEntries = d.boot_entries;
      const bl = document.getElementById('boot-list');
      bl.textContent = '';
      for (const e of d.boot_entries) {
        let btnClass = 'btn-os';
        let icon = '🚀';
        const n = String(e.name || '').toLowerCase();
        if (n.includes('arch')) { btnClass = 'btn-arch'; icon = '🔵'; }
        else if (n.includes('garuda')) { btnClass = 'btn-garuda'; icon = '🦅'; }
        else if (n.includes('gentoo')) { btnClass = 'btn-gentoo'; icon = '🟣'; }
        else if (n.includes('ubuntu')) { icon = '🟠'; }
        else if (n.includes('fedora')) { icon = '🔷'; }
        else if (n.includes('windows')) { icon = '🪟'; }

        const btn = document.createElement('button');
        btn.className = btnClass;
        btn.style.cssText = 'justify-content:space-between;padding:16px';
        const spanLeft = document.createElement('span');
        spanLeft.appendChild(document.createTextNode(`${icon} `));
        const bold = document.createElement('b');
        bold.textContent = `Boot into ${e.name}`;
        spanLeft.appendChild(bold);
        spanLeft.appendChild(document.createTextNode(` (Boot${e.num})`));
        const arrow = document.createElement('span');
        arrow.textContent = '➔';
        btn.appendChild(spanLeft);
        btn.appendChild(arrow);
        btn.addEventListener('click', () => confirmBootNum(e.num, e.name));
        bl.appendChild(btn);
      }

      const uefiBtn = document.createElement('button');
      uefiBtn.style.cssText = 'justify-content:space-between;padding:14px';
      const uefiLeft = document.createElement('span');
      uefiLeft.appendChild(document.createTextNode('⚙️ '));
      const uefiBold = document.createElement('b');
      uefiBold.textContent = 'Enter BIOS / UEFI Firmware Setup';
      uefiLeft.appendChild(uefiBold);
      const uefiArrow = document.createElement('span');
      uefiArrow.textContent = '➔';
      uefiBtn.appendChild(uefiLeft);
      uefiBtn.appendChild(uefiArrow);
      uefiBtn.addEventListener('click', () => confirmBoot('uefi', 'BIOS / UEFI Firmware Settings'));
      bl.appendChild(uefiBtn);
    }

    // Tunnel
    document.getElementById('tunnel-status').textContent = String(d.tunnel.status || 'stopped').toUpperCase();
    const tw = document.getElementById('tunnel-url-wrap');
    if (d.tunnel.url) {
      tw.style.display = 'block';
      const tl = document.getElementById('tunnel-link');
      tl.href = d.tunnel.url;
      tl.textContent = d.tunnel.url;
    } else {
      tw.style.display = 'none';
    }
  } catch (e) {}
}

function updateLiveButton() {
  const btn = document.getElementById('live-btn');
  if (!btn) return;
  if (_liveEnabled) {
    btn.textContent = '● Live ON';
    btn.style.borderColor = 'rgba(16,185,129,0.5)';
    btn.style.color = 'var(--success)';
  } else {
    btn.textContent = '⏸ Live PAUSED';
    btn.style.borderColor = 'var(--border)';
    btn.style.color = 'var(--muted)';
  }
}

function toggleLiveMonitor() {
  _liveEnabled = !_liveEnabled;
  updateLiveButton();
  if (_liveTimer) {
    clearTimeout(_liveTimer);
    _liveTimer = null;
  }
  if (_liveEnabled && _authenticated && _activeTab === 'monitor') {
    refreshScreenshot(true);
  }
}

function scheduleLiveShot(delayMs = 1500) {
  if (_liveTimer) {
    clearTimeout(_liveTimer);
    _liveTimer = null;
  }
  if (_authenticated && _liveEnabled && _activeTab === 'monitor' && !document.hidden) {
    _liveTimer = setTimeout(() => refreshScreenshot(true), delayMs);
  }
}

async function refreshScreenshot(fromAuto = false) {
  if (!_authenticated) return;
  if (_shotInFlight) return;
  _shotInFlight = true;
  if (_liveTimer) {
    clearTimeout(_liveTimer);
    _liveTimer = null;
  }
  const img = document.getElementById('live-shot');
  const ph = document.getElementById('shot-placeholder');
  try {
    const r = await fetch('/api/screenshot?t=' + Date.now(), { credentials: 'same-origin' });
    if (r.status === 401) {
      showLogin('Session expired. Enter PIN again.');
      return;
    }
    if (!r.ok) {
      if (!_liveShotUrl) {
        img.style.display = 'none';
        if (ph) {
          ph.textContent = 'Unable to capture desktop screen';
          ph.style.display = 'block';
        }
      }
      return;
    }
    const blob = await r.blob();
    const objUrl = URL.createObjectURL(blob);
    const prevUrl = _liveShotUrl;
    _liveShotUrl = objUrl;
    img.src = objUrl;
    img.style.display = 'block';
    if (ph) ph.style.display = 'none';
    if (prevUrl) setTimeout(() => URL.revokeObjectURL(prevUrl), 200);
  } catch (e) {
    if (!fromAuto && !_liveShotUrl) {
      img.style.display = 'none';
      if (ph) ph.style.display = 'block';
    }
  } finally {
    _shotInFlight = false;
    if (_liveEnabled) scheduleLiveShot(1500);
  }
}

async function doMedia(action, value = '') {
  const r = await api('/api/media', 'POST', { action, value: String(value) });
  toast(r.message || 'Success');
  refreshStatus();
}

async function doPower(target) {
  const r = await api('/api/power', 'POST', { target });
  toast(r.message || 'Command sent');
}

async function confirmBoot(target, label) {
  if (!confirm(`Are you sure you want to execute: ${label}?`)) return;
  const r = await api('/api/power', 'POST', { target });
  toast(r.message || 'Command executed!');
}

async function confirmBootNum(num, name) {
  if (!confirm(`Reboot PC into ${name} (UEFI Boot${num})?`)) return;
  const r = await api('/api/power', 'POST', { target: 'bootnum', bootnum: num, name });
  toast(r.message || ('Rebooting into ' + name + '...'));
}

async function doAction(type, value) {
  const r = await api('/api/action', 'POST', { type, value });
  toast(r.message || 'Done');
  if (r.ok !== false && (type === 'ws' || type === 'hypr')) {
    refreshStatus();
    setTimeout(() => refreshScreenshot(false), 350);
  }
}

async function sendInput(type) {
  const val = document.getElementById('msg-input').value.trim();
  if (!val) return toast('Please enter some text first!');
  const r = await api('/api/action', 'POST', { type, value: val });
  toast(r.message || 'Sent!');
  document.getElementById('msg-input').value = '';
}

async function runTerminal() {
  const cmd = document.getElementById('cmd-input').value.trim();
  if (!cmd) return;
  document.getElementById('term-out').textContent = 'Running: ' + cmd + ' ...';
  const r = await api('/api/action', 'POST', { type: 'shell', value: cmd });
  document.getElementById('term-out').textContent = r.output || r.message || '(No output returned)';
}

async function toggleTunnel(act) {
  toast(act === 'start' ? 'Starting public tunnel (~4s)...' : 'Stopping tunnel...');
  const r = await api('/api/tunnel', 'POST', { action: act });
  refreshStatus();
  if (r.url) toast('Public Link Online: ' + r.url);
}

async function loadFiles() {
  if (!_authenticated) return;
  const r = await api('/api/files');
  const fl = document.getElementById('file-list');
  fl.textContent = '';
  if (!r.files || !r.files.length) {
    const empty = document.createElement('div');
    empty.style.cssText = 'color:var(--muted);font-size:12px';
    empty.textContent = 'Downloads folder is empty.';
    fl.appendChild(empty);
    return;
  }
  for (const f of r.files) {
    const item = document.createElement('div');
    item.className = 'file-item';

    const nameBox = document.createElement('div');
    nameBox.className = 'file-name';
    nameBox.title = f.name;
    nameBox.appendChild(document.createTextNode('📄 ' + f.name + ' '));
    const szSpan = document.createElement('span');
    szSpan.style.cssText = 'color:var(--muted);font-size:11px';
    szSpan.textContent = `(${f.size})`;
    nameBox.appendChild(szSpan);

    const link = document.createElement('a');
    link.className = 'btn';
    link.style.cssText = 'padding:6px 10px;font-size:11px';
    link.href = '/api/download?name=' + encodeURIComponent(f.name);
    link.rel = 'noopener noreferrer';
    link.download = f.name;
    link.textContent = '⬇️ Download';

    item.appendChild(nameBox);
    item.appendChild(link);
    fl.appendChild(item);
  }
}

async function uploadFile() {
  if (!_authenticated) return;
  const inp = document.getElementById('file-upload');
  if (!inp.files.length) return toast('Please select a file first!');
  const file = inp.files[0];
  toast('Uploading ' + file.name + '...');
  const r = await fetch('/api/upload?name=' + encodeURIComponent(file.name), {
    method: 'POST',
    credentials: 'same-origin',
    headers: _csrfToken ? { 'X-CSRF-Token': _csrfToken } : {},
    body: file,
  });
  if (r.status === 401) {
    showLogin('Session expired. Enter PIN again.');
    return;
  }
  const res = await r.json();
  toast(res.message || 'Upload complete!');
  inp.value = '';
  loadFiles();
}

initAuth();
</script>
</body>
</html>
"""


# === HTTP SERVER & SECURITY ===

class ControlHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _client_ip(self):
        peer = self.client_address[0] if self.client_address else "unknown"
        if self._is_private_or_loopback(peer):
            cf_ip = (self.headers.get("Cf-Connecting-Ip") or "").strip()
            if cf_ip:
                return f"{peer}|cf:{cf_ip}"
            xff = (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
            if xff:
                return f"{peer}|xff:{xff}"
        return peer

    @staticmethod
    def _is_private_or_loopback(ip_str):
        try:
            addr = ipaddress.ip_address(str(ip_str or "").strip())
            return addr.is_loopback or addr.is_private or addr.is_link_local
        except ValueError:
            return False

    def _is_non_local_request(self):
        """Detect remote/online connections (e.g. Cloudflared tunnel, external proxy, public IP)."""
        peer = self.client_address[0] if self.client_address else ""
        if peer and not self._is_private_or_loopback(peer):
            return True
        for hdr in ("Cf-Connecting-Ip", "Cf-Ray", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded"):
            if (self.headers.get(hdr) or "").strip():
                return True
        host_hdr = (self.headers.get("Host") or "").strip()
        if host_hdr:
            hostname = urllib.parse.urlparse(f"//{host_hdr}").hostname or ""
            hostname = hostname.strip().lower()
            if hostname and hostname != "localhost" and not hostname.endswith(".local"):
                if not self._is_private_or_loopback(hostname):
                    return True
        return False

    def _send_json(self, data, status=HTTPStatus.OK, extra_headers=None):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        raw_len = self.headers.get("Content-Length", "0").strip()
        try:
            length = int(raw_len)
        except ValueError:
            raise _BadRequestError("Invalid Content-Length header")
        if length < 0:
            raise _BadRequestError("Negative Content-Length")
        if length > MAX_JSON_BYTES:
            raise _PayloadTooLargeError("JSON request too large")
        if length == 0:
            return {}
        try:
            raw = self.rfile.read(length).decode("utf-8")
        except UnicodeDecodeError:
            raise _BadRequestError("Request body must be valid UTF-8")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise _BadRequestError("Malformed JSON payload")
        if not isinstance(data, dict):
            raise _BadRequestError("JSON payload must be an object")
        return data

    def _get_session(self):
        raw_cookie = self.headers.get("Cookie", "")
        if not raw_cookie:
            return None, None
        cookies = http.cookies.SimpleCookie()
        try:
            cookies.load(raw_cookie)
        except http.cookies.CookieError:
            return None, None
        morsel = cookies.get("mrc_session")
        if not morsel or not morsel.value:
            return None, None
        token = morsel.value
        now = time.time()
        with _AUTH_LOCK:
            sess = _SESSIONS.get(token)
            if not sess:
                return None, None
            if now >= sess["expires"]:
                _SESSIONS.pop(token, None)
                return None, None
            return token, sess

    def _require_auth(self):
        token, sess = self._get_session()
        if not sess:
            self._send_json({"ok": False, "message": "Authentication required"}, HTTPStatus.UNAUTHORIZED)
            return None, None
        return token, sess

    def _check_origin(self):
        """Verify Origin or Referer matches Host when supplied by browser."""
        host = (self.headers.get("Host") or "").strip().lower()
        origin = (self.headers.get("Origin") or "").strip()
        referer = (self.headers.get("Referer") or "").strip()
        if origin:
            parsed = urllib.parse.urlparse(origin)
            if not host or parsed.netloc.lower() != host:
                self._send_json({"ok": False, "message": "Origin mismatch"}, HTTPStatus.FORBIDDEN)
                return False
        elif referer:
            parsed = urllib.parse.urlparse(referer)
            if not host or parsed.netloc.lower() != host:
                self._send_json({"ok": False, "message": "Referer mismatch"}, HTTPStatus.FORBIDDEN)
                return False
        return True

    def _require_csrf(self, sess):
        if not self._check_origin():
            return False
        supplied = (self.headers.get("X-CSRF-Token") or "").strip()
        if not supplied or not hmac.compare_digest(supplied, sess["csrf"]):
            self._send_json({"ok": False, "message": "Invalid or missing CSRF token"}, HTTPStatus.FORBIDDEN)
            return False
        return True

    def _safe_filename(self, raw_name):
        decoded = urllib.parse.unquote(str(raw_name or "")).strip()
        if not decoded or "/" in decoded or "\\" in decoded or decoded in (".", ".."):
            return ""
        if any(ord(ch) < 32 for ch in decoded):
            return ""
        return decoded

    def _check_rate_limit(self, attempts_map, ip, now):
        with _AUTH_LOCK:
            if len(attempts_map) > 1000:
                oldest_ip = min(attempts_map, key=lambda k: attempts_map[k].get("locked_until", 0))
                attempts_map.pop(oldest_ip, None)
            rec = attempts_map.get(ip, {"fails": 0, "locked_until": 0.0})
            if now < rec["locked_until"]:
                return max(1, int(rec["locked_until"] - now))
        return 0

    def _record_auth_failure(self, attempts_map, ip, now, invalidate_code=False):
        global _ACTIVE_CODE
        with _AUTH_LOCK:
            rec = attempts_map.get(ip, {"fails": 0, "locked_until": 0.0})
            rec["fails"] += 1
            if rec["fails"] >= LOGIN_MAX_FAILS:
                rec["locked_until"] = now + LOGIN_LOCKOUT_SEC
                rec["fails"] = 0
                attempts_map[ip] = rec
                if invalidate_code:
                    _ACTIVE_CODE = None
                return True
            attempts_map[ip] = rec
        return False

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            body = INDEX_HTML.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/assets/control-access":
            script_candidates = [
                os.path.join(CONFIG_DIR, "termux-control-access.sh"),
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "termux", "control-access"),
            ]
            for cand in script_candidates:
                if os.path.isfile(cand):
                    with open(cand, "rb") as f:
                        body = f.read()
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "text/x-shellscript; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.end_headers()
                    self.wfile.write(body)
                    return
            self.send_error(HTTPStatus.NOT_FOUND, "Termux helper script not installed")
            return

        if path == "/api/auth/status":
            _, sess = self._get_session()
            email_cfg = get_email_otp_settings()
            self._send_json({
                "authenticated": bool(sess),
                "csrf_token": sess["csrf"] if sess else "",
                "pin_mode": get_pin_mode(),
                "is_non_local": self._is_non_local_request(),
                "email_otp_enabled": email_cfg["configured"],
            })
            return

        _, sess = self._require_auth()
        if not sess:
            return

        if path == "/api/status":
            data = {
                "os": get_os_info(),
                "cpu_pct": get_cpu_percent(),
                "cpu_temp": get_cpu_temp(),
                "ram": get_memory_info(),
                "battery": get_battery_info(),
                "media": get_media_and_display(),
                "workspaces": get_workspaces_info(),
                "disks": get_disks_info(),
                "boot_entries": get_boot_entries(),
                "ips": get_local_ips(),
                "tunnel": get_tunnel_info(),
            }
            self._send_json(data)
            return

        if path == "/api/screenshot":
            _, uid, gid, _ = get_target_user_info()
            with tempfile.TemporaryDirectory(prefix="mrc_shot_") as tmpdir:
                try:
                    if os.geteuid() == 0 and uid != 0:
                        os.chown(tmpdir, uid, gid)
                    os.chmod(tmpdir, 0o700)
                except OSError:
                    pass
                raw_path = os.path.join(tmpdir, "raw.png")
                shot_path = os.path.join(tmpdir, "shot.jpg")

                capture_cmds = [
                    ["grim", raw_path],
                    ["spectacle", "-b", "-n", "-o", raw_path],
                    ["gnome-screenshot", "-f", raw_path],
                    ["maim", raw_path],
                    ["scrot", raw_path],
                    ["import", "-window", "root", raw_path],
                ]
                for cmd in capture_cmds:
                    if not shutil.which(cmd[0]):
                        continue
                    rc, _, _ = run_as_user(cmd, timeout=8, shell=False)
                    if rc == 0 and os.path.isfile(raw_path) and os.path.getsize(raw_path) > 1000:
                        break

                if os.path.isfile(raw_path) and os.path.getsize(raw_path) > 1000:
                    img = None
                    ctype = "image/png"
                    run_first_available([
                        ["magick", raw_path, "-resize", "1280x800", "-quality", "75", shot_path],
                        ["convert", raw_path, "-resize", "1280x800", "-quality", "75", shot_path],
                    ], timeout=8)
                    if os.path.isfile(shot_path) and os.path.getsize(shot_path) > 1000:
                        with open(shot_path, "rb") as f:
                            img = f.read()
                        ctype = "image/jpeg"
                    else:
                        try:
                            from PIL import Image
                            with Image.open(raw_path) as im:
                                rgb_im = im.convert("RGB")
                                rgb_im.thumbnail((1280, 800))
                                rgb_im.save(shot_path, "JPEG", quality=75)
                            with open(shot_path, "rb") as f:
                                img = f.read()
                            ctype = "image/jpeg"
                        except Exception:
                            with open(raw_path, "rb") as f:
                                img = f.read()
                            ctype = "image/png"

                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(len(img)))
                    self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.end_headers()
                    self.wfile.write(img)
                    return

            self.send_error(HTTPStatus.NOT_FOUND, "Failed to capture desktop screen")
            return

        if path == "/api/files":
            downloads_dir = get_downloads_dir()
            os.makedirs(downloads_dir, exist_ok=True)
            files = []
            try:
                entries = [
                    e for e in os.scandir(downloads_dir)
                    if not e.is_symlink() and e.is_file(follow_symlinks=False)
                ]
                for entry in sorted(entries, key=lambda e: e.stat(follow_symlinks=False).st_mtime, reverse=True):
                    sz = entry.stat(follow_symlinks=False).st_size
                    sz_str = f"{sz / (1024*1024):.1f} MB" if sz >= 1024 * 1024 else f"{sz / 1024:.1f} KB"
                    files.append({"name": entry.name, "size": sz_str})
            except Exception:
                pass
            self._send_json({"files": files[:50]})
            return

        if path == "/api/download":
            downloads_dir = get_downloads_dir()
            name = self._safe_filename(qs.get("name", [""])[0])
            if not name:
                self._send_json({"ok": False, "message": "Invalid file name"}, HTTPStatus.BAD_REQUEST)
                return
            fpath = os.path.join(downloads_dir, name)
            if os.path.islink(fpath):
                self._send_json({"ok": False, "message": "Symlinks are not allowed"}, HTTPStatus.FORBIDDEN)
                return
            real_base = os.path.realpath(downloads_dir)
            real_file = os.path.realpath(fpath)
            try:
                within_dir = os.path.commonpath([real_base, real_file]) == real_base
            except ValueError:
                within_dir = False
            if within_dir and os.path.isfile(real_file):
                ctype = mimetypes.guess_type(real_file)[0] or "application/octet-stream"
                sz = os.path.getsize(real_file)
                safe_name = name.replace('"', "").replace("\r", "").replace("\n", "")
                enc_name = urllib.parse.quote(name)
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(sz))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Disposition", f'attachment; filename="{safe_name}"; filename*=UTF-8\'\'{enc_name}')
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                with open(real_file, "rb") as f:
                    shutil.copyfileobj(f, self.wfile)
                return
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if path == "/api/pairing/code":
            if not self._check_origin():
                return
            ip = self._client_ip()
            now = time.time()
            wait_sec = self._check_rate_limit(_PAIRING_ATTEMPTS, ip, now)
            if wait_sec:
                self._send_json(
                    {"ok": False, "message": f"Too many invalid token attempts. Try again in {wait_sec}s."},
                    HTTPStatus.TOO_MANY_REQUESTS,
                )
                return

            auth_hdr = (self.headers.get("Authorization") or "").strip()
            supplied_tok = auth_hdr[7:].strip() if auth_hdr.startswith("Bearer ") else ""
            expected_tok = get_termux_token()
            if not supplied_tok or not hmac.compare_digest(supplied_tok, expected_tok):
                locked = self._record_auth_failure(_PAIRING_ATTEMPTS, ip, now)
                if locked:
                    self._send_json(
                        {"ok": False, "message": f"Too many invalid token attempts. Locked for {LOGIN_LOCKOUT_SEC}s."},
                        HTTPStatus.TOO_MANY_REQUESTS,
                    )
                    return
                self._send_json({"ok": False, "message": "Invalid or missing pairing token"}, HTTPStatus.UNAUTHORIZED)
                return

            with _AUTH_LOCK:
                _PAIRING_ATTEMPTS.pop(ip, None)
            code, ttl = issue_one_time_code()
            tunnel_info = get_tunnel_info()
            self._send_json({
                "ok": True,
                "code": code,
                "expires_in": ttl,
                "ips": get_local_ips(),
                "port": PORT,
                "tunnel_url": tunnel_info.get("url", ""),
            })
            return

        if path == "/api/pairing/email-code":
            if not self._check_origin():
                return
            try:
                data = self._read_json()
            except _PayloadTooLargeError as e:
                self._send_json({"ok": False, "message": str(e)}, HTTPStatus.REQUEST_ENTITY_LARGE if hasattr(HTTPStatus, "REQUEST_ENTITY_LARGE") else HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                return
            except _BadRequestError as e:
                self._send_json({"ok": False, "message": str(e)}, HTTPStatus.BAD_REQUEST)
                return

            email_norm = _normalize_email(data.get("email", ""))
            if not email_norm:
                self._send_json({"ok": False, "message": "Please enter a valid email address."}, HTTPStatus.BAD_REQUEST)
                return

            email_cfg = get_email_otp_settings()
            if not email_cfg["configured"]:
                self._send_json(
                    {"ok": False, "message": "Email OTP is not configured on host. Run: sudo control-access --setup-email"},
                    HTTPStatus.SERVICE_UNAVAILABLE,
                )
                return

            ip = self._client_ip()
            now = time.time()
            with _AUTH_LOCK:
                global _EMAIL_HOURLY_TS
                _EMAIL_HOURLY_TS = [t for t in _EMAIL_HOURLY_TS if now - t < 3600]
                if len(_EMAIL_COOLDOWNS) > 1000:
                    oldest = min(_EMAIL_COOLDOWNS, key=lambda k: _EMAIL_COOLDOWNS[k])
                    _EMAIL_COOLDOWNS.pop(oldest, None)
                last_ip = _EMAIL_COOLDOWNS.get(ip, 0.0)
                if now - last_ip < EMAIL_COOLDOWN_SEC:
                    wait_s = max(1, int(EMAIL_COOLDOWN_SEC - (now - last_ip)))
                    self._send_json(
                        {"ok": False, "message": f"Please wait {wait_s}s before requesting another code."},
                        HTTPStatus.TOO_MANY_REQUESTS,
                    )
                    return
                if len(_EMAIL_HOURLY_TS) >= EMAIL_HOURLY_MAX:
                    self._send_json(
                        {"ok": False, "message": "Hourly email OTP limit reached. Try again later."},
                        HTTPStatus.TOO_MANY_REQUESTS,
                    )
                    return
                _EMAIL_COOLDOWNS[ip] = now

            generic_ok = f"If this email is registered, a 6-digit code has been sent (valid {CODE_TTL_SEC}s)."
            if not _is_allowed_email(email_norm, email_cfg["allowed_emails"]):
                self._send_json({"ok": True, "message": generic_ok})
                return

            code = f"{secrets.randbelow(1000000):06d}"
            ok_send, _ = send_otp_email(email_norm, code, CODE_TTL_SEC, client_hint=ip, settings=email_cfg)
            if not ok_send:
                self._send_json(
                    {"ok": False, "message": "Failed to send email via host SMTP. Check SMTP/App Password settings."},
                    HTTPStatus.BAD_GATEWAY,
                )
                return

            with _AUTH_LOCK:
                _EMAIL_HOURLY_TS.append(now)
            _store_one_time_code(code, CODE_TTL_SEC, source="email", email=email_norm)
            self._send_json({"ok": True, "message": generic_ok})
            return

        if path == "/api/login":
            if not self._check_origin():
                return
            try:
                data = self._read_json()
            except _PayloadTooLargeError as e:
                self._send_json({"ok": False, "message": str(e)}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                return
            except _BadRequestError as e:
                self._send_json({"ok": False, "message": str(e)}, HTTPStatus.BAD_REQUEST)
                return

            ip = self._client_ip()
            now = time.time()
            wait_sec = self._check_rate_limit(_LOGIN_ATTEMPTS, ip, now)
            if wait_sec:
                self._send_json(
                    {"ok": False, "message": f"Too many failed attempts. Try again in {wait_sec}s."},
                    HTTPStatus.TOO_MANY_REQUESTS,
                )
                return

            supplied_pin = str(data.get("pin", "")).strip()
            ok, reason = _verify_login_code(supplied_pin)
            if ok:
                session_token = secrets.token_urlsafe(32)
                csrf_token = secrets.token_urlsafe(24)
                with _AUTH_LOCK:
                    _LOGIN_ATTEMPTS.pop(ip, None)
                    expired = [k for k, v in _SESSIONS.items() if now >= v["expires"]]
                    for k in expired:
                        _SESSIONS.pop(k, None)
                    _SESSIONS[session_token] = {
                        "expires": now + SESSION_TTL_SEC,
                        "csrf": csrf_token,
                        "ip": ip,
                    }
                cookie_val = (
                    f"mrc_session={session_token}; HttpOnly; SameSite=Strict; "
                    f"Path=/; Max-Age={SESSION_TTL_SEC}"
                )
                self._send_json(
                    {"ok": True, "csrf_token": csrf_token},
                    HTTPStatus.OK,
                    extra_headers={"Set-Cookie": cookie_val},
                )
                return

            locked = self._record_auth_failure(_LOGIN_ATTEMPTS, ip, now, invalidate_code=True)
            if locked:
                self._send_json(
                    {"ok": False, "message": f"Too many failed attempts. Locked for {LOGIN_LOCKOUT_SEC}s."},
                    HTTPStatus.TOO_MANY_REQUESTS,
                )
                return

            is_remote = self._is_non_local_request()
            if is_remote:
                msg_map = {
                    "missing": "No active code. Request an Email OTP above or use 'control-access' first.",
                    "expired": "Code expired. Request a new code to continue.",
                    "invalid": "Invalid code",
                }
            else:
                msg_map = {
                    "missing": "No active code. Run 'control-access' in Termux first.",
                    "expired": "Code expired. Run 'control-access' in Termux for a new one.",
                    "invalid": "Invalid code",
                }
            self._send_json({"ok": False, "message": msg_map.get(reason, "Invalid code")}, HTTPStatus.UNAUTHORIZED)
            return

        token, sess = self._require_auth()
        if not sess:
            return
        if not self._require_csrf(sess):
            return

        if path == "/api/logout":
            with _AUTH_LOCK:
                _SESSIONS.pop(token, None)
            self._send_json(
                {"ok": True, "message": "Locked"},
                HTTPStatus.OK,
                extra_headers={"Set-Cookie": "mrc_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"},
            )
            return

        if path == "/api/upload":
            downloads_dir = get_downloads_dir()
            _, uid, gid, _ = get_target_user_info()
            raw_name = qs.get("name", [""])[0]
            if not raw_name:
                raw_name = f"upload_{int(time.time())}.bin"
            name = self._safe_filename(raw_name)
            if not name:
                self._send_json({"ok": False, "message": "Invalid upload filename"}, HTTPStatus.BAD_REQUEST)
                return

            raw_len = self.headers.get("Content-Length", "").strip()
            try:
                length = int(raw_len)
            except ValueError:
                self._send_json({"ok": False, "message": "Valid Content-Length required"}, HTTPStatus.BAD_REQUEST)
                return
            if length < 0:
                self._send_json({"ok": False, "message": "Invalid Content-Length"}, HTTPStatus.BAD_REQUEST)
                return
            if length > MAX_UPLOAD_BYTES:
                self._send_json(
                    {"ok": False, "message": f"Upload exceeds {MAX_UPLOAD_BYTES // (1024*1024)} MB limit"},
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                )
                return

            os.makedirs(downloads_dir, exist_ok=True)
            stem, ext = os.path.splitext(name)
            final_name = name
            dest = os.path.join(downloads_dir, final_name)
            idx = 1
            while os.path.exists(dest) or os.path.islink(dest):
                final_name = f"{stem}_{idx}{ext}"
                dest = os.path.join(downloads_dir, final_name)
                idx += 1

            total_read = 0
            try:
                with open(dest, "wb") as f:
                    remaining = length
                    while remaining > 0:
                        chunk = self.rfile.read(min(65536, remaining))
                        if not chunk:
                            break
                        total_read += len(chunk)
                        if total_read > MAX_UPLOAD_BYTES:
                            raise _PayloadTooLargeError("Upload exceeded size limit")
                        f.write(chunk)
                        remaining -= len(chunk)
                if total_read != length:
                    raise _BadRequestError("Incomplete upload stream")
            except _PayloadTooLargeError as e:
                try:
                    os.remove(dest)
                except OSError:
                    pass
                self._send_json({"ok": False, "message": str(e)}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                return
            except Exception as e:
                try:
                    os.remove(dest)
                except OSError:
                    pass
                self._send_json({"ok": False, "message": f"Upload failed: {e}"}, HTTPStatus.BAD_REQUEST)
                return

            try:
                if os.geteuid() == 0 and uid != 0:
                    os.chown(dest, uid, gid)
            except OSError:
                pass
            self._send_json({"ok": True, "filename": final_name, "message": f"File '{final_name}' saved to ~/Downloads!"})
            return

        try:
            data = self._read_json()
        except _PayloadTooLargeError as e:
            self._send_json({"ok": False, "message": str(e)}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return
        except _BadRequestError as e:
            self._send_json({"ok": False, "message": str(e)}, HTTPStatus.BAD_REQUEST)
            return

        if path == "/api/media":
            act = str(data.get("action", ""))
            val = data.get("value", "")
            if act == "play-pause":
                run_as_user(["playerctl", "play-pause"])
            elif act == "next":
                run_as_user(["playerctl", "next"])
            elif act == "prev":
                run_as_user(["playerctl", "previous"])
            elif act == "mute":
                run_first_available([
                    ["wpctl", "set-mute", "@DEFAULT_AUDIO_SINK@", "toggle"],
                    ["pactl", "set-sink-mute", "@DEFAULT_SINK@", "toggle"],
                    ["amixer", "set", "Master", "toggle"],
                ])
            elif act == "vol_up":
                run_first_available([
                    ["wpctl", "set-volume", "-l", "1.5", "@DEFAULT_AUDIO_SINK@", "5%+"],
                    ["pactl", "set-sink-volume", "@DEFAULT_SINK@", "+5%"],
                    ["amixer", "set", "Master", "5%+"],
                ])
            elif act == "vol_down":
                run_first_available([
                    ["wpctl", "set-volume", "@DEFAULT_AUDIO_SINK@", "5%-"],
                    ["pactl", "set-sink-volume", "@DEFAULT_SINK@", "-5%"],
                    ["amixer", "set", "Master", "5%-"],
                ])
            elif act == "vol_set":
                try:
                    pct = max(0, min(150, int(float(val))))
                except (TypeError, ValueError):
                    self._send_json({"ok": False, "message": "Invalid volume value"}, HTTPStatus.BAD_REQUEST)
                    return
                run_first_available([
                    ["wpctl", "set-volume", "@DEFAULT_AUDIO_SINK@", f"{pct}%"],
                    ["pactl", "set-sink-volume", "@DEFAULT_SINK@", f"{pct}%"],
                ])
            elif act == "bright_up":
                rc, _, _ = run_first_available([["brightnessctl", "set", "+10%"], ["light", "-A", "10"]])
                if rc != 0:
                    run_first_system_cmd([["brightnessctl", "set", "+10%"], ["light", "-A", "10"]])
            elif act == "bright_down":
                rc, _, _ = run_first_available([["brightnessctl", "set", "10%-"], ["light", "-U", "10"]])
                if rc != 0:
                    run_first_system_cmd([["brightnessctl", "set", "10%-"], ["light", "-U", "10"]])
            elif act == "bright_set":
                try:
                    pct = max(5, min(100, int(float(val))))
                except (TypeError, ValueError):
                    self._send_json({"ok": False, "message": "Invalid brightness value"}, HTTPStatus.BAD_REQUEST)
                    return
                rc, _, _ = run_first_available([["brightnessctl", "set", f"{pct}%"], ["light", "-S", str(pct)]])
                if rc != 0:
                    run_first_system_cmd([["brightnessctl", "set", f"{pct}%"], ["light", "-S", str(pct)]])
            else:
                self._send_json({"ok": False, "message": "Unsupported media action"}, HTTPStatus.BAD_REQUEST)
                return
            self._send_json({"ok": True, "message": f"Action {act} executed"})
            return

        if path == "/api/power":
            target = str(data.get("target", "")).lower().strip()
            bootnum = str(data.get("bootnum", "")).strip()

            if target == "bootnum":
                if not re.fullmatch(r"[0-9a-fA-F]{4}", bootnum):
                    self._send_json({"ok": False, "message": "Invalid UEFI boot number"}, HTTPStatus.BAD_REQUEST)
                    return
                norm_num = bootnum.upper()
                rc, _, err = run_cmd(["efibootmgr", "-n", norm_num])
                if rc != 0:
                    self._send_json({"ok": False, "message": f"efibootmgr failed: {err}"}, HTTPStatus.INTERNAL_SERVER_ERROR)
                    return
                name = str(data.get("name", f"Boot{norm_num}"))[:64]
                threading.Thread(
                    target=_delayed_power,
                    args=([["systemctl", "reboot"], ["loginctl", "reboot"], ["reboot"]],),
                    daemon=True,
                ).start()
                self._send_json({"ok": True, "message": f"BootNext set to {norm_num} ({name}). Rebooting..."})
                return

            if target in ("arch", "garuda", "gentoo", "ubuntu", "fedora", "debian", "windows"):
                _, out, _ = run_cmd(["efibootmgr"])
                found_num = None
                for line in out.splitlines():
                    m = re.match(r"^Boot([0-9A-Fa-f]{4})", line)
                    if m and target in line.lower():
                        found_num = m.group(1).upper()
                        break
                if not found_num:
                    self._send_json(
                        {"ok": False, "message": f"UEFI boot entry for '{target}' not found on this system!"},
                        HTTPStatus.BAD_REQUEST,
                    )
                    return
                rc, _, err = run_cmd(["efibootmgr", "-n", found_num])
                if rc != 0:
                    self._send_json({"ok": False, "message": f"efibootmgr failed: {err}"}, HTTPStatus.INTERNAL_SERVER_ERROR)
                    return
                threading.Thread(
                    target=_delayed_power,
                    args=([["systemctl", "reboot"], ["loginctl", "reboot"], ["reboot"]],),
                    daemon=True,
                ).start()
                self._send_json({"ok": True, "message": f"BootNext set to {found_num} ({target.upper()}). Rebooting..."})
                return

            if target == "uefi":
                threading.Thread(
                    target=_delayed_power,
                    args=([["systemctl", "reboot", "--firmware-setup"], ["loginctl", "reboot", "--firmware-setup"]],),
                    daemon=True,
                ).start()
                self._send_json({"ok": True, "message": "Rebooting into BIOS / UEFI setup..."})
                return

            if target == "reboot":
                threading.Thread(
                    target=_delayed_power,
                    args=([["systemctl", "reboot"], ["loginctl", "reboot"], ["reboot"]],),
                    daemon=True,
                ).start()
                self._send_json({"ok": True, "message": "Rebooting system..."})
                return

            if target == "poweroff":
                threading.Thread(
                    target=_delayed_power,
                    args=([["systemctl", "poweroff"], ["loginctl", "poweroff"], ["poweroff"]],),
                    daemon=True,
                ).start()
                self._send_json({"ok": True, "message": "Shutting down system..."})
                return

            if target == "lock":
                run_first_available([["hyprlock"], ["swaylock"], ["loginctl", "lock-session"]])
                run_cmd(["loginctl", "lock-sessions"])
                self._send_json({"ok": True, "message": "Screen locked!"})
                return

            if target == "suspend":
                threading.Thread(
                    target=_delayed_power,
                    args=([["systemctl", "suspend"], ["loginctl", "suspend"]],),
                    daemon=True,
                ).start()
                self._send_json({"ok": True, "message": "Suspending system..."})
                return

            self._send_json({"ok": False, "message": "Unknown power target"}, HTTPStatus.BAD_REQUEST)
            return

        if path == "/api/action":
            tp = str(data.get("type", "")).strip()
            val = data.get("value", "")

            if tp == "notify":
                msg = str(val).strip()
                if not msg or len(msg) > 500:
                    self._send_json({"ok": False, "message": "Notification must be 1-500 characters"}, HTTPStatus.BAD_REQUEST)
                    return
                run_first_available([
                    ["notify-send", "-u", "critical", "Mobile-RC Message", msg],
                    ["hyprctl", "notify", "1", "3000", "rgb(38bdf8)", msg],
                ])
                self._send_json({"ok": True, "message": "Notification sent to PC screen!"})
                return

            if tp == "clipboard":
                text = str(val)
                if not text or len(text) > 20000:
                    self._send_json({"ok": False, "message": "Clipboard text must be 1-20000 characters"}, HTTPStatus.BAD_REQUEST)
                    return
                rc, _, err = run_first_available(
                    [
                        ["wl-copy"],
                        ["xclip", "-selection", "clipboard"],
                        ["xsel", "--clipboard", "--input"],
                    ],
                    timeout=4,
                    input_text=text,
                    discard_output=True,
                )
                if rc != 0:
                    self._send_json({"ok": False, "message": f"Clipboard error: {err}"}, HTTPStatus.INTERNAL_SERVER_ERROR)
                    return
                self._send_json({"ok": True, "message": "Copied to PC clipboard!"})
                return

            if tp == "open_url":
                url = str(val).strip()
                if not url or any(ch.isspace() or ord(ch) < 32 for ch in url):
                    self._send_json({"ok": False, "message": "Invalid HTTP/HTTPS URL"}, HTTPStatus.BAD_REQUEST)
                    return
                head = url.split("/", 1)[0]
                if "://" not in url:
                    if ":" not in head or head.split(":", 1)[1].isdigit():
                        url = "https://" + url
                u_parsed = urllib.parse.urlparse(url)
                try:
                    _ = u_parsed.port
                    hostname = u_parsed.hostname
                except ValueError:
                    hostname = None
                if (
                    u_parsed.scheme.lower() not in ("http", "https")
                    or not hostname
                    or u_parsed.username is not None
                    or u_parsed.password is not None
                ):
                    self._send_json({"ok": False, "message": "Invalid HTTP/HTTPS URL"}, HTTPStatus.BAD_REQUEST)
                    return
                run_as_user(["xdg-open", url], background=True)
                self._send_json({"ok": True, "message": f"Opening {url} on PC browser!"})
                return

            if tp == "launch":
                preset = str(val).strip()
                if preset not in LAUNCH_PRESETS:
                    self._send_json({"ok": False, "message": "Invalid application preset"}, HTTPStatus.BAD_REQUEST)
                    return
                for cmd in LAUNCH_PRESETS[preset]:
                    if shutil.which(cmd[0]):
                        run_as_user(cmd, background=True)
                        self._send_json({"ok": True, "message": f"Launching preset: {preset}"})
                        return
                self._send_json({"ok": False, "message": f"No binary found for preset: {preset}"}, HTTPStatus.NOT_FOUND)
                return

            if tp == "ws":
                try:
                    val_num = int(val)
                except (TypeError, ValueError):
                    self._send_json({"ok": False, "message": "Workspace must be an integer"}, HTTPStatus.BAD_REQUEST)
                    return
                if not (1 <= val_num <= 99):
                    self._send_json({"ok": False, "message": "Workspace must be between 1 and 99"}, HTTPStatus.BAD_REQUEST)
                    return
                rc, _, err = run_first_available([
                    ["hyprctl", "dispatch", f"hl.dsp.focus({{ workspace = {val_num} }})"],
                    ["hyprctl", "dispatch", "workspace", str(val_num)],
                    ["swaymsg", "workspace", str(val_num)],
                    ["wmctrl", "-s", str(val_num - 1)],
                    ["xdotool", "set_desktop", str(val_num - 1)],
                ])
                if rc != 0:
                    self._send_json(
                        {"ok": False, "message": err or f"Failed to switch to Workspace {val_num}"},
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                    )
                    return
                self._send_json({"ok": True, "message": f"Switched to Workspace {val_num}"})
                return

            if tp == "hypr":
                act = str(val).strip()
                if act not in HYPR_PRESETS:
                    self._send_json({"ok": False, "message": "Invalid window action"}, HTTPStatus.BAD_REQUEST)
                    return
                rc, _, err = run_first_available(HYPR_PRESETS[act])
                if rc != 0:
                    self._send_json(
                        {"ok": False, "message": err or f"Window action failed: {act}"},
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                    )
                    return
                self._send_json({"ok": True, "message": f"Window action: {act}"})
                return

            if tp == "shell":
                if os.environ.get("MRC_DISABLE_SHELL", "").strip().lower() in ("1", "true", "yes"):
                    self._send_json({"ok": False, "message": "Quick Web Terminal is disabled"}, HTTPStatus.FORBIDDEN)
                    return
                cmd_str = str(val).strip()
                if not cmd_str or len(cmd_str) > 2000:
                    self._send_json({"ok": False, "message": "Command must be 1-2000 characters"}, HTTPStatus.BAD_REQUEST)
                    return
                rc, out, err = run_as_user(cmd_str, timeout=15, shell=True)
                combined = (out + ("\n" + err if err else "")).strip()
                self._send_json({"ok": rc == 0, "output": combined or f"(Exit code {rc})"})
                return

            self._send_json({"ok": False, "message": "Invalid action type"}, HTTPStatus.BAD_REQUEST)
            return

        if path == "/api/tunnel":
            global _TUNNEL_AUTO
            act = str(data.get("action", "start")).strip().lower()
            if act == "start":
                _TUNNEL_AUTO = True
                info = start_tunnel()
                self._send_json(info)
            elif act == "stop":
                _TUNNEL_AUTO = False
                info = stop_tunnel()
                self._send_json(info)
            else:
                self._send_json({"ok": False, "message": "Invalid tunnel action"}, HTTPStatus.BAD_REQUEST)
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")


def main():
    _ensure_config_dir()
    if get_pin_mode() == "static":
        get_pin()
    get_termux_token()
    get_ntfy_topic()
    get_cpu_percent()
    threading.Thread(target=_tunnel_watchdog, daemon=True).start()
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), ControlHandler)
    print(f"[Mobile-RC] Server running at http://0.0.0.0:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop_tunnel()
        server.server_close()


if __name__ == "__main__":
    main()

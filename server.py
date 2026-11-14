#!/usr/bin/env python3
"""Mobile-RC (Cross-Platform Linux & Windows Control Center) — Pure Python Stdlib Server."""

from collections import deque
import csv
import ctypes
from email.message import EmailMessage
from http import HTTPStatus
import hashlib
import http.cookies
import http.server
import hmac
import ipaddress
import json
import mimetypes
import os
import platform
try:
    import pwd
except ImportError:
    pwd = None
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

IS_WINDOWS = os.name == "nt"


def _default_config_dir():
    env_dir = os.environ.get("MRC_CONFIG_DIR", "").strip()
    if env_dir:
        return env_dir
    if IS_WINDOWS:
        prog_data = os.environ.get("ProgramData", r"C:\ProgramData")
        cand = os.path.join(prog_data, "Mobile-RC")
        try:
            os.makedirs(cand, exist_ok=True)
            test_f = os.path.join(cand, ".perm_check")
            with open(test_f, "w", encoding="utf-8") as f:
                f.write("ok")
            os.remove(test_f)
            return cand
        except OSError:
            local_app = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
            return os.path.join(local_app, "Mobile-RC")
    return "/opt/mobile-rc"


def _is_root_or_admin():
    if IS_WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


PORT = int(os.environ.get("MRC_PORT", "8000"))
DISCOVERY_PORT = int(os.environ.get("MRC_DISCOVERY_PORT", "8001"))
DISCOVERY_ENABLED = os.environ.get("MRC_DISCOVERY", "1").strip().lower() not in ("0", "false", "no")
CONFIG_DIR = _default_config_dir()
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
FEEDBACK_TARGET_EMAIL = os.environ.get("MRC_FEEDBACK_EMAIL", "brypra4@gmail.com").strip() or "brypra4@gmail.com"
FEEDBACK_WEBHOOK_URL = os.environ.get("MRC_FEEDBACK_WEBHOOK", "").strip()

LAUNCH_PRESETS = {
    "terminal": [
        ["kitty"],
        ["konsole"],
        ["alacritty"],
        ["foot"],
        ["wezterm"],
        ["ghostty"],
        ["gnome-terminal"],
        ["xfce4-terminal"],
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
        ["niri", "msg", "action", "fullscreen-window"],
        ["swaymsg", "fullscreen", "toggle"],
        ["riverctl", "toggle-fullscreen"],
        ["qdbus6", "org.kde.kglobalaccel", "/component/kwin", "invokeShortcut", "Window Fullscreen"],
        ["qdbus", "org.kde.kglobalaccel", "/component/kwin", "invokeShortcut", "Window Fullscreen"],
        ["wmctrl", "-r", ":ACTIVE:", "-b", "toggle,fullscreen"],
        ["xdotool", "key", "F11"],
    ],
    "killactive": [
        ["hyprctl", "dispatch", "hl.dsp.window.close()"],
        ["hyprctl", "dispatch", "killactive"],
        ["niri", "msg", "action", "close-window"],
        ["swaymsg", "kill"],
        ["riverctl", "close"],
        ["qdbus6", "org.kde.kglobalaccel", "/component/kwin", "invokeShortcut", "Window Close"],
        ["qdbus", "org.kde.kglobalaccel", "/component/kwin", "invokeShortcut", "Window Close"],
        ["kdotool", "getactivewindow", "windowclose"],
        ["wmctrl", "-c", ":ACTIVE:"],
        ["xdotool", "getactivewindow", "windowclose"],
    ],
    "dpms_toggle": [
        ["hyprctl", "dispatch", 'hl.dsp.dpms({ action = "toggle" })'],
        ["hyprctl", "dispatch", "dpms", "toggle"],
        ["niri", "msg", "action", "power-off-monitors"],
        ["swaymsg", "output", "*", "dpms", "toggle"],
        ["wlopm", "--toggle", "*"],
        ["qdbus6", "org.kde.kglobalaccel", "/component/org_kde_powerdevil", "invokeShortcut", "Turn Off Screen"],
        ["qdbus", "org.kde.kglobalaccel", "/component/org_kde_powerdevil", "invokeShortcut", "Turn Off Screen"],
        ["kscreen-doctor", "--dpms", "off"],
        ["xset", "dpms", "force", "off"],
    ],
}

_LAST_RIVER_TAG = 1

_CONFIG_LOCK = threading.Lock()
_AUTH_LOCK = threading.Lock()
_SESSIONS = {}  # token -> {"expires": float, "csrf": str, "ip": str}
_HANDOFF_TICKETS = {}  # handoff_token -> {"expires": float, "ip": str}
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
_FEEDBACK_HISTORY = {}  # ip -> list[float timestamps]
_NET_LAST = None
_PROC_LAST = None
_DISTRO_SCAN_LOCK = threading.Lock()
_DISTRO_CACHE = {"safe": None, "deep": None}
_AUDIT_LOG = deque(maxlen=150)
_TTL_CACHE = {}
_TTL_LOCK = threading.Lock()
_CONFIG_MTIME_CACHE = None  # (path, mtime_ns, size, dict)


def _cached(key, ttl_sec, fn, force=False):
    now = time.monotonic()
    if not force:
        with _TTL_LOCK:
            entry = _TTL_CACHE.get(key)
            if entry is not None and (now - entry[0]) < ttl_sec:
                val = entry[1]
                if isinstance(val, dict):
                    return dict(val)
                if isinstance(val, list):
                    return list(val)
                return val
    val = fn()
    with _TTL_LOCK:
        _TTL_CACHE[key] = (time.monotonic(), val)
    if isinstance(val, dict):
        return dict(val)
    if isinstance(val, list):
        return list(val)
    return val


def _invalidate_cache(*prefixes):
    with _TTL_LOCK:
        if not prefixes:
            _TTL_CACHE.clear()
            return
        keys = [k for k in _TTL_CACHE if any(str(k).startswith(p) for p in prefixes)]
        for k in keys:
            _TTL_CACHE.pop(k, None)


def record_audit_event(level, message):
    """Append a structured runtime/security event to the bounded ring buffer."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    _AUDIT_LOG.append({
        "ts": ts,
        "source": "mobile-rc",
        "level": str(level).upper(),
        "message": str(message),
    })


class _PayloadTooLargeError(Exception):
    pass


class _BadRequestError(Exception):
    pass


def _ensure_config_dir():
    os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)
    if not IS_WINDOWS:
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
        if not IS_WINDOWS:
            os.chmod(path, mode)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def get_config():
    global _CONFIG_MTIME_CACHE
    with _CONFIG_LOCK:
        try:
            if os.path.exists(CONFIG_FILE):
                st = os.stat(CONFIG_FILE)
                if (
                    _CONFIG_MTIME_CACHE is not None
                    and _CONFIG_MTIME_CACHE[0] == CONFIG_FILE
                    and _CONFIG_MTIME_CACHE[1] == st.st_mtime_ns
                    and _CONFIG_MTIME_CACHE[2] == st.st_size
                ):
                    return dict(_CONFIG_MTIME_CACHE[3])
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        _CONFIG_MTIME_CACHE = (CONFIG_FILE, st.st_mtime_ns, st.st_size, dict(data))
                        return dict(data)
        except Exception:
            pass
    return {}


def save_config(data):
    global _CONFIG_MTIME_CACHE
    with _CONFIG_LOCK:
        try:
            _ensure_config_dir()
            _write_secure_file(CONFIG_FILE, json.dumps(data, indent=2) + "\n", 0o600)
            try:
                st = os.stat(CONFIG_FILE)
                _CONFIG_MTIME_CACHE = (CONFIG_FILE, st.st_mtime_ns, st.st_size, dict(data))
            except OSError:
                _CONFIG_MTIME_CACHE = None
        except Exception:
            _CONFIG_MTIME_CACHE = None
    _invalidate_cache("target_user")


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


def _compute_target_user_info():
    if IS_WINDOWS or pwd is None:
        user = (
            os.environ.get("MRC_USER", "").strip()
            or os.environ.get("USERNAME", "").strip()
            or os.environ.get("USER", "").strip()
            or "user"
        )
        home = os.path.expanduser("~")
        return user, 0, 0, home

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

    try:
        for pw in pwd.getpwall():
            if 1000 <= pw.pw_uid < 60000 and not pw.pw_shell.endswith(("nologin", "false")):
                return pw.pw_name, pw.pw_uid, pw.pw_gid, pw.pw_dir
    except Exception:
        pass

    return "root", 0, 0, "/root"


def get_target_user_info():
    """Return (username, uid, gid, home_dir) of the target desktop user (cached 30s)."""
    key = f"target_user:{CONFIG_FILE}:{os.environ.get('MRC_USER', '')}"
    return _cached(key, 30.0, _compute_target_user_info)


def get_downloads_dir():
    """Locate the target user's Downloads directory cleanly."""
    _, uid, gid, home = get_target_user_info()
    if not IS_WINDOWS:
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
        if not IS_WINDOWS and hasattr(os, "geteuid") and os.geteuid() == 0 and uid != 0:
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


def _deliver_smtp_message(cfg, msg, context_label="Email"):
    """Deliver an EmailMessage over configured SMTP TLS or SSL transport."""
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
        print(f"[Mobile-RC] {context_label} SMTP error ({cfg['smtp_host']}:{cfg['smtp_port']}): {e}", file=sys.stderr)
        return False, str(e)


def send_otp_email(to_email, code, ttl, client_hint="", settings=None):
    """Send a single-use 6-digit login code via configured SMTP server (e.g. Gmail App Password)."""
    cfg = settings or get_email_otp_settings()
    if not cfg.get("configured"):
        return False, "Email OTP is not configured on host"

    host_name = platform.node() or "Linux Host"
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
    return _deliver_smtp_message(cfg, msg, "Email OTP")


def build_feedback_fallbacks(category, subject, message, sysinfo_text=""):
    """Build safe mailto and GitHub Issue fallback URLs when no relay/SMTP is configured."""
    cat_title = category.title()
    full_subject = f"[Mobile-RC {cat_title}] {subject}"
    body_lines = [message]
    if sysinfo_text:
        body_lines.extend(["", "--- System Info ---", sysinfo_text])
    full_body = "\n".join(body_lines)
    mailto_url = (
        f"mailto:{urllib.parse.quote(FEEDBACK_TARGET_EMAIL, safe='@')}"
        f"?subject={urllib.parse.quote(full_subject)}"
        f"&body={urllib.parse.quote(full_body)}"
    )
    github_url = (
        "https://github.com/739202873/linux-mobile-remote-control/issues/new"
        f"?title={urllib.parse.quote(full_subject)}"
        f"&body={urllib.parse.quote(full_body)}"
    )
    return mailto_url, github_url


def send_feedback_report(category, subject, message, reply_to="", include_sysinfo=False):
    """Deliver user suggestion/bug report via local SMTP, optional HTTPS webhook, or fallback links."""
    sysinfo_text = ""
    if include_sysinfo:
        os_info = get_os_info()
        comp = get_active_compositor(get_desktop_env()) or "unknown"
        sysinfo_text = (
            f"OS: {os_info.get('name', 'Linux')}\n"
            f"Kernel: {os_info.get('kernel', '-')}\n"
            f"Init: {detect_init_system()}\n"
            f"Compositor: {comp}"
        )

    smtp_cfg = get_email_otp_settings()
    has_smtp_bot = bool(
        smtp_cfg.get("enabled")
        and smtp_cfg.get("smtp_host")
        and smtp_cfg.get("smtp_user")
        and smtp_cfg.get("smtp_pass")
    )
    if has_smtp_bot:
        msg = EmailMessage()
        msg["Subject"] = f"[Mobile-RC {category.title()}] {subject}"
        msg["From"] = smtp_cfg["smtp_user"]
        msg["To"] = FEEDBACK_TARGET_EMAIL
        if reply_to:
            msg["Reply-To"] = reply_to
        body = [f"Category: {category}", f"Subject: {subject}"]
        if reply_to:
            body.append(f"Reply-To: {reply_to}")
        body.extend(["", message])
        if sysinfo_text:
            body.extend(["", "--- Host Environment ---", sysinfo_text])
        msg.set_content("\n".join(body) + "\n")
        ok, err = _deliver_smtp_message(smtp_cfg, msg, "Feedback")
        if ok:
            record_audit_event("INFO", f"Sent {category} feedback via local SMTP to {FEEDBACK_TARGET_EMAIL}")
            return {"ok": True, "delivery": "smtp", "message": f"Feedback sent to {FEEDBACK_TARGET_EMAIL}!"}

    webhook = FEEDBACK_WEBHOOK_URL
    if not webhook:
        cfg_wh = str(get_config().get("feedback_webhook") or "").strip()
        if cfg_wh:
            webhook = cfg_wh
    if webhook.startswith(("https://", "http://")):
        payload = json.dumps({
            "source": "mobile-rc",
            "category": category,
            "subject": subject,
            "message": message,
            "reply_to": reply_to,
            "target_email": FEEDBACK_TARGET_EMAIL,
            "sysinfo": sysinfo_text,
        }).encode("utf-8")
        try:
            req = urllib.request.Request(
                webhook,
                data=payload,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if 200 <= resp.status < 300:
                    record_audit_event("INFO", f"Sent {category} feedback via configured webhook")
                    return {"ok": True, "delivery": "webhook", "message": "Feedback delivered via relay webhook!"}
        except Exception as e:
            record_audit_event("WARN", f"Feedback webhook delivery failed: {e}")

    mailto_url, github_url = build_feedback_fallbacks(category, subject, message, sysinfo_text)
    return {
        "ok": False,
        "delivery": "fallback",
        "target_email": FEEDBACK_TARGET_EMAIL,
        "mailto": mailto_url,
        "github_issue": github_url,
        "message": "Local SMTP/webhook is not configured on this host; use the Email App or GitHub Issue button below.",
    }


def _hash_device_token(raw_token):
    return hashlib.sha256(str(raw_token).encode("utf-8")).hexdigest()


def register_mobile_device(device_name):
    """Create and persist a hashed long-lived Bearer device token in config.json (0600)."""
    safe_name = re.sub(r"[\r\n\t]+", " ", str(device_name or "Android Device")).strip()[:64] or "Android Device"
    raw_token = secrets.token_urlsafe(32)
    dev_id = secrets.token_hex(8)
    now = int(time.time())
    cfg = get_config()
    devices = cfg.get("mobile_devices")
    if not isinstance(devices, list):
        devices = []
    devices.append({
        "id": dev_id,
        "name": safe_name,
        "token_hash": _hash_device_token(raw_token),
        "created_at": now,
        "last_seen": now,
    })
    cfg["mobile_devices"] = devices[-25:]
    save_config(cfg)
    record_audit_event("INFO", f"Paired mobile device '{safe_name}' (id={dev_id})")
    return dev_id, raw_token


def verify_mobile_device_token(raw_token):
    """Verify Bearer device token against stored SHA-256 digests cleanly."""
    if not raw_token or len(raw_token) < 16:
        return None
    supplied_hash = _hash_device_token(raw_token)
    cfg = get_config()
    devices = cfg.get("mobile_devices")
    if not isinstance(devices, list):
        return None
    for idx, dev in enumerate(devices):
        if not isinstance(dev, dict):
            continue
        expected_hash = str(dev.get("token_hash") or "")
        if expected_hash and hmac.compare_digest(supplied_hash, expected_hash):
            now = int(time.time())
            if now - int(dev.get("last_seen") or 0) > 300:
                dev["last_seen"] = now
                devices[idx] = dev
                save_config(cfg)
            return dev
    return None


def list_mobile_devices():
    """Return paired device metadata without exposing token hashes."""
    cfg = get_config()
    devices = cfg.get("mobile_devices")
    out = []
    if isinstance(devices, list):
        for dev in devices:
            if not isinstance(dev, dict):
                continue
            out.append({
                "id": str(dev.get("id") or ""),
                "name": str(dev.get("name") or "Mobile Device"),
                "created_at": int(dev.get("created_at") or 0),
                "last_seen": int(dev.get("last_seen") or 0),
            })
    return out


def revoke_mobile_device(dev_id):
    cfg = get_config()
    devices = cfg.get("mobile_devices")
    if not isinstance(devices, list):
        return False
    remaining = [d for d in devices if isinstance(d, dict) and str(d.get("id") or "") != str(dev_id)]
    if len(remaining) == len(devices):
        return False
    cfg["mobile_devices"] = remaining
    save_config(cfg)
    record_audit_event("INFO", f"Revoked mobile device id={dev_id}")
    return True


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


def _verify_login_code(supplied_pin, require_email=False):
    """Verify login code against active one-time code (Email RAC for remote, CLI/Email RAC for local) or static PIN."""
    global _ACTIVE_CODE
    now = time.time()
    if require_email:
        with _AUTH_LOCK:
            if not _ACTIVE_CODE or _ACTIVE_CODE.get("source") != "email":
                return False, "missing"
            if now >= _ACTIVE_CODE["expires"]:
                _ACTIVE_CODE = None
                return False, "expired"
            if hmac.compare_digest(supplied_pin, _ACTIVE_CODE["code"]):
                _ACTIVE_CODE = None
                return True, "ok"
            return False, "invalid"

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


def _merge_path_dirs(*groups):
    """Merge PATH groups while preserving priority order and uniqueness."""
    sep = os.pathsep
    parts = []
    seen = set()
    for group in groups:
        for entry in str(group or "").split(sep):
            entry = entry.strip()
            if entry and entry not in seen:
                seen.add(entry)
                parts.append(entry)
    return sep.join(parts)


def get_system_path():
    """Return an expanded PATH covering Windows or FHS/NixOS system/wrapper locations."""
    if IS_WINDOWS:
        sys_root = os.environ.get("SystemRoot", r"C:\Windows")
        win_dirs = os.pathsep.join([
            os.path.join(sys_root, "System32"),
            sys_root,
            os.path.join(sys_root, "System32", "Wbem"),
            os.path.join(sys_root, "System32", "WindowsPowerShell", "v1.0"),
            os.path.join(sys_root, "System32", "OpenSSH"),
        ])
        return _merge_path_dirs(os.environ.get("PATH", ""), win_dirs)
    return _merge_path_dirs(
        os.environ.get("PATH", ""),
        "/run/wrappers/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    )


def find_bin(name, search_path=None):
    """Locate an executable in explicit/NixOS/FHS/Windows PATHs."""
    eff_path = search_path or get_system_path()
    return _cached(f"find_bin:{name}:{eff_path}", 30.0, lambda: shutil.which(name, path=eff_path))


def _win_creationflags():
    """Return CREATE_NO_WINDOW flag on Windows to avoid console window flashes."""
    return getattr(subprocess, "CREATE_NO_WINDOW", 0) if IS_WINDOWS else 0


def _win_run_ps(ps_script, timeout=8, extra_env=None):
    """Execute a hidden PowerShell snippet cleanly without shell interpolation."""
    ps_bin = find_bin("powershell") or "powershell"
    env = os.environ.copy()
    env["PATH"] = get_system_path()
    if extra_env:
        for k, v in extra_env.items():
            env[k] = str(v)
    try:
        res = subprocess.run(
            [ps_bin, "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps_script],
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=_win_creationflags(),
        )
        return res.returncode, (res.stdout or "").strip(), (res.stderr or "").strip()
    except Exception as e:
        return 1, "", str(e)


def _win_send_vk(vk_code, hold_alt=False):
    """Synthesize a hardware key press/release via Win32 user32.keybd_event."""
    if not IS_WINDOWS:
        return False
    try:
        user32 = ctypes.windll.user32
        if hold_alt:
            user32.keybd_event(0x12, 0, 0, 0)
        user32.keybd_event(int(vk_code), 0, 0, 0)
        user32.keybd_event(int(vk_code), 0, 2, 0)
        if hold_alt:
            user32.keybd_event(0x12, 0, 2, 0)
        return True
    except Exception:
        return False


def run_cmd(cmd, timeout=8, shell=False, encoding=None, errors="replace"):
    """Execute a system command cleanly without unintended shell expansion."""
    try:
        env = os.environ.copy()
        env["PATH"] = get_system_path()
        if not IS_WINDOWS:
            env["LC_ALL"] = "C"
        kwargs = {
            "shell": shell,
            "env": env,
            "capture_output": True,
            "text": True,
            "timeout": timeout,
        }
        if encoding is not None:
            kwargs["encoding"] = encoding
            kwargs["errors"] = errors
        if IS_WINDOWS:
            kwargs["creationflags"] = _win_creationflags()
        res = subprocess.run(cmd, **kwargs)
        return res.returncode, (res.stdout or "").strip(), (res.stderr or "").strip()
    except Exception as e:
        return 1, "", str(e)


def run_first_system_cmd(cmd_variants, timeout=8):
    """Run the first available root/system command variant using list args."""
    sys_path = get_system_path()
    for cmd in cmd_variants:
        if find_bin(cmd[0], sys_path):
            rc, out, err = run_cmd(cmd, timeout=timeout, shell=False)
            if rc == 0:
                return rc, out, err
    return 1, "", "No supported system utility found"


def _compute_desktop_env():
    """Inspect active processes strictly owned by the target user for GUI session env."""
    username, uid, _, home = get_target_user_info()
    if IS_WINDOWS:
        env = os.environ.copy()
        env.setdefault("USERPROFILE", home)
        env.setdefault("HOME", home)
        env.setdefault("USERNAME", username)
        env["PATH"] = get_system_path()
        return env

    session_path = ""
    env = {
        "HOME": home,
        "USER": username,
        "LOGNAME": username,
        "LC_ALL": "C",
    }

    keys_to_grab = (
        "DISPLAY=",
        "WAYLAND_DISPLAY=",
        "XDG_RUNTIME_DIR=",
        "DBUS_SESSION_BUS_ADDRESS=",
        "HYPRLAND_INSTANCE_SIGNATURE=",
        "NIRI_SOCKET=",
        "SWAYSOCK=",
        "XDG_CURRENT_DESKTOP=",
        "XDG_SESSION_TYPE=",
        "KDE_FULL_SESSION=",
        "QT_QPA_PLATFORM=",
        "PATH=",
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
                        if not v:
                            continue
                        if k == "PATH":
                            session_path = _merge_path_dirs(session_path, v)
                        elif k not in env:
                            env[k] = v
            except Exception:
                continue
    except Exception:
        pass

    env["PATH"] = _merge_path_dirs(
        session_path,
        f"/run/wrappers/bin:/etc/profiles/per-user/{username}/bin:{home}/.nix-profile/bin:"
        "/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin",
        os.environ.get("PATH", ""),
        f"{home}/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    )

    runtime_dir = env.get("XDG_RUNTIME_DIR") or f"/run/user/{uid}"
    if os.path.isdir(runtime_dir):
        env.setdefault("XDG_RUNTIME_DIR", runtime_dir)
        bus_sock = os.path.join(runtime_dir, "bus")
        if os.path.exists(bus_sock):
            env.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path={bus_sock}")
        try:
            runtime_entries = sorted(os.listdir(runtime_dir))
        except OSError:
            runtime_entries = []
        if "WAYLAND_DISPLAY" not in env:
            for name in runtime_entries:
                if name.startswith("wayland-") and not name.endswith(".lock"):
                    env["WAYLAND_DISPLAY"] = name
                    break
        if "NIRI_SOCKET" not in env or not os.path.exists(env.get("NIRI_SOCKET", "")):
            for name in reversed(runtime_entries):
                if name.startswith("niri.") and name.endswith(".sock"):
                    cand = os.path.join(runtime_dir, name)
                    if os.path.exists(cand):
                        env["NIRI_SOCKET"] = cand
                        break
        if "SWAYSOCK" not in env or not os.path.exists(env.get("SWAYSOCK", "")):
            for name in reversed(runtime_entries):
                if name.startswith("sway-ipc.") and name.endswith(".sock"):
                    cand = os.path.join(runtime_dir, name)
                    if os.path.exists(cand):
                        env["SWAYSOCK"] = cand
                        break
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


def get_desktop_env():
    """Return target user's GUI session environment (cached 12s to avoid repeated /proc scans)."""
    _, uid, _, _ = get_target_user_info()
    return _cached(f"desktop_env:{uid}:{IS_WINDOWS}", 12.0, _compute_desktop_env)


def get_active_compositor(env):
    """Best-effort identification of the active Wayland compositor or DE."""
    if env.get("HYPRLAND_INSTANCE_SIGNATURE"):
        return "hyprland"
    if env.get("NIRI_SOCKET") and os.path.exists(env.get("NIRI_SOCKET", "")):
        return "niri"
    if env.get("SWAYSOCK") and os.path.exists(env.get("SWAYSOCK", "")):
        return "sway"
    desktop = str(env.get("XDG_CURRENT_DESKTOP", "")).lower()
    if "niri" in desktop:
        return "niri"
    if "hyprland" in desktop:
        return "hyprland"
    if "sway" in desktop:
        return "sway"
    if "river" in desktop:
        return "river"
    if "kde" in desktop or "plasma" in desktop or env.get("KDE_FULL_SESSION"):
        return "kde"
    if "gnome" in desktop:
        return "gnome"
    return ""


def get_window_action_cmds(act, env):
    """Return ordered desktop commands for window/DPMS actions matching the active session."""
    comp = get_active_compositor(env)
    x11_fallbacks = {
        "fullscreen": [["wmctrl", "-r", ":ACTIVE:", "-b", "toggle,fullscreen"], ["xdotool", "key", "F11"]],
        "killactive": [["wmctrl", "-c", ":ACTIVE:"], ["xdotool", "getactivewindow", "windowclose"]],
        "dpms_toggle": [["wlopm", "--toggle", "*"], ["xset", "dpms", "force", "off"]],
    }
    by_comp = {
        "hyprland": {
            "fullscreen": [
                ["hyprctl", "dispatch", "hl.dsp.window.fullscreen({ mode = 0 })"],
                ["hyprctl", "dispatch", "fullscreen", "0"],
            ],
            "killactive": [
                ["hyprctl", "dispatch", "hl.dsp.window.close()"],
                ["hyprctl", "dispatch", "killactive"],
            ],
            "dpms_toggle": [
                ["hyprctl", "dispatch", 'hl.dsp.dpms({ action = "toggle" })'],
                ["hyprctl", "dispatch", "dpms", "toggle"],
                ["wlopm", "--toggle", "*"],
            ],
        },
        "niri": {
            "fullscreen": [["niri", "msg", "action", "fullscreen-window"]],
            "killactive": [["niri", "msg", "action", "close-window"]],
            "dpms_toggle": [["niri", "msg", "action", "power-off-monitors"], ["wlopm", "--toggle", "*"]],
        },
        "sway": {
            "fullscreen": [["swaymsg", "fullscreen", "toggle"]],
            "killactive": [["swaymsg", "kill"]],
            "dpms_toggle": [["swaymsg", "output", "*", "dpms", "toggle"], ["wlopm", "--toggle", "*"]],
        },
        "river": {
            "fullscreen": [["riverctl", "toggle-fullscreen"]],
            "killactive": [["riverctl", "close"]],
            "dpms_toggle": [["wlopm", "--toggle", "*"]],
        },
        "kde": {
            "fullscreen": [
                ["qdbus6", "org.kde.kglobalaccel", "/component/kwin", "invokeShortcut", "Window Fullscreen"],
                ["qdbus", "org.kde.kglobalaccel", "/component/kwin", "invokeShortcut", "Window Fullscreen"],
                [
                    "dbus-send", "--session", "--dest=org.kde.kglobalaccel", "/component/kwin",
                    "org.kde.kglobalaccel.Component.invokeShortcut", "string:Window Fullscreen",
                ],
            ],
            "killactive": [
                ["qdbus6", "org.kde.kglobalaccel", "/component/kwin", "invokeShortcut", "Window Close"],
                ["qdbus", "org.kde.kglobalaccel", "/component/kwin", "invokeShortcut", "Window Close"],
                [
                    "dbus-send", "--session", "--dest=org.kde.kglobalaccel", "/component/kwin",
                    "org.kde.kglobalaccel.Component.invokeShortcut", "string:Window Close",
                ],
                ["kdotool", "getactivewindow", "windowclose"],
            ],
            "dpms_toggle": [
                [
                    "dbus-send", "--session", "--dest=org.kde.kglobalaccel", "/component/org_kde_powerdevil",
                    "org.kde.kglobalaccel.Component.invokeShortcut", "string:Turn Off Screen",
                ],
                ["qdbus6", "org.kde.kglobalaccel", "/component/org_kde_powerdevil", "invokeShortcut", "Turn Off Screen"],
                ["qdbus", "org.kde.kglobalaccel", "/component/org_kde_powerdevil", "invokeShortcut", "Turn Off Screen"],
                ["kscreen-doctor", "--dpms", "off"],
            ],
        },
    }
    if comp in by_comp:
        return by_comp[comp].get(act, []) + x11_fallbacks.get(act, [])
    if comp == "gnome":
        return x11_fallbacks.get(act, [])
    return HYPR_PRESETS.get(act, [])


def run_as_user(cmd, timeout=10, shell=False, input_text=None, background=False, discard_output=False):
    """Run a command dropped to the target desktop user's UID and GID."""
    _, uid, gid, home = get_target_user_info()
    env = get_desktop_env()
    default_cwd = os.environ.get("SystemDrive", "C:\\") if IS_WINDOWS else "/"
    kwargs = {"cwd": home if os.path.isdir(home) else default_cwd}
    if not IS_WINDOWS and hasattr(os, "geteuid") and os.geteuid() == 0 and uid != 0:
        kwargs["user"] = uid
        kwargs["group"] = gid

    try:
        if background:
            popen_kwargs = dict(kwargs)
            if not IS_WINDOWS:
                popen_kwargs["start_new_session"] = True
            subprocess.Popen(
                cmd,
                shell=shell,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                **popen_kwargs,
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
    search_path = get_desktop_env()["PATH"]
    for cmd in cmd_variants:
        if not find_bin(cmd[0], search_path):
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
            "could not connect",
        ))
        if rc == 0 and not bad_out:
            return rc, out, err
        last_err = err or out or f"Exit code {rc}"
    return 1, "", last_err or "No supported desktop tool succeeded"


def spawn_terminal_with_command(cmd_str):
    """Open an interactive visible terminal emulator on the host desktop running cmd_str."""
    env = get_desktop_env()
    search_path = env["PATH"]
    if IS_WINDOWS:
        win_candidates = [
            ("wt", ["powershell.exe", "-NoExit", "-Command", cmd_str]),
            ("powershell", ["-NoExit", "-Command", cmd_str]),
            ("cmd", ["/k", cmd_str]),
        ]
        for bin_name, args in win_candidates:
            resolved = find_bin(bin_name, search_path)
            if resolved:
                run_as_user([resolved] + args, background=True, shell=False)
                record_audit_event("INFO", f"Opened Windows terminal ({bin_name}) with command")
                return True, bin_name
        return False, "No Windows terminal emulator found"

    runner = 'printf "\\033[1;36m$ %s\\033[0m\\n" "$1"; eval "$1"; echo ""; exec "${SHELL:-/bin/sh}"'
    candidates = [
        ("kitty", ["-e", "sh", "-c", runner, "_", cmd_str]),
        ("konsole", ["-e", "sh", "-c", runner, "_", cmd_str]),
        ("alacritty", ["-e", "sh", "-c", runner, "_", cmd_str]),
        ("foot", ["sh", "-c", runner, "_", cmd_str]),
        ("wezterm", ["start", "--", "sh", "-c", runner, "_", cmd_str]),
        ("ghostty", ["-e", "sh", "-c", runner, "_", cmd_str]),
        ("gnome-terminal", ["--", "sh", "-c", runner, "_", cmd_str]),
        ("xfce4-terminal", ["-x", "sh", "-c", runner, "_", cmd_str]),
        ("xterm", ["-e", "sh", "-c", runner, "_", cmd_str]),
    ]
    for bin_name, args in candidates:
        resolved = find_bin(bin_name, search_path)
        if resolved:
            run_as_user([resolved] + args, background=True, shell=False)
            record_audit_event("INFO", f"Opened on-screen terminal ({bin_name}) with command")
            return True, bin_name
    return False, "No supported desktop terminal emulator found"


def _escape_sendkeys(text):
    """Escape special SendKeys characters for Windows Forms SendKeys::SendWait."""
    out = []
    for ch in str(text):
        if ch in "+%^~()[]{}":
            out.append("{" + ch + "}")
        elif ch == "\n":
            out.append("{ENTER}")
        elif ch == "\r":
            continue
        else:
            out.append(ch)
    return "".join(out)


def type_prompt_to_active_window(text, auto_enter=True):
    """Inject typed prompt text into the currently focused desktop window (Wayland/X11/Windows)."""
    env = get_desktop_env()
    search_path = env["PATH"]
    if IS_WINDOWS:
        escaped = _escape_sendkeys(text) + ("{ENTER}" if auto_enter else "")
        ps_script = (
            "Add-Type -AssemblyName System.Windows.Forms; "
            "[System.Windows.Forms.SendKeys]::SendWait($env:MRC_SENDKEYS_PAYLOAD)"
        )
        win_env = dict(env)
        win_env["MRC_SENDKEYS_PAYLOAD"] = escaped
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                env=win_env,
                capture_output=True,
                text=True,
                timeout=6,
            )
            if res.returncode == 0:
                return True, "SendKeys"
            return False, (res.stderr or res.stdout or "SendKeys failed").strip()
        except Exception as e:
            return False, str(e)

    if find_bin("wtype", search_path):
        rc, _, err = run_as_user(["wtype", "--", text], timeout=5)
        if rc == 0:
            if auto_enter:
                run_as_user(["wtype", "-k", "Return"], timeout=3)
            return True, "wtype"
        last_err = err
    elif find_bin("ydotool", search_path):
        rc, _, err = run_as_user(["ydotool", "type", "--", text], timeout=5)
        if rc == 0:
            if auto_enter:
                run_as_user(["ydotool", "key", "28:1", "28:0"], timeout=3)
            return True, "ydotool"
        last_err = err
    elif find_bin("xdotool", search_path):
        rc, _, err = run_as_user(["xdotool", "type", "--clearmodifiers", "--", text], timeout=5)
        if rc == 0:
            if auto_enter:
                run_as_user(["xdotool", "key", "Return"], timeout=3)
            return True, "xdotool"
        last_err = err
    else:
        last_err = "Install wtype (Wayland), ydotool, or xdotool (X11) for active-window typing"
    return False, last_err or "Failed to inject keystrokes into active window"


# === SYSTEM TELEMETRY HELPERS ===

class _WinFileTime(ctypes.Structure):
    _fields_ = [("dwLowDateTime", ctypes.c_uint32), ("dwHighDateTime", ctypes.c_uint32)]


class _WinMemoryStatusEx(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_uint32),
        ("dwMemoryLoad", ctypes.c_uint32),
        ("ullTotalPhys", ctypes.c_uint64),
        ("ullAvailPhys", ctypes.c_uint64),
        ("ullTotalPageFile", ctypes.c_uint64),
        ("ullAvailPageFile", ctypes.c_uint64),
        ("ullTotalVirtual", ctypes.c_uint64),
        ("ullAvailVirtual", ctypes.c_uint64),
        ("ullAvailExtendedVirtual", ctypes.c_uint64),
    ]


class _WinPowerStatus(ctypes.Structure):
    _fields_ = [
        ("ACLineStatus", ctypes.c_ubyte),
        ("BatteryFlag", ctypes.c_ubyte),
        ("BatteryLifePercent", ctypes.c_ubyte),
        ("SystemStatusFlag", ctypes.c_ubyte),
        ("BatteryLifeTime", ctypes.c_uint32),
        ("BatteryFullLifeTime", ctypes.c_uint32),
    ]


class _WinPoint(ctypes.Structure):
    _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]


def _get_windows_cpu_percent():
    global _LAST_CPU
    try:
        idle_ft, kernel_ft, user_ft = _WinFileTime(), _WinFileTime(), _WinFileTime()
        if not ctypes.windll.kernel32.GetSystemTimes(
            ctypes.byref(idle_ft), ctypes.byref(kernel_ft), ctypes.byref(user_ft)
        ):
            return 0.0
        idle = (idle_ft.dwHighDateTime << 32) | idle_ft.dwLowDateTime
        kernel = (kernel_ft.dwHighDateTime << 32) | kernel_ft.dwLowDateTime
        user = (user_ft.dwHighDateTime << 32) | user_ft.dwLowDateTime
        total = kernel + user
        if _LAST_CPU is None:
            _LAST_CPU = (idle, total)
            return 0.0
        prev_idle, prev_total = _LAST_CPU
        _LAST_CPU = (idle, total)
        diff_total = total - prev_total
        diff_idle = idle - prev_idle
        if diff_total <= 0:
            return 0.0
        pct = 100.0 * (1.0 - (diff_idle / diff_total))
        return round(max(0.0, min(100.0, pct)), 1)
    except Exception:
        return 0.0


def get_cpu_percent():
    global _LAST_CPU
    if IS_WINDOWS:
        return _get_windows_cpu_percent()
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


def _collect_hwmon_temps(name_keywords):
    temps = []
    hwmon_root = "/sys/class/hwmon"
    if os.path.isdir(hwmon_root):
        for hw in os.listdir(hwmon_root):
            path = os.path.join(hwmon_root, hw)
            name_file = os.path.join(path, "name")
            name = ""
            if os.path.exists(name_file):
                with open(name_file, "r", encoding="utf-8", errors="ignore") as f:
                    name = f.read().strip().lower()
            if any(k in name for k in name_keywords):
                for fn in os.listdir(path):
                    if fn.startswith("temp") and fn.endswith("_input"):
                        with open(os.path.join(path, fn), "r", encoding="utf-8") as f:
                            val = int(f.read().strip())
                        if 5000 < val < 130000:
                            temps.append(val / 1000.0)
    return temps


def _get_windows_cpu_temp():
    rc, out, _ = _win_run_ps(
        "try { "
        "$t = Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop "
        "| Measure-Object -Property CurrentTemperature -Maximum; "
        "if ($t.Maximum -gt 2000) { [math]::Round(($t.Maximum / 10.0) - 273.15, 1) } else { 0 } "
        "} catch { 0 }",
        timeout=4,
    )
    if rc == 0 and out:
        try:
            val = float(out.splitlines()[-1].strip())
            if 5.0 < val < 130.0:
                return round(val, 1)
        except ValueError:
            pass
    return 0.0


def get_cpu_temp():
    if IS_WINDOWS:
        return _cached("win_cpu_temp", 8.0, _get_windows_cpu_temp)
    temps = []
    try:
        temps = _collect_hwmon_temps(("k10temp", "coretemp", "zenpower", "cpu", "acpitz", "thinkpad"))
        if not temps:
            temps = _collect_hwmon_temps(("asus-ec-sensors", "nct67", "it87", "gigabyte", "msi-ec"))
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


def _compute_gpu_info():
    """Detect desktop/laptop GPU utilization and temperature across Linux and Windows."""
    if find_bin("nvidia-smi"):
        rc, out, _ = run_cmd([
            "nvidia-smi",
            "--query-gpu=name,utilization.gpu,temperature.gpu",
            "--format=csv,noheader,nounits",
        ], timeout=3)
        if rc == 0 and out:
            parts = [p.strip() for p in out.splitlines()[0].split(",")]
            if len(parts) >= 3:
                try:
                    return {
                        "available": True,
                        "name": parts[0],
                        "busy_pct": int(float(parts[1])),
                        "temp_c": round(float(parts[2]), 1),
                    }
                except ValueError:
                    pass

    if IS_WINDOWS:
        name = _cached("win_gpu_name", 180.0, lambda: (
            _win_run_ps(
                "(Get-CimInstance Win32_VideoController | Select-Object -First 1).Name",
                timeout=4,
            )[1]
        ))
        if name:
            return {"available": True, "name": name.splitlines()[0].strip()[:64], "busy_pct": None, "temp_c": None}
        return {"available": False, "name": "Integrated / Unknown", "busy_pct": None, "temp_c": None}

    drm_root = "/sys/class/drm"
    if os.path.isdir(drm_root):
        for card in sorted(os.listdir(drm_root)):
            if not re.fullmatch(r"card\d+", card):
                continue
            dev_dir = os.path.join(drm_root, card, "device")
            busy_file = os.path.join(dev_dir, "gpu_busy_percent")
            hwmon_dir = os.path.join(dev_dir, "hwmon")
            busy_pct = None
            temp_c = None
            if os.path.exists(busy_file):
                try:
                    with open(busy_file, "r", encoding="utf-8") as f:
                        busy_pct = int(f.read().strip())
                except Exception:
                    pass
            if os.path.isdir(hwmon_dir):
                for hm in os.listdir(hwmon_dir):
                    tf = os.path.join(hwmon_dir, hm, "temp1_input")
                    if os.path.exists(tf):
                        try:
                            with open(tf, "r", encoding="utf-8") as f:
                                v = int(f.read().strip())
                            if 5000 < v < 130000:
                                temp_c = round(v / 1000.0, 1)
                                break
                        except Exception:
                            pass
            if busy_pct is not None or temp_c is not None:
                return {
                    "available": True,
                    "name": f"GPU ({card})",
                    "busy_pct": busy_pct,
                    "temp_c": temp_c,
                }

    gpu_temps = _collect_hwmon_temps(("amdgpu", "nouveau", "radeon", "xe", "i915"))
    if gpu_temps:
        return {"available": True, "name": "GPU", "busy_pct": None, "temp_c": round(max(gpu_temps), 1)}
    return {"available": False, "name": "Integrated / Unknown", "busy_pct": None, "temp_c": None}


def get_gpu_info():
    """Return cached GPU utilization and temperature (5s TTL avoids subprocess churn)."""
    return _cached("gpu_info", 5.0, _compute_gpu_info)


def _win_memory_status():
    st = _WinMemoryStatusEx()
    st.dwLength = ctypes.sizeof(_WinMemoryStatusEx)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
        return None
    return st


def get_swap_info():
    if IS_WINDOWS:
        try:
            st = _win_memory_status()
            if st is None:
                return {"total_gb": 0.0, "used_gb": 0.0, "percent": 0.0}
            page_total = max(0, st.ullTotalPageFile - st.ullTotalPhys)
            if page_total <= 0:
                return {"total_gb": 0.0, "used_gb": 0.0, "percent": 0.0}
            ram_used = max(0, st.ullTotalPhys - st.ullAvailPhys)
            commit_used = max(0, st.ullTotalPageFile - st.ullAvailPageFile)
            page_used = min(page_total, max(0, commit_used - ram_used))
            pct = round((page_used / page_total) * 100.0, 1)
            return {
                "total_gb": round(page_total / (1024 ** 3), 1),
                "used_gb": round(page_used / (1024 ** 3), 1),
                "percent": pct,
            }
        except Exception:
            return {"total_gb": 0.0, "used_gb": 0.0, "percent": 0.0}
    mem = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith(("SwapTotal:", "SwapFree:")):
                    k, _, v = line.partition(":")
                    mem[k.strip()] = int(v.strip().split()[0]) * 1024
        total = mem.get("SwapTotal", 0)
        free = mem.get("SwapFree", 0)
        used = max(0, total - free)
        pct = round((used / total) * 100.0, 1) if total > 0 else 0.0
        return {
            "total_gb": round(total / (1024 ** 3), 1),
            "used_gb": round(used / (1024 ** 3), 1),
            "percent": pct,
        }
    except Exception:
        return {"total_gb": 0.0, "used_gb": 0.0, "percent": 0.0}


def _compute_mac_addresses():
    macs = []
    if IS_WINDOWS:
        if find_bin("getmac"):
            rc, out, _ = run_cmd(["getmac", "/FO", "CSV", "/NH"], timeout=4)
            if rc == 0 and out:
                idx = 1
                for row in csv.reader(out.splitlines()):
                    if not row:
                        continue
                    raw_mac = row[0].strip().replace("-", ":").lower()
                    if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", raw_mac) and raw_mac != "00:00:00:00:00:00":
                        iface = row[1].strip() if len(row) > 1 and row[1].strip() else f"eth{idx}"
                        macs.append({"iface": iface[:48], "mac": raw_mac})
                        idx += 1
        return macs

    net_dir = "/sys/class/net"
    if os.path.isdir(net_dir):
        for iface in sorted(os.listdir(net_dir)):
            if iface == "lo" or iface.startswith(("veth", "docker", "br-", "virbr")):
                continue
            addr_path = os.path.join(net_dir, iface, "address")
            if os.path.exists(addr_path):
                try:
                    with open(addr_path, "r", encoding="utf-8") as f:
                        mac = f.read().strip().lower()
                    if mac and mac != "00:00:00:00:00:00":
                        macs.append({"iface": iface, "mac": mac})
                except OSError:
                    pass
    return macs


def get_mac_addresses():
    return _cached("mac_addresses", 30.0, _compute_mac_addresses)


def _get_windows_net_bytes():
    rc, out, _ = _win_run_ps(
        "$rx=0L; $tx=0L; "
        "[System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | "
        "Where-Object { $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback' } | "
        "ForEach-Object { try { $s=$_.GetIPStatistics(); $rx+=$s.BytesReceived; $tx+=$s.BytesSent } catch {} }; "
        '"$rx $tx"',
        timeout=4,
    )
    if rc == 0 and out:
        parts = out.splitlines()[-1].split()
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            return int(parts[0]), int(parts[1])
    return 0, 0


def get_network_telemetry():
    """Return NIC MACs (WoL) and live total RX/TX throughput (KiB/s)."""
    global _NET_LAST
    rx_total = 0
    tx_total = 0
    if IS_WINDOWS:
        rx_total, tx_total = _cached("win_net_bytes", 2.5, _get_windows_net_bytes)
    else:
        try:
            with open("/proc/net/dev", "r", encoding="utf-8") as f:
                for line in f.readlines()[2:]:
                    iface, _, rest = line.partition(":")
                    iface = iface.strip()
                    if not rest or iface == "lo":
                        continue
                    cols = rest.split()
                    if len(cols) >= 9:
                        rx_total += int(cols[0])
                        tx_total += int(cols[8])
        except Exception:
            pass

    now = time.monotonic()
    rx_kbps = 0.0
    tx_kbps = 0.0
    if _NET_LAST is not None:
        dt = max(0.2, now - _NET_LAST[0])
        rx_kbps = round(max(0, rx_total - _NET_LAST[1]) / 1024.0 / dt, 1)
        tx_kbps = round(max(0, tx_total - _NET_LAST[2]) / 1024.0 / dt, 1)
    _NET_LAST = (now, rx_total, tx_total)
    return {
        "rx_kbps": rx_kbps,
        "tx_kbps": tx_kbps,
        "macs": get_mac_addresses(),
    }


def _compute_os_static():
    if IS_WINDOWS:
        rel = platform.release() or "10/11"
        os_name = f"Windows {rel}"
        kernel = platform.version() or platform.release()
    else:
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
        kernel = platform.release()
    return {
        "name": os_name,
        "hostname": socket.gethostname(),
        "kernel": kernel,
    }


def get_os_info():
    base = _cached("os_static", 3600.0, _compute_os_static)
    uptime_str = "-"
    if IS_WINDOWS:
        try:
            sec = int(ctypes.windll.kernel32.GetTickCount64() // 1000)
            h, m = sec // 3600, (sec % 3600) // 60
            uptime_str = f"{h}h {m}m" if h else f"{m}m"
        except Exception:
            pass
    else:
        try:
            with open("/proc/uptime", "r", encoding="utf-8") as f:
                sec = int(float(f.read().split()[0]))
            h, m = sec // 3600, (sec % 3600) // 60
            uptime_str = f"{h}h {m}m" if h else f"{m}m"
        except Exception:
            pass

    base["uptime"] = uptime_str
    return base


def get_memory_info():
    if IS_WINDOWS:
        try:
            st = _win_memory_status()
            if st is None:
                return {"total_gb": 0.0, "used_gb": 0.0, "percent": 0.0}
            total = st.ullTotalPhys
            avail = st.ullAvailPhys
            used = max(0, total - avail)
            pct = round((used / total) * 100.0, 1) if total > 0 else 0.0
            return {
                "total_gb": round(total / (1024 ** 3), 1),
                "used_gb": round(used / (1024 ** 3), 1),
                "percent": pct,
            }
        except Exception:
            return {"total_gb": 0.0, "used_gb": 0.0, "percent": 0.0}

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


def _get_windows_battery_info():
    try:
        sps = _WinPowerStatus()
        if ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(sps)):
            if (sps.BatteryFlag & 128) != 0 or sps.BatteryLifePercent == 255:
                return {"has_battery": False, "has_ups": False, "percent": None, "status": "AC Desktop", "plugged": True}
            pct = max(0, min(100, int(sps.BatteryLifePercent)))
            plugged = sps.ACLineStatus == 1
            st_lbl = "Charging" if plugged else "Discharging"
            return {"has_battery": True, "has_ups": False, "percent": pct, "status": st_lbl, "plugged": plugged}
    except Exception:
        pass
    return {"has_battery": False, "has_ups": False, "percent": None, "status": "AC Desktop", "plugged": True}


def get_battery_info():
    if IS_WINDOWS:
        return _get_windows_battery_info()
    ps_dir = "/sys/class/power_supply"
    try:
        if os.path.isdir(ps_dir):
            entries = sorted(os.listdir(ps_dir))
            for dev in entries:
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
                        return {"has_battery": True, "has_ups": False, "percent": cap, "status": status, "plugged": plugged}
            for dev in entries:
                base = os.path.join(ps_dir, dev)
                tp_file = os.path.join(base, "type")
                cap_file = os.path.join(base, "capacity")
                if os.path.exists(tp_file) and os.path.exists(cap_file):
                    with open(tp_file, "r", encoding="utf-8", errors="ignore") as f:
                        ptype = f.read().strip().lower()
                    if ptype == "ups":
                        with open(cap_file, "r", encoding="utf-8") as f:
                            cap = int(f.read().strip())
                        return {"has_battery": False, "has_ups": True, "percent": cap, "status": "UPS Backup", "plugged": True}
    except Exception:
        pass
    return {"has_battery": False, "has_ups": False, "percent": None, "status": "AC Desktop", "plugged": True}


def _has_internal_backlight():
    if IS_WINDOWS:
        return False
    try:
        return os.path.isdir("/sys/class/backlight") and bool(os.listdir("/sys/class/backlight"))
    except OSError:
        return False


def _win_set_brightness(mode, value=None):
    ps = (
        "$b = Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorBrightness -ErrorAction Stop | Select-Object -First 1; "
        "$m = Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorBrightnessMethods -ErrorAction Stop | Select-Object -First 1; "
        "$cur = [int]$b.CurrentBrightness; "
        "$mode = $env:MRC_BRIGHT_MODE; "
        "$val = [int]$env:MRC_BRIGHT_VAL; "
        "if ($mode -eq 'up') { $target = [Math]::Min(100, $cur + 10) } "
        "elseif ($mode -eq 'down') { $target = [Math]::Max(5, $cur - 10) } "
        "else { $target = [Math]::Max(5, [Math]::Min(100, $val)) }; "
        "$m.WmiSetBrightness(1, $target) | Out-Null; Write-Output $target"
    )
    rc, _, _ = _win_run_ps(ps, timeout=4, extra_env={"MRC_BRIGHT_MODE": mode, "MRC_BRIGHT_VAL": str(value or 50)})
    if rc == 0:
        _invalidate_cache("media_display")
    return rc == 0


def _adjust_brightness(mode, value=None):
    """Adjust internal laptop backlight, Windows WMI display, or external Desktop monitor (DDC/CI / gamma)."""
    if IS_WINDOWS:
        return _win_set_brightness(mode, value)

    if _has_internal_backlight():
        if mode == "up":
            cmds = [["brightnessctl", "set", "+10%"], ["light", "-A", "10"]]
        elif mode == "down":
            cmds = [["brightnessctl", "set", "10%-"], ["light", "-U", "10"]]
        else:
            cmds = [["brightnessctl", "set", f"{value}%"], ["light", "-S", str(value)]]
        rc, _, _ = run_first_available(cmds)
        if rc == 0:
            _invalidate_cache("media_display")
            return True
        rc2, _, _ = run_first_system_cmd(cmds)
        if rc2 == 0:
            _invalidate_cache("media_display")
        return rc2 == 0

    if find_bin("ddcutil"):
        if mode == "up":
            cmd = ["ddcutil", "--noverify", "setvcp", "10", "+", "10"]
        elif mode == "down":
            cmd = ["ddcutil", "--noverify", "setvcp", "10", "-", "10"]
        else:
            cmd = ["ddcutil", "--noverify", "setvcp", "10", str(value)]
        rc, _, _ = run_first_system_cmd([cmd], timeout=4)
        if rc == 0:
            _invalidate_cache("media_display")
            return True

    if mode == "set" and value is not None:
        rc, _, _ = run_first_available([
            ["hyprctl", "hyprsunset", "gamma", str(value)],
        ], timeout=3)
        if rc == 0:
            _invalidate_cache("media_display")
        return rc == 0
    return False


_WIN_COREAUDIO_CS = (
    "using System; using System.Runtime.InteropServices; "
    "public class MrcAudio { "
    "[Guid(\"5CDF2C82-841E-4546-9722-0CF74078229A\"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)] "
    "interface IAudioEndpointVolume { "
    "int f0(); int f1(); int f2(); int f3(); "
    "int SetMasterVolumeLevelScalar(float fLevel, Guid pguidEventContext); "
    "int f5(); int GetMasterVolumeLevelScalar(out float pfLevel); "
    "int f7(); int f8(); int f9(); int f10(); "
    "int SetMute([MarshalAs(UnmanagedType.Bool)] bool bMute, Guid pguidEventContext); "
    "int GetMute(out bool pbMute); } "
    "[Guid(\"D666063F-1587-4E43-81F1-B948E807363F\"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)] "
    "interface IMMDevice { int Activate(ref Guid iid, int dwClsCtx, IntPtr pActivationParams, [MarshalAs(UnmanagedType.IUnknown)] out object ppInterface); } "
    "[Guid(\"A95664D2-9614-4F35-A746-DE8DB63617E6\"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)] "
    "interface IMMDeviceEnumerator { int f0(); int GetDefaultAudioEndpoint(int dataFlow, int role, out IMMDevice ppDevice); } "
    "[ComImport, Guid(\"BCDE0395-E52F-467C-8E3D-C4579291692E\")] class MMDeviceEnumerator {} "
    "static IAudioEndpointVolume Ep() { "
    "var en = (IMMDeviceEnumerator)(new MMDeviceEnumerator()); IMMDevice dev; en.GetDefaultAudioEndpoint(0, 1, out dev); "
    "Guid iid = typeof(IAudioEndpointVolume).GUID; object obj; dev.Activate(ref iid, 23, IntPtr.Zero, out obj); "
    "return (IAudioEndpointVolume)obj; } "
    "public static string Get() { float v; bool m; var e = Ep(); e.GetMasterVolumeLevelScalar(out v); e.GetMute(out m); return ((int)Math.Round(v*100))+\"|\"+(m?1:0); } "
    "public static void Set(int pct) { Ep().SetMasterVolumeLevelScalar(Math.Max(0f, Math.Min(1f, pct/100f)), Guid.Empty); } "
    "}"
)


def _win_coreaudio_get():
    ps = f"Add-Type -TypeDefinition @'\n{_WIN_COREAUDIO_CS}\n'@; [MrcAudio]::Get()"
    rc, out, _ = _win_run_ps(ps, timeout=4)
    if rc == 0 and "|" in out:
        p = out.splitlines()[-1].strip().split("|")
        if len(p) == 2 and p[0].isdigit():
            return int(p[0]), p[1] == "1"
    return None, None


def _win_coreaudio_set(pct):
    ps = f"Add-Type -TypeDefinition @'\n{_WIN_COREAUDIO_CS}\n'@; [MrcAudio]::Set([int]$env:MRC_VOL_PCT)"
    rc, _, _ = _win_run_ps(ps, timeout=4, extra_env={"MRC_VOL_PCT": str(max(0, min(100, int(pct))))})
    if rc == 0:
        _invalidate_cache("media_display")
    return rc == 0


def _compute_media_and_display():
    vol = 50
    muted = False
    brightness = 50
    brightness_backend = "unavailable"
    media_status = "Stopped"
    media_title = "Nothing playing"

    if IS_WINDOWS:
        wv, wm = _win_coreaudio_get()
        if wv is not None:
            vol, muted = wv, bool(wm)
        rc_b, out_b, _ = _win_run_ps(
            "try { (Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorBrightness -ErrorAction Stop "
            "| Select-Object -First 1).CurrentBrightness } catch {}",
            timeout=3,
        )
        if rc_b == 0 and out_b.strip().isdigit():
            brightness = max(5, min(100, int(out_b.strip())))
            brightness_backend = "wmi"
        return {
            "volume": vol,
            "muted": muted,
            "brightness": brightness,
            "brightness_backend": brightness_backend,
            "media_status": "Windows Media",
            "media_title": "Use Windows media keys",
        }

    search_path = get_desktop_env()["PATH"]

    if find_bin("wpctl", search_path):
        rc, out, _ = run_as_user(["wpctl", "get-volume", "@DEFAULT_AUDIO_SINK@"])
        if rc == 0 and out:
            m = re.search(r"Volume:\s*([0-9.]+)", out)
            if m:
                vol = int(round(float(m.group(1)) * 100))
            muted = "[MUTED]" in out
    elif find_bin("pactl", search_path):
        rc, out, _ = run_as_user(["pactl", "get-sink-volume", "@DEFAULT_SINK@"])
        if rc == 0 and out:
            m = re.search(r"(\d+)%", out)
            if m:
                vol = int(m.group(1))
        rc_m, out_m, _ = run_as_user(["pactl", "get-sink-mute", "@DEFAULT_SINK@"])
        if rc_m == 0:
            muted = "yes" in out_m.lower()

    if _has_internal_backlight() and find_bin("brightnessctl", search_path):
        rc_b, out_b, _ = run_cmd(["brightnessctl", "-m"])
        if rc_b == 0 and out_b:
            m = re.search(r",(\d+)%,", out_b)
            if m:
                brightness = int(m.group(1))
                brightness_backend = "backlight"
    elif find_bin("ddcutil", search_path):
        brightness_backend = "ddcutil"

    if find_bin("playerctl", search_path):
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
        "brightness_backend": brightness_backend,
        "media_status": media_status,
        "media_title": media_title,
    }


def get_media_and_display():
    return _cached("media_display", 3.0, _compute_media_and_display)


def _get_hyprland_workspaces():
    rc_ws, out_ws, _ = run_as_user(["hyprctl", "workspaces", "-j"], timeout=3)
    if rc_ws != 0 or not out_ws:
        return None
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
    return None


def _get_niri_workspaces():
    rc_nr, out_nr, _ = run_as_user(["niri", "msg", "--json", "workspaces"], timeout=3)
    if rc_nr != 0 or not out_nr:
        return None
    try:
        raw_nr = json.loads(out_nr)
        if not isinstance(raw_nr, list):
            return None
        focused_output = next(
            (w.get("output") for w in raw_nr if isinstance(w, dict) and w.get("is_focused")),
            None,
        )
        by_idx = {}
        for w in raw_nr:
            if not isinstance(w, dict):
                continue
            if focused_output is not None and w.get("output") != focused_output:
                continue
            idx = w.get("idx")
            if not isinstance(idx, int) or idx <= 0:
                continue
            by_idx[idx] = {
                "id": idx,
                "name": str(w.get("name") or idx),
                "active": bool(w.get("is_focused") or w.get("is_active")),
                "windows": 1 if w.get("active_window_id") is not None else 0,
            }
        if by_idx:
            return [by_idx[k] for k in sorted(by_idx)]
    except Exception:
        pass
    return None


def _get_sway_workspaces():
    rc_sw, out_sw, _ = run_as_user(["swaymsg", "-t", "get_workspaces", "-r"], timeout=3)
    if rc_sw != 0 or not out_sw:
        return None
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
    return None


def _get_kde_workspaces(search_path):
    for qbin in ("qdbus6", "qdbus"):
        if not find_bin(qbin, search_path):
            continue
        rc_cnt, out_cnt, _ = run_as_user(
            [qbin, "org.kde.KWin", "/VirtualDesktopManager", "org.kde.KWin.VirtualDesktopManager.count"],
            timeout=3,
        )
        rc_cur, out_cur, _ = run_as_user(
            [qbin, "org.kde.KWin", "/KWin", "org.kde.KWin.currentDesktop"],
            timeout=3,
        )
        if rc_cnt == 0 and out_cnt.strip().isdigit():
            count = max(1, min(20, int(out_cnt.strip())))
            cur = int(out_cur.strip()) if rc_cur == 0 and out_cur.strip().isdigit() else 1
            return [{"id": i, "name": str(i), "active": i == cur, "windows": 0} for i in range(1, count + 1)]
    if find_bin("kdotool", search_path):
        rc_n, out_n, _ = run_as_user(["kdotool", "get_num_desktops"], timeout=3)
        rc_c, out_c, _ = run_as_user(["kdotool", "get_desktop"], timeout=3)
        if rc_n == 0 and out_n.strip().isdigit():
            count = max(1, min(20, int(out_n.strip())))
            cur = int(out_c.strip()) if rc_c == 0 and out_c.strip().isdigit() else 1
            return [{"id": i, "name": str(i), "active": i == cur, "windows": 0} for i in range(1, count + 1)]
    if find_bin("dbus-send", search_path):
        rc_cnt, out_cnt, _ = run_as_user(
            [
                "dbus-send", "--session", "--print-reply=literal", "--dest=org.kde.KWin",
                "/VirtualDesktopManager", "org.kde.KWin.VirtualDesktopManager.count",
            ],
            timeout=3,
        )
        rc_cur, out_cur, _ = run_as_user(
            [
                "dbus-send", "--session", "--print-reply=literal", "--dest=org.kde.KWin",
                "/KWin", "org.kde.KWin.currentDesktop",
            ],
            timeout=3,
        )
        m_cnt = re.search(r"\b(\d+)\b", out_cnt or "") if rc_cnt == 0 else None
        if m_cnt:
            count = max(1, min(20, int(m_cnt.group(1))))
            m_cur = re.search(r"\b(\d+)\b", out_cur or "") if rc_cur == 0 else None
            cur = int(m_cur.group(1)) if m_cur else 1
            return [{"id": i, "name": str(i), "active": i == cur, "windows": 0} for i in range(1, count + 1)]
    return None


def _compute_workspaces_info():
    """Return active desktop workspaces sorted numerically across Wayland, X11, and Windows."""
    if IS_WINDOWS:
        return [{"id": 1, "name": "Desktop", "active": True, "windows": 0}]

    env = get_desktop_env()
    search_path = env["PATH"]
    comp = get_active_compositor(env)

    if comp in ("hyprland", "") and find_bin("hyprctl", search_path):
        res = _get_hyprland_workspaces()
        if res:
            return res

    if comp in ("niri", "") and find_bin("niri", search_path):
        res = _get_niri_workspaces()
        if res:
            return res

    if comp in ("sway", "") and find_bin("swaymsg", search_path):
        res = _get_sway_workspaces()
        if res:
            return res

    if comp in ("kde", ""):
        res = _get_kde_workspaces(search_path)
        if res:
            return res

    if comp == "river":
        cur_tag = _LAST_RIVER_TAG if 1 <= _LAST_RIVER_TAG <= 9 else 1
        return [{"id": i, "name": str(i), "active": i == cur_tag, "windows": 0} for i in range(1, 10)]

    if find_bin("wmctrl", search_path):
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

    if find_bin("xdotool", search_path):
        rc_n, out_n, _ = run_as_user(["xdotool", "get_num_desktops"], timeout=3)
        rc_c, out_c, _ = run_as_user(["xdotool", "get_desktop"], timeout=3)
        if rc_n == 0 and out_n.strip().isdigit():
            count = max(1, min(20, int(out_n.strip())))
            cur = int(out_c.strip()) + 1 if rc_c == 0 and out_c.strip().isdigit() else 1
            return [{"id": i, "name": str(i), "active": i == cur, "windows": 0} for i in range(1, count + 1)]

    return [{"id": i, "name": str(i), "active": i == 1, "windows": 0} for i in range(1, 5)]


def get_workspaces_info():
    return _cached("workspaces_info", 2.5, _compute_workspaces_info)


def _fmt_size_bytes(nbytes):
    if nbytes >= 1024 ** 4:
        return f"{nbytes / (1024 ** 4):.1f}T"
    if nbytes >= 1024 ** 3:
        return f"{nbytes / (1024 ** 3):.1f}G"
    if nbytes >= 1024 ** 2:
        return f"{nbytes / (1024 ** 2):.1f}M"
    return f"{nbytes / 1024:.0f}K"


def _collect_disk_nodes(nodes, out_list, seen=None):
    if seen is None:
        seen = set()
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
            key = (name, fstype, str(mount or ""))
            if key not in seen:
                seen.add(key)
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
            _collect_disk_nodes(children, out_list, seen)


def _compute_disks_info():
    disks = []
    if IS_WINDOWS:
        try:
            mask = int(ctypes.windll.kernel32.GetLogicalDrives())
            drive_types = {2: "Removable", 3: "Fixed", 4: "Network"}
            for i in range(26):
                if not (mask & (1 << i)):
                    continue
                letter = chr(65 + i)
                root = f"{letter}:\\"
                dtype = int(ctypes.windll.kernel32.GetDriveTypeW(root))
                if dtype not in drive_types:
                    continue
                try:
                    usage = shutil.disk_usage(root)
                    pct = int(round((usage.used / usage.total) * 100.0)) if usage.total > 0 else 0
                    disks.append({
                        "part": f"{letter}:",
                        "label": f"Drive ({letter}:)",
                        "fstype": drive_types[dtype],
                        "size": _fmt_size_bytes(usage.total),
                        "use_pct": f"{pct}%",
                        "mounted": True,
                    })
                except OSError:
                    continue
        except Exception:
            pass
        return disks

    if find_bin("lsblk"):
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


def get_disks_info(refresh=False):
    return _cached("disks_info", 20.0, _compute_disks_info, force=refresh)


def _compute_boot_entries():
    entries = []
    if IS_WINDOWS:
        if find_bin("bcdedit"):
            rc, out, _ = run_cmd(["bcdedit", "/enum", "firmware"], timeout=5)
            if rc == 0 and out:
                cur_id = ""
                cur_desc = ""
                for raw in out.splitlines() + [""]:
                    line = raw.strip()
                    if not line:
                        if cur_id and cur_desc and cur_id.lower() != "{fwbootmgr}":
                            entries.append({"num": cur_id, "name": cur_desc})
                        cur_id = ""
                        cur_desc = ""
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        k, v = parts[0].lower(), parts[1].strip()
                        if k == "identifier":
                            cur_id = v
                        elif k == "description":
                            cur_desc = v
        return entries

    if find_bin("efibootmgr"):
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


def get_boot_entries(refresh=False):
    return _cached("boot_entries", 300.0, _compute_boot_entries, force=refresh)


def _compute_init_system():
    if IS_WINDOWS:
        return "windows-svc"
    if os.path.isdir("/run/systemd/system"):
        return "systemd"
    if os.path.isdir("/run/openrc") or os.path.exists("/sbin/openrc-run"):
        return "openrc"
    if os.path.isdir("/run/runit") or os.path.isdir("/etc/runit"):
        return "runit"
    try:
        with open("/proc/1/comm", "r", encoding="utf-8", errors="ignore") as f:
            comm = f.read().strip().lower()
        if "systemd" in comm:
            return "systemd"
        if "openrc" in comm:
            return "openrc"
        if "runit" in comm:
            return "runit"
        if "s6" in comm:
            return "s6"
    except OSError:
        pass
    if find_bin("systemctl"):
        return "systemd"
    if find_bin("rc-service"):
        return "openrc"
    if find_bin("sv"):
        return "runit"
    return "unknown"


def detect_init_system():
    """Detect the host init system / service manager (cached across polling ticks)."""
    return _cached("init_system", 3600.0, _compute_init_system)


def _read_tail_lines(path, max_lines=150, max_bytes=524288):
    """Read at most the trailing max_bytes from a log file cleanly."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            start = max(0, size - max_bytes)
            f.seek(start)
            raw = f.read().decode("utf-8", errors="replace")
        lines = raw.splitlines()
        if start > 0 and lines:
            lines = lines[1:]
        return [ln for ln in lines if ln.strip()][-max_lines:]
    except OSError:
        return []


def _classify_log_level(text, default="INFO"):
    low = text.lower()
    if any(k in low for k in ("critical", "crit", "fatal", "panic", "segfault", "oom-killer", "error", "[err]", " fail", "failed")):
        return "ERROR"
    if any(k in low for k in ("warn", "warning", "deprecated", "timeout", "retry")):
        return "WARN"
    return default


def _level_matches_filter(entry_level, wanted):
    w = (wanted or "all").lower()
    lvl = (entry_level or "INFO").upper()
    if w == "err":
        return lvl in ("ERROR", "CRIT", "FATAL")
    if w == "warn":
        return lvl in ("ERROR", "CRIT", "FATAL", "WARN")
    return True


def _parse_log_line(raw_line, source_name):
    ts = ""
    msg = raw_line.strip()
    m_iso = re.match(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\S*)?)\s+(.*)$", msg)
    if m_iso:
        ts = m_iso.group(1)
        msg = m_iso.group(2)
    else:
        m_dmesg = re.match(r"^\[([^\]]+)\]\s*(.*)$", msg)
        if m_dmesg:
            ts = m_dmesg.group(1).strip()
            msg = m_dmesg.group(2)
        else:
            m_sys = re.match(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(.*)$", msg)
            if m_sys:
                ts = m_sys.group(1)
                msg = m_sys.group(2)
    return {
        "ts": ts,
        "source": source_name,
        "level": _classify_log_level(raw_line),
        "message": msg[:1200],
    }


def _read_windows_event_logs(log_name, source_tag, max_events):
    entries = []
    ps = (
        "try { "
        "Get-WinEvent -LogName $env:MRC_EVT_LOG -MaxEvents ([int]$env:MRC_EVT_MAX) -ErrorAction Stop | "
        "ForEach-Object { "
        "$t = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); "
        "$l = [string]$_.LevelDisplayName; "
        "$p = [string]$_.ProviderName; "
        "$m = ([string]$_.Message) -replace '[\\r\\n\\t]+',' '; "
        '"$t|$l|$p|$m" '
        "} } catch {}"
    )
    rc, out, _ = _win_run_ps(ps, timeout=6, extra_env={"MRC_EVT_LOG": log_name, "MRC_EVT_MAX": str(max_events)})
    if rc == 0 and out:
        for line in out.splitlines():
            parts = line.split("|", 3)
            if len(parts) < 4:
                continue
            ts, lvl_raw, prov, msg = parts[0].strip(), parts[1].strip(), parts[2].strip(), parts[3].strip()
            lvl = _classify_log_level(f"{lvl_raw} {msg}")
            entries.append({
                "ts": ts,
                "source": source_tag,
                "level": lvl,
                "message": f"[{prov}] {msg}"[:1200] if prov else msg[:1200],
            })
        entries.reverse()
    return entries


def get_system_logs(source="all", level="all", query="", lines=120):
    """Aggregate bounded logs across Windows Event Logs or Linux journal, syslog/OpenRC, dmesg, and mobile-rc."""
    src = (source or "all").strip().lower()
    lvl = (level or "all").strip().lower()
    q_low = str(query or "").strip().lower()[:120]
    try:
        limit = max(20, min(400, int(lines)))
    except (TypeError, ValueError):
        limit = 120

    per_src = limit if src != "all" else max(30, min(80, limit))
    entries = []

    if IS_WINDOWS:
        available_sources = ["mobile-rc", "system", "application"]
        if src in ("all", "mobile-rc"):
            for item in list(_AUDIT_LOG)[-per_src:]:
                entries.append(dict(item))
        if src in ("all", "system"):
            entries.extend(_read_windows_event_logs("System", "system", per_src))
        if src in ("all", "application"):
            entries.extend(_read_windows_event_logs("Application", "application", per_src))
    else:
        has_journal = bool(find_bin("journalctl"))
        has_dmesg = bool(find_bin("dmesg"))
        syslog_files = [
            p for p in (
                "/var/log/messages",
                "/var/log/syslog",
                "/var/log/socklog/everything/current",
                "/var/log/everything/current",
            )
            if os.path.isfile(p)
        ]
        openrc_files = [p for p in ("/var/log/rc.log",) if os.path.isfile(p)]

        available_sources = ["mobile-rc"]
        if has_journal:
            available_sources.append("journal")
        if openrc_files:
            available_sources.append("openrc")
        if syslog_files:
            available_sources.append("syslog")
        if has_dmesg:
            available_sources.append("dmesg")

        if src in ("all", "mobile-rc"):
            for item in list(_AUDIT_LOG)[-per_src:]:
                entries.append(dict(item))
            if os.path.isfile("/var/log/mobile-rc.log"):
                for raw in _read_tail_lines("/var/log/mobile-rc.log", max_lines=per_src):
                    entries.append(_parse_log_line(raw, "mobile-rc"))

        if src in ("all", "journal") and has_journal:
            jcmd = ["journalctl", "-n", str(per_src), "--no-pager", "-o", "short-iso"]
            if lvl == "err":
                jcmd.extend(["-p", "3"])
            elif lvl == "warn":
                jcmd.extend(["-p", "4"])
            rc, out, _ = run_cmd(jcmd, timeout=6)
            if rc == 0 and out:
                for raw in out.splitlines():
                    if not raw.startswith("-- "):
                        entries.append(_parse_log_line(raw, "journal"))

        if src in ("all", "openrc") and openrc_files:
            for path in openrc_files:
                for raw in _read_tail_lines(path, max_lines=per_src):
                    entries.append(_parse_log_line(raw, "openrc"))

        if src in ("all", "syslog") and syslog_files:
            for path in syslog_files[:2]:
                for raw in _read_tail_lines(path, max_lines=per_src):
                    entries.append(_parse_log_line(raw, "syslog"))

        if src in ("all", "dmesg") and has_dmesg:
            dcmd = ["dmesg", "-T"]
            if lvl == "err":
                dcmd.append("--level=emerg,alert,crit,err")
            elif lvl == "warn":
                dcmd.append("--level=emerg,alert,crit,err,warn")
            rc, out, _ = run_cmd(dcmd, timeout=5)
            if rc != 0:
                rc, out, _ = run_cmd(["dmesg"], timeout=5)
            if rc == 0 and out:
                for raw in out.splitlines()[-per_src:]:
                    if raw.strip():
                        entries.append(_parse_log_line(raw, "dmesg"))

    filtered = []
    for item in entries:
        if not _level_matches_filter(item.get("level"), lvl):
            continue
        if q_low:
            hay = f"{item.get('ts', '')} {item.get('source', '')} {item.get('level', '')} {item.get('message', '')}".lower()
            if q_low not in hay:
                continue
        filtered.append(item)

    if len(filtered) > limit:
        filtered = filtered[-limit:]

    return {
        "init_system": detect_init_system(),
        "available_sources": available_sources,
        "entries": filtered,
        "total": len(filtered),
    }


def _parse_os_release_file(path):
    """Parse /etc/os-release style key=value metadata into a dict."""
    if not os.path.isfile(path):
        return None
    data = {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                data[k.strip()] = v.strip().strip("\"'")
        if data:
            return {
                "name": data.get("PRETTY_NAME") or data.get("NAME") or "Linux",
                "id": data.get("ID") or "linux",
                "version_id": data.get("VERSION_ID") or "",
            }
    except OSError:
        pass
    return None


def _scan_bootloader_configs():
    """Collect bootloader entries from systemd-boot and GRUB configs read-only."""
    entries = []
    for base in ("/boot/loader/entries", "/efi/loader/entries", "/boot/efi/loader/entries"):
        if not os.path.isdir(base):
            continue
        try:
            for fname in sorted(os.listdir(base)):
                if not fname.endswith(".conf"):
                    continue
                fpath = os.path.join(base, fname)
                title = fname[:-5]
                linux_img = ""
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            s = line.strip()
                            if s.startswith("title "):
                                title = s[6:].strip()
                            elif s.startswith("linux "):
                                linux_img = s[6:].strip()
                except OSError:
                    continue
                entries.append({"loader": "systemd-boot", "title": title, "kernel": linux_img, "file": fname})
        except OSError:
            pass

    for gpath in ("/boot/grub/grub.cfg", "/boot/grub2/grub.cfg", "/boot/efi/EFI/grub/grub.cfg"):
        if not os.path.isfile(gpath):
            continue
        try:
            with open(gpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(524288)
            for m in re.finditer(r"^\s*menuentry\s+(['\"])(.+?)\1", content, flags=re.MULTILINE):
                title = m.group(2).strip()
                if title:
                    entries.append({"loader": "grub", "title": title, "kernel": "", "file": gpath})
        except OSError:
            pass
    return entries[:40]


def _scan_mounted_filesystems():
    """List mounted Linux filesystems cleanly via findmnt or /proc/mounts."""
    mounts = []
    if find_bin("findmnt"):
        rc, out, _ = run_cmd(["findmnt", "-J", "-l", "-o", "SOURCE,TARGET,FSTYPE,OPTIONS"], timeout=5)
        if rc == 0 and out:
            try:
                parsed = json.loads(out)
                for node in parsed.get("filesystems", []):
                    fstype = str(node.get("fstype") or "")
                    target = str(node.get("target") or "")
                    source = str(node.get("source") or "")
                    opts = str(node.get("options") or "")
                    if fstype in ("proc", "sysfs", "tmpfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "pstore", "bpf", "tracefs", "securityfs", "efivarfs", "fusectl", "debugfs", "ramfs", "configfs", "hugetlbfs", "mqueue", "autofs"):
                        continue
                    mounts.append({"source": source, "target": target, "fstype": fstype, "options": opts})
                return mounts[:30]
            except Exception:
                pass
    try:
        with open("/proc/mounts", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 4:
                    continue
                source, target, fstype, opts = parts[0], parts[1], parts[2], parts[3]
                if not source.startswith("/dev/"):
                    continue
                mounts.append({"source": source, "target": target, "fstype": fstype, "options": opts})
    except OSError:
        pass
    return mounts[:30]


def _inspect_mounted_tree_for_distros(root_path, dev_path, fstype, label, uuid):
    """Look for /etc/os-release at root or in Btrfs top-level subvolumes under root_path."""
    found = []
    seen_roots = set()
    candidates = [("", root_path)]
    if fstype == "btrfs":
        try:
            for name in sorted(os.listdir(root_path)):
                if name.startswith("@"):
                    sub_path = os.path.join(root_path, name)
                    if os.path.isdir(sub_path):
                        candidates.append((name, sub_path))
        except OSError:
            pass
    for subvol, base in candidates:
        for rel in ("etc/os-release", "usr/lib/os-release"):
            info = _parse_os_release_file(os.path.join(base, rel))
            if info:
                key = (dev_path, subvol, info["name"])
                if key not in seen_roots:
                    seen_roots.add(key)
                    found.append({
                        "name": info["name"],
                        "id": info["id"],
                        "version_id": info["version_id"],
                        "device": dev_path,
                        "fstype": fstype,
                        "label": label,
                        "uuid": uuid,
                        "subvolume": subvol or "/",
                    })
                break
    return found


def _walk_lsblk_devices(nodes, out):
    for node in nodes or []:
        out.append(node)
        if node.get("children"):
            _walk_lsblk_devices(node["children"], out)


def _get_windows_distros_info(os_info, refresh=False):
    cpu_model = os.environ.get("PROCESSOR_IDENTIFIER") or platform.processor() or "x86_64 CPU"
    host = {
        "name": os_info.get("name", "Windows"),
        "hostname": os_info.get("hostname", ""),
        "kernel": os_info.get("kernel", ""),
        "arch": platform.machine(),
        "init_system": "windows-svc",
        "compositor": "DWM",
        "cpu_model": cpu_model,
        "gpu_name": get_gpu_info().get("name", "Integrated / Unknown"),
    }
    detected_distros = [{"name": host["name"], "source": "Running Host", "detail": f"windows-svc / {host['kernel']}"}]
    if find_bin("wsl"):
        rc, out, _ = run_cmd(["wsl", "-l", "-v"], timeout=5, encoding="utf-16-le")
        if rc == 0 and out:
            for line in out.splitlines()[1:]:
                clean = line.replace("\x00", "").strip().lstrip("*").strip()
                if not clean:
                    continue
                parts = clean.split()
                if parts:
                    detected_distros.append({
                        "name": parts[0],
                        "source": "WSL",
                        "detail": " ".join(parts[1:]) if len(parts) > 1 else "Installed",
                    })
    filesystems = [
        {"target": d["part"], "fstype": d["fstype"], "source": f"{d['size']} ({d['use_pct']} used)"}
        for d in get_disks_info(refresh=refresh)
    ]
    return {
        "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "deep_scan": False,
        "cached": False,
        "host": host,
        "efi_entries": get_boot_entries(refresh=refresh),
        "bootloader_entries": [],
        "os_prober": [],
        "filesystems": filesystems,
        "unmounted_distros": [],
        "detected_distros": detected_distros,
        "scan_errors": [],
    }


def get_installed_distros_info(deep=False, refresh=False):
    """Inventory running OS, bootloaders, os-prober / WSL, and optionally read-only unmounted partitions."""
    global _DISTRO_CACHE
    cache_key = "deep" if deep else "safe"
    now = time.time()
    cached = _DISTRO_CACHE.get(cache_key)
    ttl = 300 if deep else 45
    if not refresh and cached and (now - cached.get("_ts", 0)) < ttl:
        res = dict(cached)
        res.pop("_ts", None)
        res["cached"] = True
        return res

    os_info = get_os_info()
    if IS_WINDOWS:
        payload = _get_windows_distros_info(os_info, refresh=refresh)
        cache_copy = dict(payload)
        cache_copy["_ts"] = now
        _DISTRO_CACHE[cache_key] = cache_copy
        return payload

    cpu_model = ""
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("model name"):
                    cpu_model = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass

    env = get_desktop_env()
    host = {
        "name": os_info.get("name", "Linux"),
        "hostname": os_info.get("hostname", ""),
        "kernel": os_info.get("kernel", ""),
        "arch": platform.machine(),
        "init_system": detect_init_system(),
        "compositor": get_active_compositor(env) or "unknown",
        "cpu_model": cpu_model or platform.processor() or "Unknown CPU",
        "gpu_name": get_gpu_info().get("name", "Integrated / Unknown"),
    }

    efi_entries = get_boot_entries(refresh=refresh)
    bootloader_entries = _scan_bootloader_configs()
    filesystems = _scan_mounted_filesystems()

    os_prober = []
    if find_bin("os-prober"):
        rc, out, _ = run_cmd(["os-prober"], timeout=10)
        if rc == 0 and out:
            for line in out.splitlines():
                parts = line.split(":")
                if len(parts) >= 3:
                    os_prober.append({
                        "device": parts[0].strip(),
                        "name": parts[1].strip(),
                        "short": parts[2].strip(),
                        "boot_type": parts[3].strip() if len(parts) > 3 else "",
                    })

    unmounted_distros = []
    scan_errors = []
    if deep:
        linux_fs = {"ext4", "ext3", "ext2", "btrfs", "xfs", "f2fs", "jfs", "reiserfs", "nilfs2"}
        with _DISTRO_SCAN_LOCK:
            if find_bin("lsblk"):
                rc, out, err = run_cmd(
                    ["lsblk", "-J", "-o", "NAME,PATH,TYPE,FSTYPE,LABEL,PARTLABEL,UUID,SIZE,MOUNTPOINT"],
                    timeout=8,
                )
                if rc == 0 and out:
                    try:
                        tree = json.loads(out)
                        flat = []
                        _walk_lsblk_devices(tree.get("blockdevices", []), flat)
                        for dev in flat:
                            name = str(dev.get("name") or "")
                            if name.startswith(("zram", "loop", "ram")):
                                continue
                            fstype = str(dev.get("fstype") or "").lower()
                            mnt = dev.get("mountpoint")
                            dev_path = str(dev.get("path") or (f"/dev/{name}" if name else ""))
                            if not dev_path or mnt or fstype not in linux_fs:
                                continue
                            label = str(dev.get("label") or dev.get("partlabel") or "")
                            uuid = str(dev.get("uuid") or "")
                            with tempfile.TemporaryDirectory(prefix="mrc-probe-") as tmpdir:
                                mounted = False
                                try:
                                    opts_candidates = ["ro,noload", "ro"] if fstype in ("ext4", "ext3", "xfs") else ["ro"]
                                    for mopts in opts_candidates:
                                        mrc, _, merr = run_cmd(["mount", "-o", mopts, dev_path, tmpdir], timeout=6)
                                        if mrc == 0:
                                            mounted = True
                                            break
                                    if mounted:
                                        found = _inspect_mounted_tree_for_distros(tmpdir, dev_path, fstype, label, uuid)
                                        unmounted_distros.extend(found)
                                except Exception as ex:
                                    scan_errors.append(f"{dev_path}: {ex}")
                                finally:
                                    if mounted:
                                        urc, _, uerr = run_cmd(["umount", tmpdir], timeout=6)
                                        if urc != 0:
                                            scan_errors.append(f"umount {dev_path}: {uerr or urc}")
                    except Exception as ex:
                        scan_errors.append(f"lsblk parse: {ex}")
                elif err:
                    scan_errors.append(err)
            else:
                scan_errors.append("lsblk utility not found")

    detected_distros = [{"name": host["name"], "source": "Running Host", "detail": f"{host['init_system']} / {host['kernel']}"}]
    seen_names = {host["name"].lower()}
    for item in unmounted_distros:
        lbl = f"{item['device']} ({item['fstype']}, subvol {item['subvolume']})"
        detected_distros.append({"name": item["name"], "source": "Unmounted Partition", "detail": lbl})
        seen_names.add(item["name"].lower())
    for item in os_prober:
        if item["name"].lower() not in seen_names:
            detected_distros.append({"name": item["name"], "source": "os-prober", "detail": item["device"]})
            seen_names.add(item["name"].lower())
    for item in bootloader_entries:
        t = item["title"]
        if t.lower() not in seen_names:
            detected_distros.append({"name": t, "source": item["loader"], "detail": item.get("kernel") or item.get("file", "")})
            seen_names.add(t.lower())

    payload = {
        "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "deep_scan": bool(deep),
        "cached": False,
        "host": host,
        "efi_entries": efi_entries,
        "bootloader_entries": bootloader_entries,
        "os_prober": os_prober,
        "filesystems": filesystems,
        "unmounted_distros": unmounted_distros,
        "detected_distros": detected_distros,
        "scan_errors": scan_errors,
    }
    cache_copy = dict(payload)
    cache_copy["_ts"] = now
    _DISTRO_CACHE[cache_key] = cache_copy
    return payload


def _compute_services_info():
    """Return host service list normalized across OpenRC, systemd, runit, and Windows Services."""
    init_sys = detect_init_system()
    services = []
    if IS_WINDOWS:
        ps = (
            "Get-Service | Sort-Object Status -Descending | Select-Object -First 80 "
            "Name,@{N='Status';E={$_.Status.ToString()}},@{N='StartType';E={$_.StartType.ToString()}} | "
            "ConvertTo-Json -Compress"
        )
        rc, out, _ = _win_run_ps(ps, timeout=6)
        if rc == 0 and out:
            try:
                parsed = json.loads(out)
                if isinstance(parsed, dict):
                    parsed = [parsed]
                for item in parsed:
                    if isinstance(item, dict) and item.get("Name"):
                        services.append({
                            "name": str(item["Name"]),
                            "status": str(item.get("Status") or "Unknown").lower(),
                            "runlevel": str(item.get("StartType") or "windows"),
                        })
            except Exception:
                pass
        return {"init_system": init_sys, "services": services}

    if init_sys == "openrc" and find_bin("rc-status"):
        rc, out, _ = run_cmd(["rc-status", "-a", "-C"], timeout=6)
        runlevel = "default"
        if rc == 0 and out:
            for line in out.splitlines():
                s = line.strip()
                if not s:
                    continue
                if s.startswith("Runlevel:"):
                    runlevel = s.split(":", 1)[1].strip()
                    continue
                m = re.match(r"^([A-Za-z0-9_.@:-]+)\s+\[\s*([^\]]+?)\s*\]$", s)
                if m:
                    services.append({
                        "name": m.group(1),
                        "status": m.group(2).strip(),
                        "runlevel": runlevel,
                    })
    elif init_sys == "systemd" and find_bin("systemctl"):
        rc, out, _ = run_cmd(
            ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend"],
            timeout=6,
        )
        if rc == 0 and out:
            for line in out.splitlines()[:80]:
                parts = line.split(None, 4)
                if len(parts) >= 4:
                    unit = parts[0].removesuffix(".service")
                    services.append({
                        "name": unit,
                        "status": f"{parts[2]} ({parts[3]})",
                        "runlevel": "systemd",
                    })
    elif init_sys == "runit" and find_bin("sv"):
        for base in ("/run/runit/service", "/var/service"):
            if not os.path.isdir(base):
                continue
            for name in sorted(os.listdir(base))[:60]:
                rc, out, _ = run_cmd(["sv", "status", os.path.join(base, name)], timeout=3)
                st = out.split(":", 1)[0].strip() if out else ("ok" if rc == 0 else "down")
                services.append({"name": name, "status": st, "runlevel": "runit"})
            break
    return {"init_system": init_sys, "services": services}


def get_services_info():
    return _cached("services_info", 4.0, _compute_services_info)


def control_service(name, action):
    """Safely start, stop, restart, or reload a system service under validated init tools."""
    svc = str(name or "").strip()
    act = str(action or "").strip().lower()
    svc_pattern = r"[A-Za-z0-9_.@:$-]{1,96}" if IS_WINDOWS else r"[A-Za-z0-9_.@:-]{1,96}"
    if not re.fullmatch(svc_pattern, svc):
        return False, "Invalid service name"
    if act not in ("start", "stop", "restart", "reload"):
        return False, "Invalid service action"
    init_sys = detect_init_system()
    if IS_WINDOWS:
        if act == "reload":
            return False, "Reload is not supported on Windows services (use restart)"
        verb = {"start": "Start-Service", "stop": "Stop-Service -Force", "restart": "Restart-Service -Force"}[act]
        rc, out, err = _win_run_ps(
            f"{verb} -Name $env:MRC_SVC_NAME -ErrorAction Stop",
            timeout=20,
            extra_env={"MRC_SVC_NAME": svc},
        )
    elif init_sys == "openrc" and find_bin("rc-service"):
        rc, out, err = run_cmd(["rc-service", svc, act], timeout=20)
    elif init_sys == "systemd" and find_bin("systemctl"):
        rc, out, err = run_cmd(["systemctl", act, svc], timeout=20)
    elif init_sys == "runit" and find_bin("sv"):
        sv_act = "hup" if act == "reload" else act
        rc, out, err = run_cmd(["sv", sv_act, svc], timeout=15)
    else:
        return False, f"Service control not supported on init system '{init_sys}'"
    _invalidate_cache("services_info")
    msg = (out or err or f"{svc} {act}: exit {rc}").strip()
    if rc == 0:
        record_audit_event("INFO", f"Service action: {svc} -> {act}")
    else:
        record_audit_event("WARN", f"Service action failed: {svc} -> {act} ({msg})")
    return rc == 0, msg


def get_processes_info(limit=30):
    """Return top running processes sorted by CPU/RSS delta using /proc or Windows tasklist."""
    global _PROC_LAST
    try:
        cap = max(5, min(60, int(limit)))
    except (TypeError, ValueError):
        cap = 30

    if IS_WINDOWS:
        items = []
        rc, out, _ = run_cmd(["tasklist", "/FO", "CSV", "/NH"], timeout=6)
        if rc == 0 and out:
            for row in csv.reader(out.splitlines()):
                if len(row) < 5:
                    continue
                name = row[0].strip()
                try:
                    pid = int(row[1].strip())
                except ValueError:
                    continue
                mem_digits = re.sub(r"[^\d]", "", row[4])
                rss_mb = round(int(mem_digits) / 1024.0, 1) if mem_digits else 0.0
                items.append({
                    "pid": pid,
                    "name": name[:32],
                    "cmd": name[:96],
                    "state": "R",
                    "cpu_pct": 0.0,
                    "rss_mb": rss_mb,
                })
        items.sort(key=lambda p: p["rss_mb"], reverse=True)
        return {"processes": items[:cap], "total": len(items)}

    total_ticks = 0
    try:
        with open("/proc/stat", "r", encoding="utf-8") as f:
            total_ticks = sum(int(x) for x in f.readline().split()[1:8])
    except Exception:
        total_ticks = 0

    prev_total, prev_procs = _PROC_LAST if _PROC_LAST else (0, {})
    dt_ticks = max(1, total_ticks - prev_total) if prev_total and total_ticks > prev_total else 0
    cur_procs = {}
    items = []
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        pids = []

    for pid_str in pids:
        try:
            pid = int(pid_str)
            with open(f"/proc/{pid}/stat", "r", encoding="utf-8", errors="ignore") as f:
                stat_raw = f.read()
            rparen = stat_raw.rfind(")")
            if rparen <= 0:
                continue
            lparen = stat_raw.find("(")
            comm = stat_raw[lparen + 1:rparen]
            rest = stat_raw[rparen + 2:].split()
            if len(rest) < 22:
                continue
            state = rest[0]
            proc_ticks = int(rest[11]) + int(rest[12])
            rss_pages = int(rest[21])
            rss_mb = round((rss_pages * 4096) / (1024 * 1024), 1)
            cur_procs[pid] = proc_ticks
            cpu_pct = 0.0
            if dt_ticks > 0 and pid in prev_procs:
                cpu_pct = round(max(0.0, (proc_ticks - prev_procs[pid]) / dt_ticks * 100.0 * (os.cpu_count() or 1)), 1)
            cmd = comm
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as cf:
                    raw_cmd = cf.read(256).replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
                if raw_cmd:
                    cmd = raw_cmd[:96]
            except OSError:
                pass
            items.append({
                "pid": pid,
                "name": comm[:32],
                "cmd": cmd,
                "state": state,
                "cpu_pct": cpu_pct,
                "rss_mb": rss_mb,
            })
        except Exception:
            continue

    _PROC_LAST = (total_ticks, cur_procs)
    items.sort(key=lambda p: (p["cpu_pct"], p["rss_mb"]), reverse=True)
    return {"processes": items[:cap], "total": len(items)}


def kill_process(pid, sig_name="TERM"):
    """Send TERM, KILL, or HUP to a non-init non-self PID cleanly."""
    try:
        pid_int = int(pid)
    except (TypeError, ValueError):
        return False, "Invalid PID"
    min_protected = 4 if IS_WINDOWS else 1
    if pid_int <= min_protected or pid_int == os.getpid():
        return False, "Refusing to signal init/system or Mobile-RC server process"
    sig_key = str(sig_name or "TERM").strip().upper()
    if sig_key not in ("TERM", "KILL", "HUP"):
        return False, "Unsupported signal (use TERM, KILL, or HUP)"

    if IS_WINDOWS:
        cmd = ["taskkill", "/PID", str(pid_int)]
        if sig_key == "KILL":
            cmd.append("/F")
        rc, out, err = run_cmd(cmd, timeout=8)
        msg = (out or err or f"taskkill PID {pid_int}: exit {rc}").strip()
        if rc == 0:
            record_audit_event("WARN", f"Terminated Windows PID {pid_int} ({sig_key})")
        return rc == 0, msg

    sig_map = {"TERM": 15, "KILL": 9, "HUP": 1}
    try:
        os.kill(pid_int, sig_map[sig_key])
        record_audit_event("WARN", f"Sent SIG{sig_key} to PID {pid_int}")
        return True, f"Sent SIG{sig_key} to PID {pid_int}"
    except ProcessLookupError:
        return False, f"Process {pid_int} not found"
    except PermissionError:
        return False, f"Permission denied signaling PID {pid_int}"
    except Exception as e:
        return False, str(e)


_ALLOWED_REMOTE_KEYS = {
    "Return", "BackSpace", "Escape", "Tab", "space",
    "Left", "Right", "Up", "Down", "Prior", "Next", "Home", "End",
    "XF86AudioPlay", "XF86AudioRaiseVolume", "XF86AudioLowerVolume",
}

_WIN_VK_MAP = {
    "Return": 0x0D, "BackSpace": 0x08, "Escape": 0x1B, "Tab": 0x09, "space": 0x20,
    "Prior": 0x21, "Next": 0x22, "End": 0x23, "Home": 0x24,
    "Left": 0x25, "Up": 0x26, "Right": 0x27, "Down": 0x28,
    "XF86AudioPlay": 0xB3, "XF86AudioRaiseVolume": 0xAF, "XF86AudioLowerVolume": 0xAE,
}


def _send_windows_remote_input(kind, payload):
    try:
        user32 = ctypes.windll.user32
        if kind == "move":
            dx = max(-800, min(800, int(round(float(payload.get("dx", 0))))))
            dy = max(-800, min(800, int(round(float(payload.get("dy", 0))))))

            pt = _WinPoint()
            user32.GetCursorPos(ctypes.byref(pt))
            user32.SetCursorPos(pt.x + dx, pt.y + dy)
            return True, "win32"

        if kind == "click":
            btn = str(payload.get("button", "left")).strip().lower()
            flags = {"left": (0x0002, 0x0004), "right": (0x0008, 0x0010), "middle": (0x0020, 0x0040)}
            if btn not in flags:
                return False, "Unsupported mouse button"
            down, up = flags[btn]
            user32.mouse_event(down, 0, 0, 0, 0)
            user32.mouse_event(up, 0, 0, 0, 0)
            return True, "win32"

        if kind == "scroll":
            dy = max(-20, min(20, int(round(float(payload.get("dy", 0))))))
            if dy == 0:
                return True, "noop"
            user32.mouse_event(0x0800, 0, 0, ctypes.c_ulong(-dy * 120), 0)
            return True, "win32"

        if kind == "key":
            key = str(payload.get("key", "")).strip()
            if key not in _WIN_VK_MAP:
                return False, "Unsupported key"
            _win_send_vk(_WIN_VK_MAP[key])
            return True, "win32"

        if kind == "text":
            text = str(payload.get("text", ""))
            if not text or len(text) > 1000:
                return False, "Text must be 1-1000 characters"
            return type_prompt_to_active_window(text, auto_enter=bool(payload.get("auto_enter", False)))
        return False, "Unsupported remote input kind"
    except Exception as e:
        return False, str(e)


def send_remote_input(kind, payload):
    """Dispatch mobile trackpad, click, scroll, whitelisted key, or text events to desktop."""
    kind = str(kind or "").strip().lower()
    if not isinstance(payload, dict):
        payload = {}
    if IS_WINDOWS:
        return _send_windows_remote_input(kind, payload)

    env = get_desktop_env()
    search_path = env["PATH"]
    has_ydo = bool(find_bin("ydotool", search_path))
    has_xdo = bool(find_bin("xdotool", search_path))
    has_wtype = bool(find_bin("wtype", search_path))

    if kind == "move":
        try:
            dx = max(-800, min(800, int(round(float(payload.get("dx", 0))))))
            dy = max(-800, min(800, int(round(float(payload.get("dy", 0))))))
        except (TypeError, ValueError):
            return False, "Invalid mouse delta"
        if has_ydo:
            rc, _, err = run_as_user(["ydotool", "mousemove", "--", str(dx), str(dy)], timeout=3)
            return rc == 0, ("ydotool" if rc == 0 else err)
        if has_xdo:
            rc, _, err = run_as_user(["xdotool", "mousemove_relative", "--", str(dx), str(dy)], timeout=3)
            return rc == 0, ("xdotool" if rc == 0 else err)
        return False, "Install ydotool (Wayland) or xdotool (X11) for remote cursor movement"

    if kind == "click":
        btn = str(payload.get("button", "left")).strip().lower()
        btn_map_xdo = {"left": "1", "middle": "2", "right": "3"}
        btn_map_ydo = {"left": "0xC0", "right": "0xC1", "middle": "0xC2"}
        if btn not in btn_map_xdo:
            return False, "Unsupported mouse button"
        if has_ydo:
            rc, _, err = run_as_user(["ydotool", "click", btn_map_ydo[btn]], timeout=3)
            return rc == 0, ("ydotool" if rc == 0 else err)
        if has_xdo:
            rc, _, err = run_as_user(["xdotool", "click", btn_map_xdo[btn]], timeout=3)
            return rc == 0, ("xdotool" if rc == 0 else err)
        return False, "Install ydotool (Wayland) or xdotool (X11) for mouse click"

    if kind == "scroll":
        try:
            dy = max(-20, min(20, int(round(float(payload.get("dy", 0))))))
        except (TypeError, ValueError):
            return False, "Invalid scroll delta"
        if dy == 0:
            return True, "noop"
        if has_ydo:
            rc, _, err = run_as_user(["ydotool", "mousemove", "-w", "--", "0", str(-dy)], timeout=3)
            return rc == 0, ("ydotool" if rc == 0 else err)
        if has_xdo:
            btn = "4" if dy < 0 else "5"
            rc, _, err = run_as_user(["xdotool", "click", "--repeat", str(abs(dy)), btn], timeout=3)
            return rc == 0, ("xdotool" if rc == 0 else err)
        return False, "Install ydotool or xdotool for remote scroll"

    if kind == "key":
        key = str(payload.get("key", "")).strip()
        if key not in _ALLOWED_REMOTE_KEYS:
            return False, "Unsupported key"
        if has_wtype:
            rc, _, err = run_as_user(["wtype", "-k", key], timeout=3)
            if rc == 0:
                return True, "wtype"
        if has_xdo:
            rc, _, err = run_as_user(["xdotool", "key", key], timeout=3)
            return rc == 0, ("xdotool" if rc == 0 else err)
        if has_ydo and key == "Return":
            rc, _, err = run_as_user(["ydotool", "key", "28:1", "28:0"], timeout=3)
            return rc == 0, ("ydotool" if rc == 0 else err)
        return False, "Install wtype, ydotool, or xdotool for remote key input"

    if kind == "text":
        text = str(payload.get("text", ""))
        if not text or len(text) > 1000:
            return False, "Text must be 1-1000 characters"
        return type_prompt_to_active_window(text, auto_enter=bool(payload.get("auto_enter", False)))

    return False, "Unsupported remote input kind"


def _discovery_worker():
    """Respond to LAN UDP discovery broadcasts on DISCOVERY_PORT cleanly."""
    if not DISCOVERY_ENABLED:
        return
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("0.0.0.0", DISCOVERY_PORT))
    except OSError as e:
        record_audit_event("WARN", f"LAN discovery UDP listener unavailable on port {DISCOVERY_PORT}: {e}")
        return

    record_audit_event("INFO", f"LAN discovery UDP listener active on port {DISCOVERY_PORT}")
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            msg = data.decode("utf-8", errors="ignore").strip()
            if msg == "MOBILE_RC_DISCOVER" or '"discover"' in msg.lower():
                os_info = get_os_info()
                reply = json.dumps({
                    "service": "mobile-rc",
                    "version": 2,
                    "hostname": os_info.get("hostname", socket.gethostname()),
                    "os": os_info.get("name", "Linux"),
                    "port": PORT,
                    "ips": get_local_ips(),
                    "macs": get_mac_addresses(),
                }).encode("utf-8")
                sock.sendto(reply, addr)
        except Exception:
            time.sleep(0.2)


def _compute_local_ips():
    ips = []
    if IS_WINDOWS:
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                ip_addr = info[4][0]
                if ip_addr and not ip_addr.startswith("127.") and ip_addr not in ips:
                    ips.append(ip_addr)
        except Exception:
            pass
    if not IS_WINDOWS and find_bin("ip"):
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
    if not IS_WINDOWS and not ips and find_bin("hostname"):
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
            if ip_addr and not ip_addr.startswith("127.") and ip_addr not in ips:
                ips.append(ip_addr)
            s.close()
        except Exception:
            pass
    return ips


def get_local_ips():
    return _cached("local_ips", 15.0, _compute_local_ips)


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
    keygen_bin = find_bin("ssh-keygen")
    if not os.path.exists(SSH_KEY_FILE) and keygen_bin:
        subprocess.run(
            [keygen_bin, "-t", "ed25519", "-N", "", "-f", SSH_KEY_FILE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            creationflags=_win_creationflags(),
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
            m = re.search(
                r"(https://(?!admin\.|www\.|docs\.)[a-zA-Z0-9._-]+\.(?:lhr\.life|localhost\.run))\b",
                line,
            )
            if m:
                url = m.group(1)
                changed = False
                with _TUNNEL_LOCK:
                    if _TUNNEL_PROC is not proc:
                        return
                    if _TUNNEL_URL != url:
                        _TUNNEL_URL = url
                        changed = True
                    _TUNNEL_STATUS = "online"
                if changed:
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
    ssh_bin = find_bin("ssh")
    if not ssh_bin:
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
            ssh_bin,
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

        tunnel_env = os.environ.copy()
        tunnel_env["PATH"] = get_system_path()
        proc = subprocess.Popen(
            cmd,
            env=tunnel_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            creationflags=_win_creationflags(),
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


def capture_desktop_screenshot():
    """Capture active desktop display into compressed JPEG (or PNG fallback) across Windows/Linux."""
    _, uid, gid, _ = get_target_user_info()
    with tempfile.TemporaryDirectory(prefix="mrc_shot_") as tmpdir:
        try:
            if not IS_WINDOWS and hasattr(os, "geteuid") and os.geteuid() == 0 and uid != 0:
                os.chown(tmpdir, uid, gid)
            os.chmod(tmpdir, 0o700)
        except OSError:
            pass
        raw_path = os.path.join(tmpdir, "raw.png")
        shot_path = os.path.join(tmpdir, "shot.jpg")

        if IS_WINDOWS:
            ps_script = (
                "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; "
                "$vs = [System.Windows.Forms.SystemInformation]::VirtualScreen; "
                "$bmp = New-Object System.Drawing.Bitmap($vs.Width, $vs.Height); "
                "$g = [System.Drawing.Graphics]::FromImage($bmp); "
                "$g.CopyFromScreen($vs.Left, $vs.Top, 0, 0, $bmp.Size); "
                "$scale = [Math]::Min(1.0, [Math]::Min(1280.0 / [Math]::Max(1, $bmp.Width), 800.0 / [Math]::Max(1, $bmp.Height))); "
                "$tw = [Math]::Max(1, [int][Math]::Round($bmp.Width * $scale)); "
                "$th = [Math]::Max(1, [int][Math]::Round($bmp.Height * $scale)); "
                "$outBmp = New-Object System.Drawing.Bitmap($tw, $th); "
                "$g2 = [System.Drawing.Graphics]::FromImage($outBmp); "
                "$g2.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic; "
                "$g2.DrawImage($bmp, 0, 0, $tw, $th); "
                "$enc = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' } | Select-Object -First 1; "
                "$ep = New-Object System.Drawing.Imaging.EncoderParameters(1); "
                "$ep.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality, 75L); "
                "$outBmp.Save($env:MRC_SHOT_PATH, $enc, $ep); "
                "$g2.Dispose(); $outBmp.Dispose(); $g.Dispose(); $bmp.Dispose()"
            )
            rc, _, _ = _win_run_ps(ps_script, timeout=8, extra_env={"MRC_SHOT_PATH": shot_path})
            if rc == 0 and os.path.isfile(shot_path) and os.path.getsize(shot_path) > 500:
                with open(shot_path, "rb") as f:
                    return f.read(), "image/jpeg"
            return None, None

        env = get_desktop_env()
        comp = get_active_compositor(env)
        capture_cmds = [
            ["grim", raw_path],
            ["wayshot", "-f", raw_path],
            ["spectacle", "-b", "-n", "-o", raw_path],
            ["gnome-screenshot", "-f", raw_path],
            ["maim", raw_path],
            ["scrot", raw_path],
            ["import", "-window", "root", raw_path],
        ]
        if comp == "kde":
            capture_cmds.insert(0, capture_cmds.pop(2))
        elif comp == "gnome":
            capture_cmds.insert(0, capture_cmds.pop(3))
        for cmd in capture_cmds:
            if not find_bin(cmd[0], env["PATH"]):
                continue
            rc, _, _ = run_as_user(cmd, timeout=8, shell=False)
            if rc == 0 and os.path.isfile(raw_path) and os.path.getsize(raw_path) > 1000:
                break

        if os.path.isfile(raw_path) and os.path.getsize(raw_path) > 1000:
            run_first_available([
                ["magick", raw_path, "-resize", "1280x800", "-quality", "75", shot_path],
                ["convert", raw_path, "-resize", "1280x800", "-quality", "75", shot_path],
            ], timeout=8)
            if os.path.isfile(shot_path) and os.path.getsize(shot_path) > 1000:
                with open(shot_path, "rb") as f:
                    return f.read(), "image/jpeg"
            try:
                from PIL import Image
                with Image.open(raw_path) as im:
                    rgb_im = im.convert("RGB")
                    rgb_im.thumbnail((1280, 800))
                    rgb_im.save(shot_path, "JPEG", quality=75)
                with open(shot_path, "rb") as f:
                    return f.read(), "image/jpeg"
            except Exception:
                with open(raw_path, "rb") as f:
                    return f.read(), "image/png"
    return None, None


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
<meta name="theme-color" content="#070b14">
<title>Mobile-RC • Control Center</title>
<style>
  :root {
    --bg: #070b14;
    --bg-elev: #0d1424;
    --card: rgba(15, 23, 42, 0.88);
    --card-inner: rgba(2, 6, 23, 0.48);
    --border: rgba(148, 163, 184, 0.14);
    --border-strong: rgba(148, 163, 184, 0.24);
    --accent: #38bdf8;
    --accent-soft: rgba(56, 189, 248, 0.14);
    --accent2: #818cf8;
    --text: #f8fafc;
    --muted: #94a3b8;
    --danger: #ef4444;
    --success: #10b981;
    --warning: #f59e0b;
    --radius: 16px;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; font-family: system-ui, -apple-system, 'Segoe UI', Roboto, Inter, sans-serif; -webkit-tap-highlight-color: transparent; }
  body {
    background: radial-gradient(circle at 12% 8%, rgba(56,189,248,0.10), transparent 36%),
                radial-gradient(circle at 88% 85%, rgba(129,140,248,0.08), transparent 38%),
                var(--bg);
    color: var(--text);
    min-height: 100vh;
    font-size: 14px;
    line-height: 1.45;
  }
  .num { font-variant-numeric: tabular-nums; }
  .svg-ic { width: 18px; height: 18px; flex-shrink: 0; display: inline-block; vertical-align: middle; }
  .svg-sm { width: 15px; height: 15px; flex-shrink: 0; display: inline-block; vertical-align: middle; }

  .app-shell { display: flex; min-height: 100vh; width: 100%; }
  .sidebar-rail {
    display: none;
    width: 224px;
    flex-shrink: 0;
    background: rgba(9, 14, 27, 0.96);
    border-right: 1px solid var(--border);
    padding: 18px 12px;
    flex-direction: column;
    justify-content: space-between;
    position: sticky;
    top: 0;
    height: 100vh;
    z-index: 30;
  }
  .sidebar-brand {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 10px 16px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 12px;
  }
  .brand-logo {
    width: 34px;
    height: 34px;
    border-radius: 10px;
    background: linear-gradient(135deg, rgba(56,189,248,0.22), rgba(129,140,248,0.22));
    border: 1px solid rgba(56,189,248,0.35);
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--accent);
  }
  .sidebar-links { display: flex; flex-direction: column; gap: 4px; }
  .sidebar-rail .nav-item {
    display: flex;
    flex-direction: row;
    align-items: center;
    justify-content: flex-start;
    gap: 10px;
    padding: 10px 12px;
    border-radius: 11px;
    font-size: 13px;
    font-weight: 600;
    color: var(--muted);
    background: transparent;
    border: 1px solid transparent;
    width: 100%;
    text-align: left;
  }
  .sidebar-rail .nav-item:hover { background: rgba(255,255,255,0.04); color: var(--text); }
  .sidebar-rail .nav-item.active {
    background: var(--accent-soft);
    color: var(--accent);
    border-color: rgba(56,189,248,0.28);
  }
  .sidebar-footer { padding-top: 12px; border-top: 1px solid var(--border); }

  .main-wrap { flex: 1; min-width: 0; display: flex; flex-direction: column; }
  .container { width: 100%; max-width: 1260px; margin: 0 auto; padding: 14px 14px 92px; }

  @media (min-width: 768px) {
    .sidebar-rail { display: flex; }
    .bottom-nav { display: none !important; }
    .container { padding: 20px 24px 32px; }
  }

  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    padding: 4px 2px 16px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 16px;
  }
  .os-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: rgba(56,189,248,0.12);
    color: var(--accent);
    border: 1px solid rgba(56,189,248,0.28);
    padding: 3px 10px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.2px;
  }
  .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--success);
    box-shadow: 0 0 8px var(--success);
    display: inline-block;
  }
  .title { font-size: 20px; font-weight: 800; letter-spacing: -0.35px; margin-top: 4px; }
  .subtitle { font-size: 12px; color: var(--muted); }

  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 15px;
    margin-bottom: 14px;
    box-shadow: 0 10px 30px rgba(2, 6, 23, 0.35);
    min-width: 0;
  }
  .card-title {
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.7px;
    color: var(--muted);
    font-weight: 700;
    margin-bottom: 12px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
  .card-title-left { display: inline-flex; align-items: center; gap: 7px; color: #cbd5e1; }

  .bento-metrics {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 10px;
    margin-bottom: 14px;
  }
  @media (min-width: 1024px) {
    .bento-metrics { grid-template-columns: repeat(4, 1fr); gap: 12px; }
  }
  .bento-2col { display: grid; grid-template-columns: 1fr; gap: 14px; }
  @media (min-width: 1024px) {
    .bento-2col { grid-template-columns: 1.35fr 1fr; align-items: start; }
  }
  .bento-pair { display: grid; grid-template-columns: 1fr; gap: 14px; }
  @media (min-width: 900px) {
    .bento-pair { grid-template-columns: repeat(2, 1fr); align-items: start; }
  }

  .grid-2 { display: grid; grid-template-columns: repeat(2, 1fr); gap: 9px; }
  .grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }
  .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 7px; }

  .stat-box {
    background: var(--card);
    border: 1px solid var(--border);
    padding: 13px;
    border-radius: 14px;
    min-width: 0;
  }
  .stat-label { font-size: 11px; color: var(--muted); font-weight: 700; letter-spacing: 0.4px; }
  .stat-row { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; margin: 4px 0 6px; }
  .stat-val { font-size: 20px; font-weight: 800; color: var(--text); }
  .bar-bg { height: 5px; background: rgba(255,255,255,0.07); border-radius: 99px; overflow: hidden; }
  .bar-fill { height: 100%; background: linear-gradient(90deg, var(--accent), var(--accent2)); border-radius: 99px; transition: width 0.35s ease; }
  .spark-wrap { width: 100%; height: 28px; margin-top: 7px; opacity: 0.92; }
  .spark-wrap svg { width: 100%; height: 100%; display: block; }

  button {
    background: rgba(255,255,255,0.055);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 11px;
    padding: 10px 12px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.14s ease, border-color 0.14s ease, transform 0.1s ease;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
  }
  button:hover { background: rgba(255,255,255,0.09); border-color: var(--border-strong); }
  button:active { transform: scale(0.97); }
  button:disabled { opacity: 0.55; cursor: not-allowed; }
  .btn-sm { padding: 5px 10px; font-size: 11px; border-radius: 8px; }
  .btn-primary { background: linear-gradient(135deg, #0ea5e9, #6366f1); border-color: transparent; color: #fff; }
  .btn-primary:hover { filter: brightness(1.08); background: linear-gradient(135deg, #0ea5e9, #6366f1); }
  .btn-danger { background: rgba(239,68,68,0.14); border-color: rgba(239,68,68,0.34); color: #fca5a5; }
  .btn-danger:hover { background: rgba(239,68,68,0.24); }
  .btn-success { background: rgba(16,185,129,0.14); border-color: rgba(16,185,129,0.34); color: #6ee7b7; }
  .btn-warn { background: rgba(245,158,11,0.14); border-color: rgba(245,158,11,0.35); color: #fcd34d; }

  .btn-os { justify-content: space-between; padding: 13px 14px; font-size: 13px; text-align: left; }
  .btn-arch { border-color: rgba(23,147,209,0.45); background: rgba(23,147,209,0.12); color: #7dd3fc; }
  .btn-cachyos { border-color: rgba(20,184,166,0.45); background: rgba(20,184,166,0.12); color: #5eead4; }
  .btn-garuda { border-color: rgba(245,158,11,0.45); background: rgba(245,158,11,0.12); color: #fcd34d; }
  .btn-gentoo { border-color: rgba(168,85,247,0.45); background: rgba(168,85,247,0.12); color: #d8b4fe; }
  .btn-nixos { border-color: rgba(96,165,250,0.45); background: rgba(96,165,250,0.12); color: #93c5fd; }

  .shot-wrap {
    position: relative;
    background: #020617;
    border-radius: 12px;
    overflow: hidden;
    border: 1px solid var(--border);
    min-height: 200px;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
  }
  .shot-wrap img { width: 100%; height: auto; display: block; object-fit: contain; max-height: 430px; }
  .shot-placeholder { color: var(--muted); font-size: 12px; padding: 28px; text-align: center; }

  input[type="range"] { width: 100%; accent-color: var(--accent); height: 6px; margin: 10px 0; background: transparent; cursor: pointer; }
  input[type="text"], input[type="email"], input[type="password"], select, textarea {
    width: 100%;
    background: rgba(2, 6, 23, 0.72);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 10px 12px;
    border-radius: 10px;
    outline: none;
    font-size: 13px;
  }
  select.compact-sel { width: auto; padding: 4px 8px; font-size: 11px; border-radius: 8px; }
  input:focus, select:focus, textarea:focus { border-color: var(--accent); }

  .badge-pill {
    display: inline-flex;
    align-items: center;
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 10px;
    font-weight: 700;
    background: rgba(148,163,184,0.13);
    color: #cbd5e1;
    border: 1px solid var(--border);
  }
  .pill-ok { background: rgba(16,185,129,0.14); color: #6ee7b7; border-color: rgba(16,185,129,0.3); }
  .pill-err { background: rgba(239,68,68,0.14); color: #fca5a5; border-color: rgba(239,68,68,0.3); }
  .pill-warn { background: rgba(245,158,11,0.14); color: #fcd34d; border-color: rgba(245,158,11,0.3); }

  .row-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 10px;
    padding: 9px 10px;
    background: var(--card-inner);
    border: 1px solid rgba(148,163,184,0.08);
    border-radius: 10px;
    margin-bottom: 6px;
  }
  .row-item-col { min-width: 0; flex: 1; }
  .row-title { font-weight: 600; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .row-sub { font-size: 11px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  .scroll-box {
    max-height: 360px;
    overflow-y: auto;
    background: rgba(2, 6, 23, 0.52);
    border: 1px solid var(--border);
    border-radius: 11px;
    padding: 6px;
  }
  .log-line {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 11px;
    line-height: 1.45;
    padding: 5px 8px;
    border-bottom: 1px solid rgba(255,255,255,0.05);
    word-break: break-word;
  }
  .log-err { color: #fca5a5; background: rgba(239,68,68,0.08); }
  .log-warn { color: #fde68a; background: rgba(245,158,11,0.07); }
  .log-info { color: #cbd5e1; }

  .touchpad-box {
    background: linear-gradient(180deg, rgba(15,23,42,0.9), rgba(2,6,23,0.95));
    border: 1px dashed rgba(56,189,248,0.38);
    border-radius: 14px;
    height: 160px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 6px;
    touch-action: none;
    user-select: none;
    cursor: crosshair;
    margin-bottom: 9px;
    color: var(--muted);
    font-size: 12px;
  }

  .term {
    background: #020617;
    border: 1px solid var(--border);
    padding: 10px;
    border-radius: 10px;
    font-family: ui-monospace, monospace;
    font-size: 11px;
    color: #93c5fd;
    max-height: 185px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-break: break-all;
    margin-top: 8px;
  }

  .tab-pane { display: none; animation: fadeIn 0.16s ease; }
  .tab-pane.active { display: block; }
  @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }

  .bottom-nav {
    position: fixed;
    bottom: 0;
    left: 0;
    right: 0;
    background: rgba(7, 11, 20, 0.94);
    backdrop-filter: blur(14px);
    border-top: 1px solid var(--border);
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    padding: 6px 4px calc(6px + env(safe-area-inset-bottom));
    z-index: 40;
  }
  .bottom-nav .nav-item {
    background: transparent;
    border: none;
    color: var(--muted);
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 3px;
    padding: 5px 2px;
    font-size: 10px;
    font-weight: 600;
    border-radius: 9px;
  }
  .bottom-nav .nav-item.active { color: var(--accent); background: rgba(56,189,248,0.1); }

  #toast {
    position: fixed;
    top: 16px;
    left: 50%;
    transform: translateX(-50%) translateY(-85px);
    background: #0f172a;
    border: 1px solid var(--accent);
    color: #fff;
    padding: 9px 18px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 600;
    z-index: 120;
    transition: transform 0.25s ease;
    box-shadow: 0 12px 30px rgba(0,0,0,0.6);
    pointer-events: none;
    max-width: 90vw;
    text-align: center;
  }
  #toast.show { transform: translateX(-50%) translateY(0); }

  .overlay-modal {
    position: fixed;
    inset: 0;
    background: rgba(4, 7, 15, 0.92);
    backdrop-filter: blur(14px);
    z-index: 100;
    display: none;
    align-items: center;
    justify-content: center;
    padding: 18px;
  }
  .modal-card {
    width: 100%;
    max-width: 390px;
    background: #0f172a;
    border: 1px solid var(--border-strong);
    border-radius: 20px;
    padding: 22px;
    box-shadow: 0 24px 60px rgba(0,0,0,0.7);
  }
  .shot-modal-inner {
    width: 100%;
    max-width: 1120px;
    max-height: 92vh;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .shot-modal-inner img {
    width: 100%;
    max-height: 82vh;
    object-fit: contain;
    border-radius: 12px;
    border: 1px solid var(--border);
    background: #020617;
  }
  .login-err { color: #fca5a5; font-size: 12px; min-height: 18px; margin: 8px 0 6px; text-align: center; }
</style>
</head>
<body>

<div id="toast"></div>

<div id="login-overlay" class="overlay-modal">
  <div class="modal-card" style="text-align:center">
    <div class="os-badge" style="margin-bottom:10px"><span class="dot"></span> <span id="login-badge-text">Mobile-RC Locked</span></div>
    <div class="title" style="margin-bottom:6px">Enter Access Code</div>
    <div class="subtitle" id="login-hint" style="margin-bottom:14px">Run <code>sudo control-access</code> on your PC/Laptop and enter the 6-digit RAC below.</div>
    <div id="email-otp-box" style="display:none;margin-bottom:12px;padding-bottom:12px;border-bottom:1px solid var(--border)">
      <input type="email" id="email-input" placeholder="Registered email address" autocomplete="email" style="margin-bottom:8px" onkeydown="handleEmailKey(event)">
      <button id="send-email-btn" onclick="requestEmailCode()" style="width:100%;margin-bottom:6px">Send Code to Email</button>
      <div id="email-otp-status" class="subtitle" style="min-height:16px"></div>
    </div>
    <input type="password" id="pin-input" inputmode="numeric" maxlength="16" placeholder="6-digit RAC" autocomplete="one-time-code" style="text-align:center;font-size:18px;letter-spacing:4px;margin-bottom:6px" oninput="onPinInput(this)" onkeydown="handlePinKey(event)">
    <div class="login-err" id="login-err"></div>
    <button class="btn-primary" style="width:100%" onclick="submitLogin()">Unlock Dashboard</button>
  </div>
</div>

<div id="power-modal" class="overlay-modal">
  <div class="modal-card">
    <div class="title" id="power-modal-title" style="font-size:17px;margin-top:0">Confirm Action</div>
    <div class="subtitle" id="power-modal-msg" style="margin:8px 0 18px;font-size:13px;line-height:1.5">Are you sure?</div>
    <div class="grid-2">
      <button onclick="closePowerModal()">Cancel</button>
      <button id="power-modal-confirm" class="btn-danger" onclick="execPowerConfirm()">Confirm</button>
    </div>
  </div>
</div>

<div id="shot-modal" class="overlay-modal" onclick="closeShotModal()">
  <div class="shot-modal-inner" onclick="stopModalBubble(event)">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:8px">
      <span class="os-badge"><span class="dot"></span> Fullscreen Live Desktop</span>
      <div style="display:flex;gap:8px">
        <button class="btn-sm" onclick="refreshScreenshot(false)">Refresh Frame</button>
        <button class="btn-sm btn-danger" onclick="closeShotModal()">Close</button>
      </div>
    </div>
    <img id="shot-modal-img" alt="Fullscreen Desktop View">
  </div>
</div>

<div class="app-shell">
  <aside class="sidebar-rail">
    <div>
      <div class="sidebar-brand">
        <div class="brand-logo">
          <svg class="svg-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
        </div>
        <div>
          <div style="font-weight:800;font-size:14px;letter-spacing:-0.2px">Mobile-RC</div>
          <div style="font-size:11px;color:var(--muted)" id="side-os-badge">Control Center</div>
        </div>
      </div>
      <div class="sidebar-links">
        <button class="nav-item active" data-tab="monitor" onclick="switchTab('monitor', this)">
          <svg class="svg-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v18h18"/><path d="M7 14l4-4 4 3 5-6"/></svg>
          <span>Monitor</span>
        </button>
        <button class="nav-item" data-tab="media" onclick="switchTab('media', this)">
          <svg class="svg-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="5.5" cy="17.5" r="2.5"/><circle cx="17.5" cy="15.5" r="2.5"/><path d="M8 17.5V6l12-2v11.5"/></svg>
          <span>Media &amp; Display</span>
        </button>
        <button class="nav-item" data-tab="boot" onclick="switchTab('boot', this)">
          <svg class="svg-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg>
          <span>Boot &amp; Power</span>
        </button>
        <button class="nav-item" data-tab="remote" onclick="switchTab('remote', this)">
          <svg class="svg-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M6 10h.01M10 10h.01M14 10h.01M18 10h.01M8 14h8"/></svg>
          <span>Remote &amp; Shell</span>
        </button>
        <button class="nav-item" data-tab="logs" onclick="switchTab('logs', this)">
          <svg class="svg-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"/><line x1="7" y1="9" x2="17" y2="9"/><line x1="7" y1="13" x2="14" y2="13"/><line x1="7" y1="17" x2="11" y2="17"/></svg>
          <span>System &amp; Procs</span>
        </button>
        <button class="nav-item" data-tab="network" onclick="switchTab('network', this)">
          <svg class="svg-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><line x1="3.6" y1="9" x2="20.4" y2="9"/><line x1="3.6" y1="15" x2="20.4" y2="15"/><path d="M12 3a14.5 14.5 0 0 0 0 18 14.5 14.5 0 0 0 0-18"/></svg>
          <span>Network &amp; Files</span>
        </button>
      </div>
    </div>
    <div class="sidebar-footer">
      <button class="btn-danger" style="width:100%" onclick="doLogout()">
        <svg class="svg-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        <span>Lock Session</span>
      </button>
    </div>
  </aside>

  <div class="main-wrap">
    <div class="container">
      <div class="header">
        <div>
          <div class="os-badge" id="os-badge"><span class="dot"></span> <span id="os-name">Loading...</span></div>
          <div class="title" id="hostname">Mobile-RC</div>
          <div class="subtitle num" id="kernel-uptime">Kernel - | Uptime -</div>
        </div>
        <div style="text-align:right">
          <div class="num" style="font-size:20px;font-weight:800" id="bat-top">--</div>
          <div class="subtitle" id="bat-status">Power</div>
          <button id="logout-btn" onclick="doLogout()" class="btn-sm" style="margin-top:6px">Lock</button>
        </div>
      </div>

      <!-- TAB 1: MONITOR -->
      <div id="tab-monitor" class="tab-pane active">
        <div class="bento-metrics">
          <div class="stat-box">
            <div class="stat-label">CPU LOAD</div>
            <div class="stat-row"><span class="stat-val num" id="cpu-val">0%</span><span class="badge-pill num" id="cpu-peak">Peak 0%</span></div>
            <div class="bar-bg"><div class="bar-fill" id="cpu-bar" style="width:0%"></div></div>
            <div class="spark-wrap" id="cpu-spark"></div>
          </div>
          <div class="stat-box">
            <div class="stat-label">TEMPERATURE</div>
            <div class="stat-row"><span class="stat-val num" id="temp-val">0°C</span><span class="badge-pill" id="temp-sub">Thermal</span></div>
            <div class="bar-bg"><div class="bar-fill" id="temp-bar" style="width:0%"></div></div>
          </div>
          <div class="stat-box">
            <div class="stat-label">MEMORY (RAM)</div>
            <div class="stat-row"><span class="stat-val num" id="ram-val">0 GB</span><span class="badge-pill num" id="ram-pct">0%</span></div>
            <div class="bar-bg"><div class="bar-fill" id="ram-bar" style="width:0%"></div></div>
          </div>
          <div class="stat-box" id="stat-power-card">
            <div class="stat-label" id="bat-label">POWER / GPU</div>
            <div class="stat-row"><span class="stat-val num" id="bat-val">--</span></div>
            <div class="subtitle num" style="font-size:11px;margin-bottom:5px" id="bat-sub">Swap: -- | Net: --</div>
            <div class="bar-bg"><div class="bar-fill" id="bat-bar" style="width:0%"></div></div>
            <div class="spark-wrap" id="net-spark"></div>
          </div>
        </div>

        <div class="bento-2col">
          <div class="card">
            <div class="card-title">
              <span class="card-title-left">
                <svg class="svg-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>
                <span>Live Desktop Screen</span>
              </span>
              <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">
                <select id="live-interval" class="compact-sel" onchange="changeLiveInterval(this.value)">
                  <option value="0">Off</option>
                  <option value="1000">1s</option>
                  <option value="2000" selected>2s</option>
                  <option value="5000">5s</option>
                </select>
                <button id="live-btn" class="btn-sm" onclick="toggleLiveMonitor()">Live ON</button>
                <button class="btn-sm" onclick="refreshScreenshot(false)">Refresh</button>
                <button class="btn-sm" onclick="openShotModal()">Expand</button>
              </div>
            </div>
            <div class="shot-wrap" onclick="openShotModal()">
              <span class="shot-placeholder" id="shot-placeholder">Loading live desktop screen...</span>
              <img id="live-shot" style="display:none" alt="Live Desktop View">
            </div>
            <div class="grid-3" style="margin-top:10px">
              <button class="btn-sm" onclick="doAction('hypr', 'fullscreen')">Fullscreen</button>
              <button class="btn-sm" onclick="doAction('hypr', 'dpms_toggle')">Display Sleep</button>
              <button class="btn-sm btn-danger" onclick="doAction('hypr', 'killactive')">Close Active</button>
            </div>
          </div>

          <div>
            <div class="card">
              <div class="card-title">
                <span class="card-title-left">
                  <svg class="svg-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/></svg>
                  <span>Workspaces</span>
                </span>
              </div>
              <div class="grid-4" id="ws-list"></div>
            </div>

            <div class="card">
              <div class="card-title">
                <span class="card-title-left">
                  <svg class="svg-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/><path d="M3 12c0 1.66 4 3 9 3s9-1.34 9-3"/></svg>
                  <span>Disk Partitions</span>
                </span>
                <button class="btn-sm" onclick="refreshFullStatus(true)">Refresh</button>
              </div>
              <div id="disk-list"><div class="subtitle">Scanning storage...</div></div>
            </div>
          </div>
        </div>
      </div>

      <!-- TAB 2: MEDIA & DISPLAY -->
      <div id="tab-media" class="tab-pane">
        <div class="bento-pair">
          <div class="card">
            <div class="card-title"><span>Media Playback</span><span class="badge-pill" id="media-st">Stopped</span></div>
            <div style="padding:12px;background:var(--card-inner);border-radius:12px;margin-bottom:12px;border:1px solid var(--border)">
              <div style="font-size:15px;font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" id="media-title">No media active</div>
            </div>
            <div class="grid-3">
              <button onclick="doMedia('prev')">Prev</button>
              <button class="btn-primary" onclick="doMedia('play-pause')">Play / Pause</button>
              <button onclick="doMedia('next')">Next</button>
            </div>
          </div>

          <div class="card">
            <div class="card-title"><span>Audio Volume</span><span id="vol-label" class="num" style="color:var(--accent);font-weight:800">50%</span></div>
            <input type="range" id="vol-slider" min="0" max="150" value="50" onchange="doMedia('vol_set', this.value)" oninput="previewSlider('vol-label', this.value)">
            <div class="grid-3">
              <button onclick="doMedia('vol_down')">-5%</button>
              <button onclick="doMedia('mute')">Mute Toggle</button>
              <button onclick="doMedia('vol_up')">+5%</button>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-title"><span>Screen Brightness</span><span id="bright-label" class="num" style="color:var(--accent);font-weight:800">50%</span></div>
          <input type="range" id="bright-slider" min="5" max="100" value="50" onchange="doMedia('bright_set', this.value)" oninput="previewSlider('bright-label', this.value)">
          <div class="grid-2">
            <button onclick="doMedia('bright_down')">Dim (-10%)</button>
            <button onclick="doMedia('bright_up')">Brighten (+10%)</button>
          </div>
        </div>
      </div>

      <!-- TAB 3: BOOT, OS & POWER -->
      <div id="tab-boot" class="tab-pane">
        <div class="bento-pair">
          <div class="card">
            <div class="card-title">
              <span>Installed Operating Systems</span>
              <div style="display:flex;gap:6px">
                <button class="btn-sm" onclick="loadDistros(false, true)">Refresh</button>
                <button class="btn-sm" id="btn-deep-scan" onclick="loadDistros(true, true)" style="border-color:rgba(56,189,248,0.45)">Deep Probe</button>
              </div>
            </div>
            <div class="subtitle" id="distro-host-summary" style="margin-bottom:10px">Inspecting host OS environment...</div>
            <div id="distro-list" style="display:flex;flex-direction:column;gap:6px">Loading OS inventory...</div>
          </div>

          <div>
            <div class="card">
              <div class="card-title"><span>UEFI Boot Switcher (Next Boot)</span></div>
              <div style="display:flex;flex-direction:column;gap:8px" id="boot-list">
                <div class="subtitle">Loading UEFI firmware entries...</div>
              </div>
            </div>

            <div class="card">
              <div class="card-title"><span>Power &amp; Session Controls</span></div>
              <div class="grid-2">
                <button onclick="doPower('lock')">Lock Screen</button>
                <button onclick="doPower('suspend')">Sleep / Suspend</button>
                <button class="btn-primary" onclick="confirmBoot('reboot', 'Reboot Host System')">Reboot PC</button>
                <button class="btn-danger" onclick="confirmBoot('poweroff', 'Power Off Host System')">Shutdown PC</button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- TAB 4: REMOTE CONTROL & SHELL -->
      <div id="tab-remote" class="tab-pane">
        <div class="bento-pair">
          <div class="card">
            <div class="card-title"><span>Remote Touchpad &amp; Keys</span><span class="badge-pill" id="tp-status">Ready</span></div>
            <div id="touchpad-surface" class="touchpad-box">
              <svg class="svg-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M5 3l14 9-6.5 1.5L10 20 5 3z"/></svg>
              <span>Drag to move cursor | Tap to left-click</span>
            </div>
            <div class="grid-3" style="margin-bottom:8px">
              <button class="btn-sm" onclick="sendRemoteClick('left')">Left Click</button>
              <button class="btn-sm" onclick="sendRemoteClick('middle')">Middle</button>
              <button class="btn-sm" onclick="sendRemoteClick('right')">Right Click</button>
            </div>
            <div class="grid-2" style="margin-bottom:8px">
              <button class="btn-sm" onclick="sendRemoteScroll(-3)">Scroll Up</button>
              <button class="btn-sm" onclick="sendRemoteScroll(3)">Scroll Down</button>
            </div>
            <div class="grid-4">
              <button class="btn-sm" onclick="sendRemoteKey('Escape')">Esc</button>
              <button class="btn-sm" onclick="sendRemoteKey('Up')">Up</button>
              <button class="btn-sm" onclick="sendRemoteKey('BackSpace')">Back</button>
              <button class="btn-sm" onclick="sendRemoteKey('Return')">Enter</button>
              <button class="btn-sm" onclick="sendRemoteKey('Left')">Left</button>
              <button class="btn-sm" onclick="sendRemoteKey('Down')">Down</button>
              <button class="btn-sm" onclick="sendRemoteKey('Right')">Right</button>
              <button class="btn-sm" onclick="sendRemoteKey('space')">Space</button>
            </div>
          </div>

          <div>
            <div class="card">
              <div class="card-title"><span>Clipboard, Notification &amp; URL</span></div>
              <input type="text" id="msg-input" placeholder="Message, text snippet, or https:// URL..." style="margin-bottom:9px">
              <div class="grid-3">
                <button class="btn-primary" onclick="sendInput('notify')">Notify</button>
                <button onclick="sendInput('clipboard')">Copy to PC</button>
                <button onclick="sendInput('open_url')">Open URL</button>
              </div>
            </div>

            <div class="card">
              <div class="card-title"><span>Quick Application Launcher</span></div>
              <div class="grid-2">
                <button onclick="doAction('launch', 'terminal')">Open Terminal</button>
                <button onclick="doAction('launch', 'youtube')">Open YouTube</button>
                <button onclick="doAction('launch', 'files')">File Manager</button>
                <button onclick="doAction('launch', 'btop')">System Monitor</button>
              </div>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-title"><span>Quick Web Terminal</span></div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px">
            <input type="text" id="cmd-input" style="flex:1;min-width:190px" placeholder="Command (e.g. df -h, uname -a, ip addr)..." onkeydown="handleCmdKey(event)">
            <button class="btn-primary" onclick="runTerminal('shell')">Run Silent</button>
            <button onclick="runTerminal('shell_gui')" style="border-color:rgba(56,189,248,0.45)">Open on Screen</button>
            <button onclick="runTerminal('shell_type')">Type to Active</button>
          </div>
          <label style="display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted);cursor:pointer">
            <input type="checkbox" id="cmd-auto-enter" checked style="width:auto">
            <span>Auto-Enter when typing into active desktop window</span>
          </label>
          <pre class="term" id="term-out">Ready to execute commands or type prompts to host...</pre>
        </div>
      </div>

      <!-- TAB 5: SYSTEM LOGS, PROCESSES & SERVICES -->
      <div id="tab-logs" class="tab-pane">
        <div class="card">
          <div class="card-title">
            <span>System Logs &amp; Audit Events</span>
            <div style="display:flex;gap:6px;align-items:center">
              <span class="badge-pill" id="logs-init-badge">init: --</span>
              <button class="btn-sm" onclick="loadLogs()">Refresh</button>
            </div>
          </div>
          <div class="grid-2" style="margin-bottom:8px">
            <select id="log-source" onchange="loadLogs()">
              <option value="all">All Sources</option>
              <option value="mobile-rc">Mobile-RC Audit</option>
            </select>
            <select id="log-level" onchange="loadLogs()">
              <option value="all">All Severities</option>
              <option value="err">Errors Only</option>
              <option value="warn">Warnings &amp; Errors</option>
            </select>
          </div>
          <div style="display:flex;gap:8px;margin-bottom:10px">
            <input type="text" id="log-query" placeholder="Filter log message..." onkeydown="handleLogQueryKey(event)">
            <button onclick="loadLogs()">Filter</button>
          </div>
          <div id="logs-list" class="scroll-box" style="padding:0">
            <div class="subtitle" style="padding:12px">Loading host logs...</div>
          </div>
        </div>

        <div class="bento-pair">
          <div class="card">
            <div class="card-title">
              <span>Top Processes</span>
              <button class="btn-sm" onclick="loadProcesses()">Refresh</button>
            </div>
            <div id="proc-list" class="scroll-box">
              <div class="subtitle" style="padding:10px">Open tab or click Refresh to inspect processes...</div>
            </div>
          </div>

          <div class="card">
            <div class="card-title">
              <span>Host Services</span>
              <button class="btn-sm" onclick="loadServices()">Refresh</button>
            </div>
            <input type="text" id="svc-filter" placeholder="Search service name..." style="margin-bottom:8px" oninput="filterServices()">
            <div id="svc-list" class="scroll-box">
              <div class="subtitle" style="padding:10px">Open tab or click Refresh to inspect services...</div>
            </div>
          </div>
        </div>
      </div>

      <!-- TAB 6: NETWORK, DEVICES, FILES & FEEDBACK -->
      <div id="tab-network" class="tab-pane">
        <div class="bento-pair">
          <div class="card">
            <div class="card-title">
              <span>LAN Addresses &amp; Wake-on-LAN MACs</span>
              <button class="btn-sm" onclick="refreshFullStatus(true)">Refresh</button>
            </div>
            <div id="lan-info-box"><div class="subtitle">Loading interface addresses...</div></div>
          </div>

          <div class="card">
            <div class="card-title">
              <span>Paired Mobile Devices</span>
              <button class="btn-sm" onclick="loadDevices()">Refresh</button>
            </div>
            <div id="devices-list"><div class="subtitle">Loading paired devices...</div></div>
          </div>
        </div>

        <div class="bento-pair">
          <div class="card">
            <div class="card-title"><span>Remote HTTPS Tunnel (Opt-In)</span></div>
            <p class="subtitle" style="margin-bottom:10px">Disabled by default. Enable only when connecting outside your LAN; RAC / PIN login remains mandatory.</p>
            <div id="tunnel-box" style="background:var(--card-inner);padding:11px;border-radius:11px;border:1px solid var(--border);margin-bottom:10px;word-break:break-all;font-size:12px">
              Status: <b id="tunnel-status">Checking...</b>
              <div id="tunnel-url-wrap" style="margin-top:6px;display:none">
                Public URL: <a id="tunnel-link" href="#" target="_blank" rel="noopener noreferrer" style="color:var(--accent);font-weight:700"></a>
              </div>
            </div>
            <div class="grid-2">
              <button class="btn-success" onclick="toggleTunnel('start')">Start Tunnel</button>
              <button class="btn-danger" onclick="toggleTunnel('stop')">Stop Tunnel</button>
            </div>
          </div>

          <div class="card">
            <div class="card-title"><span>Upload File to Host Downloads</span></div>
            <input type="file" id="file-upload" style="margin-bottom:10px;font-size:12px">
            <button class="btn-primary" style="width:100%" onclick="uploadFile()">Upload to PC Now</button>
          </div>
        </div>

        <div class="bento-pair">
          <div class="card">
            <div class="card-title">
              <span>Download Files from Host</span>
              <button class="btn-sm" onclick="loadFiles()">Refresh</button>
            </div>
            <div id="file-list" class="scroll-box" style="max-height:280px"><div class="subtitle" style="padding:10px">Loading files...</div></div>
          </div>

          <div class="card">
            <div class="card-title">
              <span>Feedback &amp; Bug Reports</span>
              <span class="badge-pill">brypra4@gmail.com</span>
            </div>
            <div style="display:flex;flex-direction:column;gap:8px">
              <select id="fb-category">
                <option value="suggestion">Suggestion / Feature Idea</option>
                <option value="bug">Bug Report</option>
                <option value="other">Other Question / Feedback</option>
              </select>
              <input type="text" id="fb-subject" maxlength="120" placeholder="Short summary / subject">
              <input type="email" id="fb-reply" maxlength="120" placeholder="Your email (optional, for reply)">
              <textarea id="fb-message" rows="3" maxlength="4000" placeholder="Describe your suggestion, issue, or reproduction steps..."></textarea>
              <label style="display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted);cursor:pointer">
                <input type="checkbox" id="fb-sysinfo" checked style="width:auto">
                <span>Attach host OS / init / compositor info (no IPs or tokens)</span>
              </label>
              <button class="btn-primary" onclick="submitFeedback()" id="fb-submit-btn">Send Feedback</button>
            </div>
            <div id="fb-status" style="font-size:12px;margin-top:8px;color:var(--muted)"></div>
            <div id="fb-fallbacks" style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px"></div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<nav class="bottom-nav">
  <button class="nav-item active" data-tab="monitor" onclick="switchTab('monitor', this)">
    <svg class="svg-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 3v18h18"/><path d="M7 14l4-4 4 3 5-6"/></svg>
    <span>Monitor</span>
  </button>
  <button class="nav-item" data-tab="media" onclick="switchTab('media', this)">
    <svg class="svg-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="5.5" cy="17.5" r="2.5"/><circle cx="17.5" cy="15.5" r="2.5"/><path d="M8 17.5V6l12-2v11.5"/></svg>
    <span>Media</span>
  </button>
  <button class="nav-item" data-tab="boot" onclick="switchTab('boot', this)">
    <svg class="svg-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg>
    <span>Boot</span>
  </button>
  <button class="nav-item" data-tab="remote" onclick="switchTab('remote', this)">
    <svg class="svg-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M8 14h8"/></svg>
    <span>Remote</span>
  </button>
  <button class="nav-item" data-tab="logs" onclick="switchTab('logs', this)">
    <svg class="svg-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="4" width="18" height="16" rx="2"/><line x1="7" y1="9" x2="17" y2="9"/><line x1="7" y1="14" x2="13" y2="14"/></svg>
    <span>System</span>
  </button>
  <button class="nav-item" data-tab="network" onclick="switchTab('network', this)">
    <svg class="svg-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><line x1="3.6" y1="9" x2="20.4" y2="9"/><line x1="3.6" y1="15" x2="20.4" y2="15"/></svg>
    <span>Network</span>
  </button>
</nav>

<script>
let _activeTab = 'monitor';
let _liveEnabled = true;
let _liveIntervalMs = 2000;
let _liveTimer = null;
let _shotInFlight = false;
let _liveShotUrl = null;
let _cachedBootEntries = null;
let _authenticated = false;
let _csrfToken = '';
let _pollTimer = null;
let _lastWsSig = '';
let _lastDiskSig = '';
let _cpuHist = [];
let _netHist = [];
let _servicesCache = [];
let _pendingModal = null;
let _pinMode = 'on_demand';
let _loginBusy = false;

function handleEmailKey(e) { if (e && e.key === 'Enter') requestEmailCode(); }
function handlePinKey(e) { if (e && e.key === 'Enter') submitLogin(); }
function handleCmdKey(e) { if (e && e.key === 'Enter') runTerminal('shell'); }
function handleLogQueryKey(e) { if (e && e.key === 'Enter') loadLogs(); }
function stopModalBubble(e) { if (e) e.stopPropagation(); }

function previewSlider(labelId, val) {
  const el = document.getElementById(labelId);
  if (el) el.textContent = String(val) + '%';
}

function toast(msg) {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2600);
}

function showLogin(msg = '') {
  _authenticated = false;
  if (_pollTimer) { clearTimeout(_pollTimer); _pollTimer = null; }
  if (_liveTimer) { clearTimeout(_liveTimer); _liveTimer = null; }
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

function scheduleTelemetryPoll(delayMs = 3500) {
  if (_pollTimer) { clearTimeout(_pollTimer); _pollTimer = null; }
  if (_authenticated && !document.hidden) {
    _pollTimer = setTimeout(async () => {
      await refreshTelemetry();
      scheduleTelemetryPoll(3500);
    }, delayMs);
  }
}

function hideLogin() {
  _authenticated = true;
  _lastWsSig = '';
  _lastDiskSig = '';
  document.getElementById('login-err').textContent = '';
  document.getElementById('pin-input').value = '';
  document.getElementById('login-overlay').style.display = 'none';
  updateLiveButton();
  refreshFullStatus(false);
  scheduleTelemetryPoll(3500);
  refreshScreenshot(true);
}

function onPinInput(el) {
  if (!el) return;
  if (_pinMode !== 'static') {
    const digits = el.value.replace(/\D+/g, '').slice(0, 6);
    if (el.value !== digits) el.value = digits;
    if (digits.length === 6 && !_loginBusy) submitLogin();
  }
}

async function initAuth() {
  const urlParams = new URLSearchParams(window.location.search);
  const hashParams = new URLSearchParams(window.location.hash.replace(/^#/, ''));
  const handoff = (urlParams.get('handoff') || hashParams.get('handoff') || '').trim();
  const autoRac = (urlParams.get('rac') || hashParams.get('rac') || '').trim();
  if (handoff || autoRac) window.history.replaceState(null, '', window.location.pathname);
  try {
    const r = await fetch('/api/auth/status', { credentials: 'same-origin' });
    const d = await r.json();
    if (d && d.pin_mode) _pinMode = d.pin_mode;
    const hint = document.getElementById('login-hint');
    const badge = document.getElementById('login-badge-text');
    const emailBox = document.getElementById('email-otp-box');
    const emailStatus = document.getElementById('email-otp-status');
    if (d && d.is_non_local) {
      if (badge) badge.textContent = 'Mobile-RC • Online Access';
      if (d.email_otp_enabled) {
        if (emailBox) emailBox.style.display = 'block';
        if (hint) hint.textContent = 'External network detected. Request a 6-digit RAC via your registered email (auto-unlocks on 6th digit).';
      } else {
        if (emailBox) emailBox.style.display = 'none';
        if (hint) hint.textContent = 'External network detected. Configure Email OTP on host via: control-access --setup-email';
      }
    } else {
      if (badge) badge.textContent = 'Mobile-RC • Local LAN';
      if (emailBox) emailBox.style.display = 'none';
      if (hint) {
        hint.textContent = (d && d.pin_mode === 'static')
          ? 'Enter the static PIN configured in pin.txt on your host.'
          : 'Local LAN: run control-access on your host and enter the 6-digit RAC below.';
      }
    }
    if (emailStatus) emailStatus.textContent = '';
    if (d && d.authenticated && d.csrf_token) {
      _csrfToken = d.csrf_token;
      hideLogin();
      return;
    }
    if (handoff) {
      const hr = await fetch('/api/login', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ handoff_token: handoff }),
      });
      const hd = await hr.json();
      if (hr.ok && hd.ok && hd.csrf_token) {
        _csrfToken = hd.csrf_token;
        hideLogin();
        toast('Unlocked!');
        return;
      }
    }
    if (autoRac && /^\d{6}$/.test(autoRac)) {
      const pinEl = document.getElementById('pin-input');
      if (pinEl) {
        pinEl.value = autoRac;
        await submitLogin();
        if (_authenticated) return;
      }
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
    if (statusEl) { statusEl.style.color = '#fca5a5'; statusEl.textContent = 'Please enter a valid email address.'; }
    return;
  }
  if (btn) btn.disabled = true;
  if (statusEl) { statusEl.style.color = 'var(--muted)'; statusEl.textContent = 'Sending verification code...'; }
  try {
    const r = await fetch('/api/pairing/email-code', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    const d = await r.json();
    if (r.ok && d.ok) {
      if (statusEl) { statusEl.style.color = 'var(--success)'; statusEl.textContent = d.message || 'Check your inbox for the 6-digit code.'; }
      const pinInp = document.getElementById('pin-input');
      if (pinInp) pinInp.focus();
    } else if (statusEl) {
      statusEl.style.color = '#fca5a5';
      statusEl.textContent = d.message || 'Could not send email code.';
    }
  } catch (e) {
    if (statusEl) { statusEl.style.color = '#fca5a5'; statusEl.textContent = 'Connection error while sending email code.'; }
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function submitLogin() {
  if (_loginBusy) return;
  const pin = document.getElementById('pin-input').value.trim();
  const errEl = document.getElementById('login-err');
  if (!pin) { errEl.textContent = 'Please enter your access code.'; return; }
  _loginBusy = true;
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
  } finally {
    _loginBusy = false;
  }
}

async function doLogout() {
  try { await api('/api/logout', 'POST', {}); } catch (e) {}
  _cachedBootEntries = null;
  showLogin('Locked');
}

function switchTab(name, btn) {
  _activeTab = name;
  document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.tab === name);
  });
  const pane = document.getElementById('tab-' + name);
  if (pane) pane.classList.add('active');
  if (name === 'monitor') {
    if (_liveEnabled && _liveIntervalMs > 0 && _authenticated) refreshScreenshot(true);
  } else if (_liveTimer) {
    clearTimeout(_liveTimer);
    _liveTimer = null;
  }
  if (name === 'boot') loadDistros(false, false);
  if (name === 'logs') { loadLogs(); loadProcesses(); loadServices(); }
  if (name === 'network') { loadFiles(); loadDevices(); }
}

document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    if (_pollTimer) { clearTimeout(_pollTimer); _pollTimer = null; }
    if (_liveTimer) { clearTimeout(_liveTimer); _liveTimer = null; }
  } else if (_authenticated) {
    refreshTelemetry();
    scheduleTelemetryPoll(3500);
    if (_activeTab === 'monitor' && _liveEnabled && _liveIntervalMs > 0) refreshScreenshot(true);
  }
});

async function api(path, method = 'GET', body = null) {
  const opts = { method, credentials: 'same-origin', headers: {} };
  if (method !== 'GET' && _csrfToken) opts.headers['X-CSRF-Token'] = _csrfToken;
  if (body !== null) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(path, opts);
  if (r.status === 401) {
    showLogin('Session expired. Enter access code again.');
    throw new Error('Unauthorized');
  }
  return await r.json();
}

function renderSparkline(containerId, values, maxFloor, colorHex) {
  const wrap = document.getElementById(containerId);
  if (!wrap || !values.length) return;
  const maxVal = Math.max(maxFloor, ...values);
  const w = 120;
  const h = 28;
  const n = values.length;
  const pts = values.map((v, idx) => {
    const x = n === 1 ? w : Math.round((idx / (n - 1)) * w * 10) / 10;
    const y = Math.round((h - 2 - (Math.max(0, v) / maxVal) * (h - 5)) * 10) / 10;
    return x + ',' + y;
  });
  wrap.textContent = '';
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 120 28');
  svg.setAttribute('preserveAspectRatio', 'none');
  const polyArea = document.createElementNS(ns, 'polygon');
  polyArea.setAttribute('fill', colorHex);
  polyArea.setAttribute('fill-opacity', '0.16');
  polyArea.setAttribute('points', '0,28 ' + pts.join(' ') + ' ' + w + ',28');
  const polyLine = document.createElementNS(ns, 'polyline');
  polyLine.setAttribute('fill', 'none');
  polyLine.setAttribute('stroke', colorHex);
  polyLine.setAttribute('stroke-width', '1.8');
  polyLine.setAttribute('stroke-linejoin', 'round');
  polyLine.setAttribute('points', pts.join(' '));
  svg.appendChild(polyArea);
  svg.appendChild(polyLine);
  wrap.appendChild(svg);
}

function applyTelemetryData(d) {
  if (!d || !d.os) return;
  document.getElementById('os-name').textContent = d.os.name;
  document.getElementById('side-os-badge').textContent = d.os.name + ' (' + (d.init_system || 'host') + ')';
  document.getElementById('hostname').textContent = d.os.hostname;
  document.getElementById('kernel-uptime').textContent = d.os.kernel + ' | Up ' + d.os.uptime;

  const cpuPct = Number(d.cpu_pct || 0);
  _cpuHist.push(cpuPct);
  if (_cpuHist.length > 30) _cpuHist.shift();
  const peakCpu = Math.round(Math.max(..._cpuHist));
  document.getElementById('cpu-val').textContent = cpuPct + '%';
  document.getElementById('cpu-peak').textContent = 'Peak ' + peakCpu + '%';
  document.getElementById('cpu-bar').style.width = Math.min(100, cpuPct) + '%';
  renderSparkline('cpu-spark', _cpuHist, 100, '#38bdf8');

  document.getElementById('temp-val').textContent = d.cpu_temp + '°C';
  document.getElementById('temp-bar').style.width = Math.min(100, Number(d.cpu_temp || 0)) + '%';

  document.getElementById('ram-val').textContent = d.ram.used_gb + '/' + d.ram.total_gb + ' GB';
  document.getElementById('ram-pct').textContent = d.ram.percent + '%';
  document.getElementById('ram-bar').style.width = d.ram.percent + '%';

  const bat = d.battery || {};
  const gpu = d.gpu || {};
  const swap = d.swap || {};
  const net = d.network || {};
  const batLabelEl = document.getElementById('bat-label');
  const batSubEl = document.getElementById('bat-sub');
  const batBarEl = document.getElementById('bat-bar');
  if (bat.percent !== null && bat.percent !== undefined) {
    batLabelEl.textContent = bat.has_ups ? 'UPS BACKUP' : 'BATTERY LEVEL';
    document.getElementById('bat-val').textContent = bat.percent + '%';
    batBarEl.style.width = bat.percent + '%';
    document.getElementById('bat-top').textContent = (bat.plugged ? 'AC ' : '') + bat.percent + '%';
    document.getElementById('bat-status').textContent = bat.status || 'Battery';
  } else {
    batLabelEl.textContent = gpu.available ? 'DESKTOP / GPU' : 'HOST POWER';
    let gpuVal = 'AC';
    let barPct = 100;
    if (gpu.busy_pct !== null && gpu.busy_pct !== undefined) {
      gpuVal = gpu.busy_pct + '%';
      barPct = Math.max(0, Math.min(100, gpu.busy_pct));
    } else if (gpu.temp_c !== null && gpu.temp_c !== undefined) {
      gpuVal = gpu.temp_c + '°C';
      barPct = Math.min(100, Math.round(gpu.temp_c));
    }
    document.getElementById('bat-val').textContent = gpuVal;
    batBarEl.style.width = barPct + '%';
    document.getElementById('bat-top').textContent = 'AC';
    document.getElementById('bat-status').textContent = (gpu.temp_c !== null && gpu.temp_c !== undefined) ? (gpu.temp_c + '°C GPU') : (bat.status || 'AC Host');
  }
  const rx = Number(net.rx_kbps || 0);
  const tx = Number(net.tx_kbps || 0);
  _netHist.push(Math.round((rx + tx) * 10) / 10);
  if (_netHist.length > 30) _netHist.shift();
  const swapTxt = (swap.total_gb > 0) ? ('Swap ' + swap.used_gb + '/' + swap.total_gb + 'GB') : 'Swap off';
  if (batSubEl) batSubEl.textContent = swapTxt + ' | RX ' + rx + ' / TX ' + tx + ' KiB/s';
  renderSparkline('net-spark', _netHist, 64, '#10b981');

  if (d.media) {
    document.getElementById('vol-label').textContent = (d.media.muted ? 'MUTED ' : '') + d.media.volume + '%';
    document.getElementById('vol-slider').value = d.media.volume;
    document.getElementById('bright-label').textContent = d.media.brightness + '%';
    document.getElementById('bright-slider').value = d.media.brightness;
    document.getElementById('media-st').textContent = d.media.media_status;
    document.getElementById('media-title').textContent = d.media.media_title;
  }

  const wsEl = document.getElementById('ws-list');
  if (wsEl) {
    const wsList = Array.isArray(d.workspaces) && d.workspaces.length
      ? d.workspaces
      : [{ id: 1, name: '1', active: true }, { id: 2, name: '2', active: false }, { id: 3, name: '3', active: false }, { id: 4, name: '4', active: false }];
    const wsSig = wsList.map(w => w.id + ':' + (w.name || w.id) + ':' + (w.active ? 1 : 0)).join('|');
    if (wsSig !== _lastWsSig) {
      _lastWsSig = wsSig;
      wsEl.style.gridTemplateColumns = 'repeat(' + (wsList.length <= 4 ? wsList.length : 4) + ', 1fr)';
      wsEl.textContent = '';
      for (const w of wsList) {
        const b = document.createElement('button');
        b.className = w.active ? 'btn-sm btn-primary' : 'btn-sm';
        b.textContent = (w.name && String(w.name) !== String(w.id)) ? ('WS ' + w.id + ' (' + w.name + ')') : ('WS ' + w.id);
        b.addEventListener('click', () => doAction('ws', String(w.id)));
        wsEl.appendChild(b);
      }
    }
  }

  const dl = document.getElementById('disk-list');
  if (dl && Array.isArray(d.disks)) {
    const diskSig = d.disks.map(x => x.part + ':' + x.use_pct + ':' + x.size + ':' + (x.mounted ? 1 : 0)).join('|');
    if (diskSig !== _lastDiskSig) {
      _lastDiskSig = diskSig;
      dl.textContent = '';
      if (d.disks.length) {
        for (const x of d.disks) {
          const row = document.createElement('div');
          row.className = 'row-item';
          const col = document.createElement('div');
          col.className = 'row-item-col';
          const title = document.createElement('div');
          title.className = 'row-title';
          title.textContent = x.label + ' (' + x.part + ')';
          const sub = document.createElement('div');
          sub.className = 'row-sub';
          sub.textContent = (x.fstype || 'disk') + ' | ' + x.size + (x.mountpoint ? (' | ' + x.mountpoint) : '');
          col.appendChild(title);
          col.appendChild(sub);
          const pill = document.createElement('span');
          pill.className = 'badge-pill num ' + (x.mounted ? 'pill-ok' : '');
          pill.textContent = x.use_pct || '--';
          row.appendChild(col);
          row.appendChild(pill);
          dl.appendChild(row);
        }
      } else {
        const empty = document.createElement('div');
        empty.className = 'subtitle';
        empty.textContent = 'No storage partitions detected.';
        dl.appendChild(empty);
      }
    }
  }

  if (d.boot_entries && (!_cachedBootEntries || d.boot_entries.length)) {
    const sameBoot = _cachedBootEntries && JSON.stringify(_cachedBootEntries) === JSON.stringify(d.boot_entries);
    if (!sameBoot) {
      _cachedBootEntries = d.boot_entries;
      const bl = document.getElementById('boot-list');
      bl.textContent = '';
      for (const e of d.boot_entries) {
        let btnClass = 'btn-os';
        const n = String(e.name || '').toLowerCase();
        if (n.includes('cachyos') || n.includes('cachy')) btnClass += ' btn-cachyos';
        else if (n.includes('nixos')) btnClass += ' btn-nixos';
        else if (n.includes('arch')) btnClass += ' btn-arch';
        else if (n.includes('garuda')) btnClass += ' btn-garuda';
        else if (n.includes('gentoo')) btnClass += ' btn-gentoo';
        const btn = document.createElement('button');
        btn.className = btnClass;
        const left = document.createElement('span');
        const b = document.createElement('b');
        b.textContent = e.name;
        left.appendChild(b);
        left.appendChild(document.createTextNode(' (Boot' + e.num + ')'));
        const badge = document.createElement('span');
        badge.className = 'badge-pill';
        badge.textContent = 'Reboot Next';
        btn.appendChild(left);
        btn.appendChild(badge);
        btn.addEventListener('click', () => confirmBootNum(e.num, e.name));
        bl.appendChild(btn);
      }
      const uefiBtn = document.createElement('button');
      uefiBtn.className = 'btn-os';
      const uLeft = document.createElement('b');
      uLeft.textContent = 'Enter BIOS / UEFI Firmware Setup';
      const uTag = document.createElement('span');
      uTag.className = 'badge-pill';
      uTag.textContent = 'Firmware';
      uefiBtn.appendChild(uLeft);
      uefiBtn.appendChild(uTag);
      uefiBtn.addEventListener('click', () => confirmBoot('uefi', 'BIOS / UEFI Firmware Settings'));
      bl.appendChild(uefiBtn);
    }
  }

  const lanBox = document.getElementById('lan-info-box');
  if (lanBox) {
    lanBox.textContent = '';
    const ips = Array.isArray(d.ips) ? d.ips : [];
    const macs = Array.isArray(net.macs) ? net.macs : [];
    if (!ips.length && !macs.length) {
      const empty = document.createElement('div');
      empty.className = 'subtitle';
      empty.textContent = 'No active LAN interfaces reported.';
      lanBox.appendChild(empty);
    } else {
      for (const ip of ips) _appendKvRow(lanBox, 'LAN IPv4', ip);
      for (const m of macs) _appendKvRow(lanBox, 'WoL (' + (m.iface || 'NIC') + ')', m.mac || '-');
    }
  }

  if (d.tunnel) {
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
  }
}

async function refreshTelemetry() {
  if (!_authenticated || document.hidden) return;
  try {
    const d = await api('/api/telemetry');
    applyTelemetryData(d);
  } catch (e) {}
}

async function refreshFullStatus(forceRefresh = false) {
  if (!_authenticated) return;
  try {
    const d = await api('/api/status' + (forceRefresh ? '?refresh=1' : ''));
    applyTelemetryData(d);
    if (forceRefresh) toast('Telemetry refreshed');
  } catch (e) {}
}

function updateLiveButton() {
  const btn = document.getElementById('live-btn');
  if (!btn) return;
  if (_liveEnabled && _liveIntervalMs > 0) {
    btn.textContent = 'Live ON';
    btn.style.borderColor = 'rgba(16,185,129,0.5)';
    btn.style.color = 'var(--success)';
  } else {
    btn.textContent = 'Paused';
    btn.style.borderColor = 'var(--border)';
    btn.style.color = 'var(--muted)';
  }
}

function changeLiveInterval(msVal) {
  const ms = Number(msVal);
  _liveIntervalMs = Number.isFinite(ms) ? ms : 2000;
  _liveEnabled = _liveIntervalMs > 0;
  updateLiveButton();
  if (_liveTimer) { clearTimeout(_liveTimer); _liveTimer = null; }
  if (_liveEnabled && _authenticated && _activeTab === 'monitor') refreshScreenshot(true);
}

function toggleLiveMonitor() {
  if (_liveIntervalMs === 0) {
    _liveIntervalMs = 2000;
    const sel = document.getElementById('live-interval');
    if (sel) sel.value = '2000';
    _liveEnabled = true;
  } else {
    _liveEnabled = !_liveEnabled;
  }
  updateLiveButton();
  if (_liveTimer) { clearTimeout(_liveTimer); _liveTimer = null; }
  if (_liveEnabled && _authenticated && _activeTab === 'monitor') refreshScreenshot(true);
}

function openShotModal() {
  const modal = document.getElementById('shot-modal');
  const mImg = document.getElementById('shot-modal-img');
  if (_liveShotUrl && mImg) mImg.src = _liveShotUrl;
  if (modal) modal.style.display = 'flex';
  refreshScreenshot(false);
}

function closeShotModal() {
  const modal = document.getElementById('shot-modal');
  if (modal) modal.style.display = 'none';
}

function scheduleLiveShot() {
  if (_liveTimer) { clearTimeout(_liveTimer); _liveTimer = null; }
  if (_authenticated && _liveEnabled && _liveIntervalMs > 0 && _activeTab === 'monitor' && !document.hidden) {
    _liveTimer = setTimeout(() => refreshScreenshot(true), _liveIntervalMs);
  }
}

async function refreshScreenshot(fromAuto = false) {
  if (!_authenticated || _shotInFlight) return;
  _shotInFlight = true;
  if (_liveTimer) { clearTimeout(_liveTimer); _liveTimer = null; }
  const img = document.getElementById('live-shot');
  const mImg = document.getElementById('shot-modal-img');
  const ph = document.getElementById('shot-placeholder');
  try {
    const r = await fetch('/api/screenshot?t=' + Date.now(), { credentials: 'same-origin' });
    if (r.status === 401) { showLogin('Session expired. Enter access code again.'); return; }
    if (!r.ok) {
      if (!_liveShotUrl && ph) {
        img.style.display = 'none';
        ph.textContent = 'Desktop capture unavailable';
        ph.style.display = 'block';
      }
      return;
    }
    const blob = await r.blob();
    const objUrl = URL.createObjectURL(blob);
    const prevUrl = _liveShotUrl;
    _liveShotUrl = objUrl;
    img.src = objUrl;
    img.style.display = 'block';
    if (mImg) mImg.src = objUrl;
    if (ph) ph.style.display = 'none';
    if (prevUrl) setTimeout(() => URL.revokeObjectURL(prevUrl), 250);
  } catch (e) {
    if (!fromAuto && !_liveShotUrl && ph) {
      img.style.display = 'none';
      ph.style.display = 'block';
    }
  } finally {
    _shotInFlight = false;
    if (_liveEnabled && _liveIntervalMs > 0) scheduleLiveShot();
  }
}

async function doMedia(action, value = '') {
  const r = await api('/api/media', 'POST', { action, value: String(value) });
  toast(r.message || 'Success');
  refreshTelemetry();
}

async function doPower(target) {
  const r = await api('/api/power', 'POST', { target });
  toast(r.message || 'Command sent');
}

function openConfirmModal(title, msg, payload) {
  _pendingModal = payload;
  document.getElementById('power-modal-title').textContent = title;
  document.getElementById('power-modal-msg').textContent = msg;
  document.getElementById('power-modal').style.display = 'flex';
}

function closePowerModal() {
  _pendingModal = null;
  document.getElementById('power-modal').style.display = 'none';
}

async function execPowerConfirm() {
  const p = _pendingModal;
  closePowerModal();
  if (!p) return;
  if (p.kind === 'power') {
    const r = await api('/api/power', 'POST', p.body);
    toast(r.message || 'Command executed');
  } else if (p.kind === 'kill') {
    const r = await api('/api/process/kill', 'POST', { pid: p.pid, signal: 'TERM' });
    toast(r.message || 'Signal sent');
    loadProcesses();
  }
}

function confirmBoot(target, label) {
  openConfirmModal('Confirm Power Action', 'Execute: ' + label + '? Active sessions may terminate immediately.', { kind: 'power', body: { target } });
}

function confirmBootNum(num, name) {
  openConfirmModal('Switch Boot Target', 'Reboot PC into ' + name + ' (UEFI Boot' + num + ')?', { kind: 'power', body: { target: 'bootnum', bootnum: num, name } });
}

function confirmKillProc(pid, name) {
  openConfirmModal('Terminate Process', 'Send SIGTERM / terminate process ' + name + ' (PID ' + pid + ')?', { kind: 'kill', pid, name });
}

async function doAction(type, value) {
  const r = await api('/api/action', 'POST', { type, value });
  toast(r.message || 'Done');
  if (r.ok !== false && (type === 'ws' || type === 'hypr')) {
    refreshTelemetry();
    setTimeout(() => refreshScreenshot(false), 350);
  }
}

async function sendInput(type) {
  const val = document.getElementById('msg-input').value.trim();
  if (!val) return toast('Enter a message, snippet, or URL first');
  const r = await api('/api/action', 'POST', { type, value: val });
  toast(r.message || 'Sent');
  document.getElementById('msg-input').value = '';
}

function _appendSectionHeader(parent, title) {
  const h = document.createElement('div');
  h.style.cssText = 'font-size:11px;font-weight:700;color:var(--accent);text-transform:uppercase;margin-top:8px;margin-bottom:2px';
  h.textContent = title;
  parent.appendChild(h);
}

function _appendKvRow(parent, leftText, rightText) {
  const row = document.createElement('div');
  row.className = 'row-item';
  const l = document.createElement('div');
  l.className = 'row-title';
  l.textContent = leftText;
  const r = document.createElement('div');
  r.className = 'row-sub num';
  r.style.flexShrink = '0';
  r.textContent = rightText;
  row.appendChild(l);
  row.appendChild(r);
  parent.appendChild(row);
}

async function loadDistros(deep, refresh) {
  const sumEl = document.getElementById('distro-host-summary');
  const listEl = document.getElementById('distro-list');
  const btn = document.getElementById('btn-deep-scan');
  if (!sumEl || !listEl) return;
  if (deep && btn) { btn.disabled = true; btn.textContent = 'Scanning...'; }
  const qs = '?deep=' + (deep ? '1' : '0') + (refresh ? '&refresh=1' : '');
  const d = await api('/api/distros' + qs);
  if (deep && btn) { btn.disabled = false; btn.textContent = 'Deep Probe'; }
  if (!d || (d.ok === false && d.status)) {
    sumEl.textContent = 'Failed to scan host OS inventory.';
    return;
  }
  const h = d.host || {};
  sumEl.textContent = [h.name || 'Host', 'Init: ' + (h.init_system || 'unknown'), 'Comp: ' + (h.compositor || 'unknown'), 'Kernel: ' + (h.kernel || '-'), h.cpu_model || '', h.gpu_name || ''].filter(Boolean).join(' | ');
  listEl.textContent = '';

  _appendSectionHeader(listEl, 'Detected Operating Systems (' + (d.detected_distros || []).length + ')');
  (d.detected_distros || []).forEach(item => {
    _appendKvRow(listEl, item.name || 'OS', (item.source || '') + (item.detail ? (' - ' + item.detail) : ''));
  });
  if (d.unmounted_distros && d.unmounted_distros.length > 0) {
    _appendSectionHeader(listEl, 'Unmounted Partition Probe');
    d.unmounted_distros.forEach(u => _appendKvRow(listEl, u.name + ' (' + (u.subvolume || '/') + ')', u.device + ' [' + u.fstype + ']'));
  } else if (d.deep_scan) {
    _appendKvRow(listEl, 'Unmounted Partitions', 'No additional OS roots found');
  }
  if (d.bootloader_entries && d.bootloader_entries.length > 0) {
    _appendSectionHeader(listEl, 'Bootloader Entries');
    d.bootloader_entries.slice(0, 12).forEach(b => _appendKvRow(listEl, b.title || b.file, b.loader + (b.kernel ? (' | ' + b.kernel) : '')));
  }
  if (d.filesystems && d.filesystems.length > 0) {
    _appendSectionHeader(listEl, 'Mounted Filesystems');
    d.filesystems.slice(0, 10).forEach(fs => _appendKvRow(listEl, fs.target || '/', (fs.fstype || '') + ' (' + (fs.source || '') + ')'));
  }
}

async function loadLogs() {
  const listEl = document.getElementById('logs-list');
  const badgeEl = document.getElementById('logs-init-badge');
  const srcEl = document.getElementById('log-source');
  if (!listEl || !srcEl) return;
  const curSrc = srcEl.value || 'all';
  const lvl = document.getElementById('log-level').value;
  const q = document.getElementById('log-query').value.trim();
  const qs = '?source=' + encodeURIComponent(curSrc) + '&level=' + encodeURIComponent(lvl) + '&q=' + encodeURIComponent(q) + '&lines=120';
  const d = await api('/api/logs' + qs);
  if (!d || (d.ok === false && d.status)) {
    listEl.textContent = '';
    const errDiv = document.createElement('div');
    errDiv.style.padding = '12px';
    errDiv.textContent = d.message || 'Unable to load system logs.';
    listEl.appendChild(errDiv);
    return;
  }
  if (badgeEl) badgeEl.textContent = 'init: ' + (d.init_system || 'unknown');
  if (Array.isArray(d.sources)) {
    const newOpts = ['all', ...d.sources];
    const existing = Array.from(srcEl.options).map(o => o.value);
    if (JSON.stringify(existing) !== JSON.stringify(newOpts)) {
      srcEl.textContent = '';
      for (const s of newOpts) {
        const opt = document.createElement('option');
        opt.value = s;
        opt.textContent = s === 'all' ? 'All Sources' : s;
        srcEl.appendChild(opt);
      }
      srcEl.value = newOpts.includes(curSrc) ? curSrc : 'all';
    }
  }
  listEl.textContent = '';
  const items = d.entries || [];
  if (!items.length) {
    const empty = document.createElement('div');
    empty.className = 'subtitle';
    empty.style.padding = '12px';
    empty.textContent = 'No log lines matched this filter.';
    listEl.appendChild(empty);
    return;
  }
  items.slice().reverse().forEach(entry => {
    const row = document.createElement('div');
    const lvlStr = String(entry.level || 'INFO').toUpperCase();
    const cls = lvlStr.includes('ERR') || lvlStr.includes('CRIT') || lvlStr.includes('FATAL') ? 'log-err' : (lvlStr.includes('WARN') ? 'log-warn' : 'log-info');
    row.className = 'log-line ' + cls;
    row.textContent = [entry.ts, '[' + (entry.source || 'sys') + ']', '[' + lvlStr + ']'].filter(Boolean).join(' ') + ' ' + (entry.message || '');
    listEl.appendChild(row);
  });
}

async function loadProcesses() {
  const el = document.getElementById('proc-list');
  if (!el) return;
  const d = await api('/api/processes?limit=25');
  el.textContent = '';
  const procs = (d && Array.isArray(d.processes)) ? d.processes : [];
  if (!procs.length) {
    const empty = document.createElement('div');
    empty.className = 'subtitle';
    empty.style.padding = '10px';
    empty.textContent = 'No process list returned.';
    el.appendChild(empty);
    return;
  }
  for (const p of procs) {
    const row = document.createElement('div');
    row.className = 'row-item';
    const col = document.createElement('div');
    col.className = 'row-item-col';
    const title = document.createElement('div');
    title.className = 'row-title';
    title.textContent = p.name + ' (PID ' + p.pid + ')';
    const sub = document.createElement('div');
    sub.className = 'row-sub num';
    sub.textContent = 'CPU ' + (p.cpu_pct || 0) + '% | RAM ' + (p.rss_mb || 0) + ' MB | ' + (p.cmd || p.name);
    col.appendChild(title);
    col.appendChild(sub);
    const killBtn = document.createElement('button');
    killBtn.className = 'btn-sm btn-danger';
    killBtn.textContent = 'Kill';
    killBtn.addEventListener('click', () => confirmKillProc(p.pid, p.name));
    row.appendChild(col);
    row.appendChild(killBtn);
    el.appendChild(row);
  }
}

function renderServicesList() {
  const el = document.getElementById('svc-list');
  const q = (document.getElementById('svc-filter')?.value || '').trim().toLowerCase();
  if (!el) return;
  el.textContent = '';
  const filtered = _servicesCache.filter(s => !q || String(s.name || '').toLowerCase().includes(q));
  if (!filtered.length) {
    const empty = document.createElement('div');
    empty.className = 'subtitle';
    empty.style.padding = '10px';
    empty.textContent = 'No services matched.';
    el.appendChild(empty);
    return;
  }
  for (const s of filtered.slice(0, 60)) {
    const row = document.createElement('div');
    row.className = 'row-item';
    const col = document.createElement('div');
    col.className = 'row-item-col';
    const title = document.createElement('div');
    title.className = 'row-title';
    title.textContent = s.name;
    const sub = document.createElement('div');
    sub.className = 'row-sub';
    const st = String(s.status || 'unknown');
    const isUp = st.includes('started') || st.includes('active') || st.includes('running') || st === 'ok';
    sub.textContent = st + (s.runlevel ? (' | ' + s.runlevel) : '');
    sub.style.color = isUp ? 'var(--success)' : 'var(--muted)';
    col.appendChild(title);
    col.appendChild(sub);
    const acts = document.createElement('div');
    acts.style.cssText = 'display:flex;gap:4px;flex-shrink:0';
    for (const actName of (isUp ? ['restart', 'stop'] : ['start'])) {
      const b = document.createElement('button');
      b.className = 'btn-sm ' + (actName === 'stop' ? 'btn-danger' : (actName === 'start' ? 'btn-success' : ''));
      b.textContent = actName[0].toUpperCase() + actName.slice(1);
      b.addEventListener('click', () => controlSvc(s.name, actName));
      acts.appendChild(b);
    }
    row.appendChild(col);
    row.appendChild(acts);
    el.appendChild(row);
  }
}

function filterServices() { renderServicesList(); }

async function loadServices() {
  const d = await api('/api/services');
  _servicesCache = (d && Array.isArray(d.services)) ? d.services : [];
  renderServicesList();
}

async function controlSvc(name, action) {
  toast(action + ' ' + name + '...');
  const r = await api('/api/services', 'POST', { name, action });
  toast(r.message || (r.ok ? 'Done' : 'Failed'));
  loadServices();
}

async function loadDevices() {
  const el = document.getElementById('devices-list');
  if (!el) return;
  const d = await api('/api/mobile/devices');
  el.textContent = '';
  const devs = (d && Array.isArray(d.devices)) ? d.devices : [];
  if (!devs.length) {
    const empty = document.createElement('div');
    empty.className = 'subtitle';
    empty.textContent = 'No paired mobile tokens active.';
    el.appendChild(empty);
    return;
  }
  for (const dev of devs) {
    const row = document.createElement('div');
    row.className = 'row-item';
    const col = document.createElement('div');
    col.className = 'row-item-col';
    const title = document.createElement('div');
    title.className = 'row-title';
    title.textContent = dev.name || dev.id;
    const seen = dev.last_seen ? new Date(dev.last_seen * 1000).toLocaleString() : 'Never';
    const sub = document.createElement('div');
    sub.className = 'row-sub num';
    sub.textContent = 'ID: ' + dev.id + ' | Last seen: ' + seen;
    col.appendChild(title);
    col.appendChild(sub);
    const revBtn = document.createElement('button');
    revBtn.className = 'btn-sm btn-danger';
    revBtn.textContent = 'Revoke';
    revBtn.addEventListener('click', () => revokeDevice(dev.id, dev.name));
    row.appendChild(col);
    row.appendChild(revBtn);
    el.appendChild(row);
  }
}

async function revokeDevice(id, name) {
  const r = await api('/api/mobile/revoke', 'POST', { id });
  toast(r.ok ? ('Revoked ' + (name || id)) : (r.message || 'Revoke failed'));
  loadDevices();
}

async function sendRemoteClick(button) {
  const r = await api('/api/input', 'POST', { kind: 'click', button });
  const st = document.getElementById('tp-status');
  if (st) st.textContent = r.ok ? (button + ' click') : (r.message || 'Failed');
}

async function sendRemoteScroll(dy) {
  await api('/api/input', 'POST', { kind: 'scroll', dy });
}

async function sendRemoteKey(key) {
  const r = await api('/api/input', 'POST', { kind: 'key', key });
  const st = document.getElementById('tp-status');
  if (st) st.textContent = r.ok ? ('Key: ' + key) : (r.message || 'Failed');
}

(function bindTouchpad() {
  const pad = document.getElementById('touchpad-surface');
  if (!pad) return;
  let lastX = null;
  let lastY = null;
  let moved = false;
  let accDx = 0;
  let accDy = 0;
  let flushTimer = null;

  const flushMove = () => {
    flushTimer = null;
    const dx = Math.round(accDx);
    const dy = Math.round(accDy);
    accDx -= dx;
    accDy -= dy;
    if (dx !== 0 || dy !== 0) {
      api('/api/input', 'POST', { kind: 'move', dx, dy }).catch(() => {});
    }
  };

  pad.addEventListener('pointerdown', (e) => {
    pad.setPointerCapture(e.pointerId);
    lastX = e.clientX;
    lastY = e.clientY;
    moved = false;
  });
  pad.addEventListener('pointermove', (e) => {
    if (lastX === null) return;
    const dx = (e.clientX - lastX) * 1.6;
    const dy = (e.clientY - lastY) * 1.6;
    lastX = e.clientX;
    lastY = e.clientY;
    if (Math.abs(dx) > 1.5 || Math.abs(dy) > 1.5) moved = true;
    accDx += dx;
    accDy += dy;
    if (!flushTimer) flushTimer = setTimeout(flushMove, 45);
  });
  pad.addEventListener('pointerup', () => {
    if (!moved && lastX !== null) sendRemoteClick('left');
    lastX = null;
    lastY = null;
  });
  pad.addEventListener('pointercancel', () => { lastX = null; lastY = null; });
})();

async function submitFeedback() {
  const statusEl = document.getElementById('fb-status');
  const fbLinksEl = document.getElementById('fb-fallbacks');
  const btn = document.getElementById('fb-submit-btn');
  const subject = document.getElementById('fb-subject').value.trim();
  const message = document.getElementById('fb-message').value.trim();
  if (!subject || !message) {
    statusEl.style.color = '#fde68a';
    statusEl.textContent = 'Please fill in both Subject and Feedback details.';
    return;
  }
  btn.disabled = true;
  statusEl.style.color = 'var(--muted)';
  statusEl.textContent = 'Sending feedback...';
  fbLinksEl.textContent = '';
  const r = await api('/api/feedback', 'POST', {
    category: document.getElementById('fb-category').value,
    subject,
    message,
    reply_to: document.getElementById('fb-reply').value.trim(),
    include_sysinfo: document.getElementById('fb-sysinfo').checked,
  });
  btn.disabled = false;
  if (r.ok) {
    statusEl.style.color = '#86efac';
    statusEl.textContent = r.message || 'Feedback delivered to brypra4@gmail.com.';
    document.getElementById('fb-subject').value = '';
    document.getElementById('fb-message').value = '';
    return;
  }
  statusEl.style.color = '#fde68a';
  statusEl.textContent = r.message || 'Use an option below to deliver directly.';
  const makeLinkBtn = (label, url, primary) => {
    if (!url || !(url.startsWith('mailto:') || url.startsWith('https://'))) return;
    const a = document.createElement('a');
    a.href = url;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.textContent = label;
    a.style.cssText = 'display:inline-block;padding:8px 12px;border-radius:10px;text-decoration:none;font-size:12px;font-weight:700;' + (primary ? 'background:var(--accent);color:#0f172a' : 'background:rgba(255,255,255,0.08);color:var(--text);border:1px solid var(--border)');
    fbLinksEl.appendChild(a);
  };
  makeLinkBtn('Open Email App', r.mailto, true);
  makeLinkBtn('Open GitHub Issue', r.github_issue, false);
}

async function runTerminal(mode) {
  const actType = mode || 'shell';
  const cmd = document.getElementById('cmd-input').value.trim();
  if (!cmd) return;
  const autoEnter = document.getElementById('cmd-auto-enter') ? document.getElementById('cmd-auto-enter').checked : true;
  document.getElementById('term-out').textContent = 'Running (' + actType + '): ' + cmd + ' ...';
  const payload = { type: actType, value: cmd };
  if (actType === 'shell_type') payload.auto_enter = autoEnter;
  const r = await api('/api/action', 'POST', payload);
  document.getElementById('term-out').textContent = r.output || r.message || '(No output returned)';
}

async function toggleTunnel(act) {
  toast(act === 'start' ? 'Starting public tunnel (~4s)...' : 'Stopping tunnel...');
  const r = await api('/api/tunnel', 'POST', { action: act });
  refreshFullStatus(false);
  if (r.url) toast('Public Link Online: ' + r.url);
}

async function loadFiles() {
  if (!_authenticated) return;
  const r = await api('/api/files');
  const fl = document.getElementById('file-list');
  fl.textContent = '';
  if (!r.files || !r.files.length) {
    const empty = document.createElement('div');
    empty.className = 'subtitle';
    empty.style.padding = '10px';
    empty.textContent = 'Downloads folder is empty.';
    fl.appendChild(empty);
    return;
  }
  for (const f of r.files) {
    const item = document.createElement('div');
    item.className = 'row-item';
    const col = document.createElement('div');
    col.className = 'row-item-col';
    col.title = f.name;
    const title = document.createElement('div');
    title.className = 'row-title';
    title.textContent = f.name;
    const sub = document.createElement('div');
    sub.className = 'row-sub num';
    sub.textContent = f.size;
    col.appendChild(title);
    col.appendChild(sub);
    const link = document.createElement('a');
    link.href = '/api/download?name=' + encodeURIComponent(f.name);
    link.rel = 'noopener noreferrer';
    link.download = f.name;
    link.textContent = 'Download';
    link.style.cssText = 'padding:5px 10px;font-size:11px;border-radius:8px;border:1px solid var(--border);color:var(--text);text-decoration:none;font-weight:600;background:rgba(255,255,255,0.06);flex-shrink:0';
    item.appendChild(col);
    item.appendChild(link);
    fl.appendChild(item);
  }
}

async function uploadFile() {
  if (!_authenticated) return;
  const inp = document.getElementById('file-upload');
  if (!inp.files.length) return toast('Select a file first');
  const file = inp.files[0];
  toast('Uploading ' + file.name + '...');
  const r = await fetch('/api/upload?name=' + encodeURIComponent(file.name), {
    method: 'POST',
    credentials: 'same-origin',
    headers: _csrfToken ? { 'X-CSRF-Token': _csrfToken } : {},
    body: file,
  });
  if (r.status === 401) { showLogin('Session expired. Enter access code again.'); return; }
  const res = await r.json();
  toast(res.message || 'Upload complete');
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

    def _is_loopback_request(self):
        """Ensure request originates strictly from host loopback (127.0.0.1 / ::1) with no proxy headers."""
        peer = self.client_address[0] if self.client_address else ""
        try:
            if not ipaddress.ip_address(str(peer).strip()).is_loopback:
                return False
        except ValueError:
            return False
        for hdr in ("Cf-Connecting-Ip", "Cf-Ray", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded"):
            if (self.headers.get(hdr) or "").strip():
                return False
        return True

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
        auth_hdr = (self.headers.get("Authorization") or "").strip()
        if auth_hdr.startswith("Bearer "):
            raw_tok = auth_hdr[7:].strip()
            parsed_path = urllib.parse.urlparse(self.path).path
            if raw_tok and parsed_path.startswith("/api/"):
                dev = verify_mobile_device_token(raw_tok)
                if dev is not None:
                    return f"bearer:{dev.get('id', 'device')}", {
                        "csrf": "",
                        "ip": self._client_ip(),
                        "is_bearer": True,
                        "device": dev,
                        "exp": time.time() + SESSION_TTL_SEC,
                    }
            return None, None
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
        if sess and sess.get("is_bearer") is True:
            return True
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
                os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "share",
                    "mobile-rc",
                    "termux-control-access.sh",
                ),
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
            refresh = qs.get("refresh", ["0"])[0].strip().lower() in ("1", "true", "yes")
            if refresh:
                _invalidate_cache("local_ips", "gpu_info", "media_display")
            data = {
                "os": get_os_info(),
                "init_system": detect_init_system(),
                "cpu_pct": get_cpu_percent(),
                "cpu_temp": get_cpu_temp(),
                "ram": get_memory_info(),
                "swap": get_swap_info(),
                "gpu": get_gpu_info(),
                "battery": get_battery_info(),
                "network": get_network_telemetry(),
                "media": get_media_and_display(),
                "workspaces": get_workspaces_info(),
                "disks": get_disks_info(refresh=refresh),
                "boot_entries": get_boot_entries(refresh=refresh),
                "ips": get_local_ips(),
                "tunnel": get_tunnel_info(),
            }
            self._send_json(data)
            return

        if path == "/api/telemetry":
            self._send_json({
                "os": get_os_info(),
                "init_system": detect_init_system(),
                "cpu_pct": get_cpu_percent(),
                "cpu_temp": get_cpu_temp(),
                "ram": get_memory_info(),
                "swap": get_swap_info(),
                "gpu": get_gpu_info(),
                "battery": get_battery_info(),
                "network": get_network_telemetry(),
                "media": get_media_and_display(),
                "workspaces": get_workspaces_info(),
                "disks": get_disks_info(),
                "ips": get_local_ips(),
                "tunnel": get_tunnel_info(),
            })
            return

        if path == "/api/logs":
            src = qs.get("source", ["all"])[0]
            lvl = qs.get("level", ["all"])[0]
            q = qs.get("q", [""])[0]
            lines = qs.get("lines", ["120"])[0]
            self._send_json(get_system_logs(source=src, level=lvl, query=q, lines=lines))
            return

        if path == "/api/distros":
            deep = qs.get("deep", ["0"])[0].strip().lower() in ("1", "true", "yes")
            refresh = qs.get("refresh", ["0"])[0].strip().lower() in ("1", "true", "yes")
            self._send_json(get_installed_distros_info(deep=deep, refresh=refresh))
            return

        if path == "/api/services":
            self._send_json(get_services_info())
            return

        if path == "/api/processes":
            limit = qs.get("limit", ["30"])[0]
            self._send_json(get_processes_info(limit=limit))
            return

        if path == "/api/mobile/devices":
            self._send_json({"ok": True, "devices": list_mobile_devices()})
            return

        if path == "/api/screenshot":
            img, ctype = capture_desktop_screenshot()
            if img:
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", ctype or "image/jpeg")
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

        if path == "/api/mobile/pair":
            if not self._check_origin():
                return
            ip = self._client_ip()
            now = time.time()
            wait_sec = self._check_rate_limit(_PAIRING_ATTEMPTS, ip, now)
            if wait_sec:
                self._send_json(
                    {"ok": False, "message": f"Too many pairing attempts. Try again in {wait_sec}s."},
                    HTTPStatus.TOO_MANY_REQUESTS,
                )
                return

            try:
                data = self._read_json()
            except _PayloadTooLargeError as e:
                self._send_json({"ok": False, "message": str(e)}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                return
            except _BadRequestError as e:
                self._send_json({"ok": False, "message": str(e)}, HTTPStatus.BAD_REQUEST)
                return

            device_name = str(data.get("device_name", "Mobile-RC App")).strip()
            auth_hdr = (self.headers.get("Authorization") or "").strip()
            supplied_tok = auth_hdr[7:].strip() if auth_hdr.startswith("Bearer ") else str(data.get("pairing_token", "")).strip()
            expected_tok = get_termux_token()
            authorized = False
            used_pin_auth = False

            if supplied_tok and self._is_loopback_request() and hmac.compare_digest(supplied_tok, expected_tok):
                authorized = True
            elif "pin" in data:
                used_pin_auth = True
                pin_ok, _ = _verify_login_code(
                    str(data.get("pin", "")),
                    require_email=self._is_non_local_request(),
                )
                if pin_ok:
                    authorized = True
            else:
                _, sess = self._get_session()
                if sess:
                    if sess.get("is_bearer") is True:
                        authorized = True
                    else:
                        supplied_csrf = (self.headers.get("X-CSRF-Token") or "").strip()
                        if supplied_csrf and hmac.compare_digest(supplied_csrf, sess["csrf"]):
                            authorized = True

            if not authorized:
                locked = self._record_auth_failure(
                    _PAIRING_ATTEMPTS,
                    ip,
                    now,
                    invalidate_code=(used_pin_auth and get_pin_mode() != "static"),
                )
                if locked:
                    self._send_json(
                        {"ok": False, "message": f"Too many invalid attempts. Locked for {LOGIN_LOCKOUT_SEC}s."},
                        HTTPStatus.TOO_MANY_REQUESTS,
                    )
                    return
                self._send_json({"ok": False, "message": "Invalid pairing token or PIN"}, HTTPStatus.UNAUTHORIZED)
                return

            with _AUTH_LOCK:
                _PAIRING_ATTEMPTS.pop(ip, None)
            dev_id, raw_device_token = register_mobile_device(device_name)
            self._send_json({
                "ok": True,
                "token": raw_device_token,
                "device_id": dev_id,
                "device": {"id": dev_id, "name": device_name or "Mobile-RC App"},
                "host": get_os_info(),
                "init_system": detect_init_system(),
                "macs": get_mac_addresses(),
                "ips": get_local_ips(),
                "port": PORT,
            })
            return

        if path == "/api/pairing/code":
            if not self._is_loopback_request():
                record_audit_event("WARN", f"Blocked non-loopback RAC generation attempt from {self._client_ip()}")
                self._send_json(
                    {
                        "ok": False,
                        "message": "Random Access Code (RAC) can only be generated on the host PC/Laptop (sudo control-access).",
                    },
                    HTTPStatus.FORBIDDEN,
                )
                return
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

            handoff_in = str(data.get("handoff_token", "")).strip()
            if handoff_in:
                with _AUTH_LOCK:
                    expired_h = [k for k, v in _HANDOFF_TICKETS.items() if now >= v["expires"]]
                    for k in expired_h:
                        _HANDOFF_TICKETS.pop(k, None)
                    ticket = _HANDOFF_TICKETS.pop(handoff_in, None)
                if ticket and now < ticket["expires"]:
                    session_token = secrets.token_urlsafe(32)
                    csrf_token = secrets.token_urlsafe(24)
                    with _AUTH_LOCK:
                        _LOGIN_ATTEMPTS.pop(ip, None)
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
                self._send_json({"ok": False, "message": "Invalid or expired login ticket"}, HTTPStatus.UNAUTHORIZED)
                return

            is_remote = self._is_non_local_request()
            supplied_pin = str(data.get("pin", "")).strip()
            ok, reason = _verify_login_code(supplied_pin, require_email=is_remote)
            if ok:
                session_token = secrets.token_urlsafe(32)
                csrf_token = secrets.token_urlsafe(24)
                handoff_out = ""
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
                    if bool(data.get("handoff", False)):
                        handoff_out = secrets.token_urlsafe(24)
                        _HANDOFF_TICKETS[handoff_out] = {
                            "expires": now + 45.0,
                            "ip": ip,
                        }
                cookie_val = (
                    f"mrc_session={session_token}; HttpOnly; SameSite=Strict; "
                    f"Path=/; Max-Age={SESSION_TTL_SEC}"
                )
                resp_payload = {"ok": True, "csrf_token": csrf_token}
                if handoff_out:
                    resp_payload["handoff_token"] = handoff_out
                self._send_json(
                    resp_payload,
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

            if is_remote:
                msg_map = {
                    "missing": "No active Email RAC. Request a 6-digit code via Email above first.",
                    "expired": "Email RAC expired. Request a new Email code to continue.",
                    "invalid": "Invalid code",
                }
            else:
                msg_map = {
                    "missing": "No active RAC. Run 'sudo control-access' on your PC/Laptop first.",
                    "expired": "RAC expired. Run 'sudo control-access' on your PC/Laptop for a new one.",
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
                if not IS_WINDOWS and hasattr(os, "geteuid") and os.geteuid() == 0 and uid != 0:
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
                if IS_WINDOWS:
                    _win_send_vk(0xB3)
                else:
                    run_as_user(["playerctl", "play-pause"])
            elif act == "next":
                if IS_WINDOWS:
                    _win_send_vk(0xB0)
                else:
                    run_as_user(["playerctl", "next"])
            elif act == "prev":
                if IS_WINDOWS:
                    _win_send_vk(0xB1)
                else:
                    run_as_user(["playerctl", "previous"])
            elif act == "mute":
                if IS_WINDOWS:
                    _win_send_vk(0xAD)
                else:
                    run_first_available([
                        ["wpctl", "set-mute", "@DEFAULT_AUDIO_SINK@", "toggle"],
                        ["pactl", "set-sink-mute", "@DEFAULT_SINK@", "toggle"],
                        ["amixer", "set", "Master", "toggle"],
                    ])
            elif act == "vol_up":
                if IS_WINDOWS:
                    _win_send_vk(0xAF)
                else:
                    run_first_available([
                        ["wpctl", "set-volume", "-l", "1.5", "@DEFAULT_AUDIO_SINK@", "5%+"],
                        ["pactl", "set-sink-volume", "@DEFAULT_SINK@", "+5%"],
                        ["amixer", "set", "Master", "5%+"],
                    ])
            elif act == "vol_down":
                if IS_WINDOWS:
                    _win_send_vk(0xAE)
                else:
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
                if IS_WINDOWS:
                    _win_coreaudio_set(min(100, pct))
                else:
                    run_first_available([
                        ["wpctl", "set-volume", "@DEFAULT_AUDIO_SINK@", f"{pct}%"],
                        ["pactl", "set-sink-volume", "@DEFAULT_SINK@", f"{pct}%"],
                    ])
            elif act == "bright_up":
                if not _adjust_brightness("up"):
                    self._send_json({"ok": False, "message": "Brightness control unavailable (internal backlight or ddcutil required)"}, HTTPStatus.NOT_IMPLEMENTED)
                    return
            elif act == "bright_down":
                if not _adjust_brightness("down"):
                    self._send_json({"ok": False, "message": "Brightness control unavailable (internal backlight or ddcutil required)"}, HTTPStatus.NOT_IMPLEMENTED)
                    return
            elif act == "bright_set":
                try:
                    pct = max(5, min(100, int(float(val))))
                except (TypeError, ValueError):
                    self._send_json({"ok": False, "message": "Invalid brightness value"}, HTTPStatus.BAD_REQUEST)
                    return
                if not _adjust_brightness("set", pct):
                    self._send_json({"ok": False, "message": "Brightness control unavailable (backlight, ddcutil, or hyprsunset required)"}, HTTPStatus.NOT_IMPLEMENTED)
                    return
            else:
                self._send_json({"ok": False, "message": "Unsupported media action"}, HTTPStatus.BAD_REQUEST)
                return
            _invalidate_cache("media_display")
            self._send_json({"ok": True, "message": f"Action {act} executed"})
            return

        if path == "/api/power":
            target = str(data.get("target", "")).lower().strip()
            bootnum = str(data.get("bootnum", "")).strip()

            if target == "bootnum":
                if IS_WINDOWS:
                    self._send_json({"ok": False, "message": "Per-entry efibootmgr switching is Linux-only; use UEFI Firmware Reboot instead"}, HTTPStatus.NOT_IMPLEMENTED)
                    return
                if not re.fullmatch(r"[0-9a-fA-F]{4}", bootnum):
                    self._send_json({"ok": False, "message": "Invalid UEFI boot number"}, HTTPStatus.BAD_REQUEST)
                    return
                norm_num = bootnum.upper()
                rc, _, err = run_cmd(["efibootmgr", "-n", norm_num])
                if rc != 0:
                    self._send_json({"ok": False, "message": f"efibootmgr failed: {err}"}, HTTPStatus.INTERNAL_SERVER_ERROR)
                    return
                _invalidate_cache("boot_entries")
                name = str(data.get("name", f"Boot{norm_num}"))[:64]
                threading.Thread(
                    target=_delayed_power,
                    args=([["systemctl", "reboot"], ["loginctl", "reboot"], ["reboot"]],),
                    daemon=True,
                ).start()
                self._send_json({"ok": True, "message": f"BootNext set to {norm_num} ({name}). Rebooting..."})
                return

            if target in ("arch", "cachyos", "garuda", "gentoo", "nixos", "ubuntu", "fedora", "debian", "windows"):
                if IS_WINDOWS:
                    self._send_json({"ok": False, "message": "OS BootNext switching via efibootmgr is Linux-only"}, HTTPStatus.NOT_IMPLEMENTED)
                    return
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
                _invalidate_cache("boot_entries")
                threading.Thread(
                    target=_delayed_power,
                    args=([["systemctl", "reboot"], ["loginctl", "reboot"], ["reboot"]],),
                    daemon=True,
                ).start()
                self._send_json({"ok": True, "message": f"BootNext set to {found_num} ({target.upper()}). Rebooting..."})
                return

            if target == "uefi":
                cmds = (
                    [["shutdown", "/r", "/fw", "/t", "1"]]
                    if IS_WINDOWS
                    else [["systemctl", "reboot", "--firmware-setup"], ["loginctl", "reboot", "--firmware-setup"]]
                )
                threading.Thread(target=_delayed_power, args=(cmds,), daemon=True).start()
                self._send_json({"ok": True, "message": "Rebooting into BIOS / UEFI setup..."})
                return

            if target == "reboot":
                cmds = (
                    [["shutdown", "/r", "/t", "1", "/c", "Mobile-RC reboot"]]
                    if IS_WINDOWS
                    else [["systemctl", "reboot"], ["loginctl", "reboot"], ["reboot"]]
                )
                threading.Thread(target=_delayed_power, args=(cmds,), daemon=True).start()
                self._send_json({"ok": True, "message": "Rebooting system..."})
                return

            if target == "poweroff":
                cmds = (
                    [["shutdown", "/s", "/t", "1", "/c", "Mobile-RC shutdown"]]
                    if IS_WINDOWS
                    else [["systemctl", "poweroff"], ["loginctl", "poweroff"], ["poweroff"]]
                )
                threading.Thread(target=_delayed_power, args=(cmds,), daemon=True).start()
                self._send_json({"ok": True, "message": "Shutting down system..."})
                return

            if target == "lock":
                if IS_WINDOWS:
                    locked = False
                    try:
                        locked = bool(ctypes.windll.user32.LockWorkStation())
                    except Exception:
                        locked = False
                    if not locked:
                        run_cmd(["rundll32.exe", "user32.dll,LockWorkStation"])
                    self._send_json({"ok": True, "message": "Screen locked!"})
                    return
                env = get_desktop_env()
                comp = get_active_compositor(env)
                lock_cmds = [
                    ["hyprlock"],
                    ["swaylock"],
                    ["waylock"],
                    ["gtklock"],
                    ["i3lock"],
                    ["loginctl", "lock-session"],
                ]
                if comp == "kde":
                    lock_cmds = [
                        ["qdbus6", "org.freedesktop.ScreenSaver", "/ScreenSaver", "Lock"],
                        ["qdbus", "org.freedesktop.ScreenSaver", "/ScreenSaver", "Lock"],
                        [
                            "dbus-send", "--session", "--dest=org.freedesktop.ScreenSaver",
                            "/ScreenSaver", "org.freedesktop.ScreenSaver.Lock",
                        ],
                    ] + lock_cmds
                run_first_available(lock_cmds)
                run_cmd(["loginctl", "lock-sessions"])
                self._send_json({"ok": True, "message": "Screen locked!"})
                return

            if target == "suspend":
                cmds = (
                    [["rundll32.exe", "powrprof.dll,SetSuspendState", "0,1,0"]]
                    if IS_WINDOWS
                    else [["systemctl", "suspend"], ["loginctl", "suspend"], ["zzz"]]
                )
                threading.Thread(target=_delayed_power, args=(cmds,), daemon=True).start()
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
                if IS_WINDOWS:
                    ps_notify = (
                        "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; "
                        "$n = New-Object System.Windows.Forms.NotifyIcon; "
                        "$n.Icon = [System.Drawing.SystemIcons]::Information; "
                        "$n.Visible = $true; "
                        "$n.ShowBalloonTip(5000, 'Mobile-RC Message', $env:MRC_NOTIFY_MSG, [System.Windows.Forms.ToolTipIcon]::Info); "
                        "Start-Sleep -Milliseconds 600; $n.Dispose()"
                    )
                    threading.Thread(
                        target=_win_run_ps,
                        args=(ps_notify,),
                        kwargs={"timeout": 8, "extra_env": {"MRC_NOTIFY_MSG": msg}},
                        daemon=True,
                    ).start()
                else:
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
                if IS_WINDOWS:
                    rc, _, err = _win_run_ps(
                        "Set-Clipboard -Value $env:MRC_CLIP_TEXT",
                        timeout=6,
                        extra_env={"MRC_CLIP_TEXT": text},
                    )
                else:
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
                if IS_WINDOWS:
                    try:
                        os.startfile(url)
                    except Exception as e:
                        self._send_json({"ok": False, "message": f"Failed to open URL: {e}"}, HTTPStatus.INTERNAL_SERVER_ERROR)
                        return
                else:
                    run_as_user(["xdg-open", url], background=True)
                self._send_json({"ok": True, "message": f"Opening {url} on PC browser!"})
                return

            if tp == "launch":
                preset = str(val).strip()
                if preset not in LAUNCH_PRESETS:
                    self._send_json({"ok": False, "message": "Invalid application preset"}, HTTPStatus.BAD_REQUEST)
                    return
                if IS_WINDOWS:
                    if preset == "youtube":
                        try:
                            os.startfile("https://youtube.com")
                            self._send_json({"ok": True, "message": "Launching preset: youtube"})
                            return
                        except Exception as e:
                            self._send_json({"ok": False, "message": f"Launch failed: {e}"}, HTTPStatus.INTERNAL_SERVER_ERROR)
                            return
                    win_presets = {
                        "terminal": [["wt"], ["powershell"], ["cmd"]],
                        "files": [["explorer.exe"]],
                        "btop": [["btop"], ["btop4win"], ["taskmgr.exe"]],
                    }
                    new_con = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
                    for cmd in win_presets.get(preset, []):
                        exe = find_bin(cmd[0])
                        if exe:
                            subprocess.Popen([exe] + cmd[1:], env=get_desktop_env(), creationflags=new_con if preset == "terminal" else 0)
                            self._send_json({"ok": True, "message": f"Launching preset: {preset}"})
                            return
                    self._send_json({"ok": False, "message": f"No Windows binary found for preset: {preset}"}, HTTPStatus.NOT_FOUND)
                    return
                search_path = get_desktop_env()["PATH"]
                for cmd in LAUNCH_PRESETS[preset]:
                    if find_bin(cmd[0], search_path):
                        run_as_user(cmd, background=True)
                        self._send_json({"ok": True, "message": f"Launching preset: {preset}"})
                        return
                self._send_json({"ok": False, "message": f"No binary found for preset: {preset}"}, HTTPStatus.NOT_FOUND)
                return

            if tp == "ws":
                global _LAST_RIVER_TAG
                try:
                    val_num = int(val)
                except (TypeError, ValueError):
                    self._send_json({"ok": False, "message": "Workspace must be an integer"}, HTTPStatus.BAD_REQUEST)
                    return
                if not (1 <= val_num <= 99):
                    self._send_json({"ok": False, "message": "Workspace must be between 1 and 99"}, HTTPStatus.BAD_REQUEST)
                    return
                if IS_WINDOWS:
                    self._send_json({"ok": False, "message": "Virtual desktop switching via API is not supported on Windows"}, HTTPStatus.NOT_IMPLEMENTED)
                    return
                env = get_desktop_env()
                comp = get_active_compositor(env)
                ws_cmds_by_comp = {
                    "hyprland": [
                        ["hyprctl", "dispatch", f"hl.dsp.focus({{ workspace = {val_num} }})"],
                        ["hyprctl", "dispatch", "workspace", str(val_num)],
                    ],
                    "niri": [["niri", "msg", "action", "focus-workspace", str(val_num)]],
                    "sway": [["swaymsg", "workspace", str(val_num)]],
                    "kde": [
                        ["qdbus6", "org.kde.KWin", "/KWin", "org.kde.KWin.setCurrentDesktop", str(val_num)],
                        ["qdbus", "org.kde.KWin", "/KWin", "org.kde.KWin.setCurrentDesktop", str(val_num)],
                        [
                            "dbus-send", "--session", "--dest=org.kde.KWin", "/KWin",
                            "org.kde.KWin.setCurrentDesktop", f"int32:{val_num}",
                        ],
                        ["kdotool", "set_desktop", str(val_num)],
                    ],
                }
                if val_num <= 32:
                    ws_cmds_by_comp["river"] = [["riverctl", "set-focused-tags", str(1 << (val_num - 1))]]
                x11_ws = [["wmctrl", "-s", str(val_num - 1)], ["xdotool", "set_desktop", str(val_num - 1)]]
                if comp in ws_cmds_by_comp:
                    ws_cmds = ws_cmds_by_comp[comp] + x11_ws
                else:
                    ws_cmds = (
                        ws_cmds_by_comp["hyprland"]
                        + ws_cmds_by_comp["niri"]
                        + ws_cmds_by_comp["sway"]
                        + ws_cmds_by_comp["kde"]
                        + x11_ws
                    )
                rc, _, err = run_first_available(ws_cmds)
                if rc != 0:
                    self._send_json(
                        {"ok": False, "message": err or f"Failed to switch to Workspace {val_num}"},
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                    )
                    return
                if comp == "river":
                    _LAST_RIVER_TAG = val_num
                _invalidate_cache("workspaces_info")
                self._send_json({"ok": True, "message": f"Switched to Workspace {val_num}"})
                return

            if tp == "hypr":
                act = str(val).strip()
                if act not in HYPR_PRESETS:
                    self._send_json({"ok": False, "message": "Invalid window action"}, HTTPStatus.BAD_REQUEST)
                    return
                if IS_WINDOWS:
                    if act == "fullscreen":
                        ok = _win_send_vk(0x7A)  # F11
                    elif act == "killactive":
                        ok = _win_send_vk(0x73, hold_alt=True)  # Alt+F4
                    elif act == "dpms_toggle":
                        try:
                            ctypes.windll.user32.SendMessageW(0xFFFF, 0x0112, 0xF170, 2)
                            ok = True
                        except Exception:
                            ok = False
                    else:
                        self._send_json({"ok": False, "message": f"Window action '{act}' is Linux compositor-only"}, HTTPStatus.NOT_IMPLEMENTED)
                        return
                    if not ok:
                        self._send_json({"ok": False, "message": f"Window action failed: {act}"}, HTTPStatus.INTERNAL_SERVER_ERROR)
                        return
                    _invalidate_cache("workspaces_info")
                    self._send_json({"ok": True, "message": f"Window action: {act}"})
                    return
                env = get_desktop_env()
                rc, _, err = run_first_available(get_window_action_cmds(act, env))
                if rc != 0:
                    self._send_json(
                        {"ok": False, "message": err or f"Window action failed: {act}"},
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                    )
                    return
                _invalidate_cache("workspaces_info")
                self._send_json({"ok": True, "message": f"Window action: {act}"})
                return

            if tp in ("shell", "shell_gui", "shell_type"):
                if os.environ.get("MRC_DISABLE_SHELL", "").strip().lower() in ("1", "true", "yes"):
                    self._send_json({"ok": False, "message": "Quick Web Terminal is disabled"}, HTTPStatus.FORBIDDEN)
                    return
                cmd_str = str(val).strip()
                if not cmd_str or len(cmd_str) > 2000:
                    self._send_json({"ok": False, "message": "Command must be 1-2000 characters"}, HTTPStatus.BAD_REQUEST)
                    return
                if tp == "shell_gui":
                    ok, detail = spawn_terminal_with_command(cmd_str)
                    self._send_json({
                        "ok": ok,
                        "output": f"Opened on-screen terminal ({detail}) with: {cmd_str}" if ok else detail,
                        "message": detail,
                    })
                    return
                if tp == "shell_type":
                    auto_enter = bool(data.get("auto_enter", True))
                    ok, detail = type_prompt_to_active_window(cmd_str, auto_enter=auto_enter)
                    self._send_json({
                        "ok": ok,
                        "output": f"Typed prompt into active window ({detail}, auto_enter={auto_enter})" if ok else detail,
                        "message": detail,
                    })
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

        if path == "/api/mobile/revoke":
            dev_id = str(data.get("id", "")).strip()
            if not dev_id:
                self._send_json({"ok": False, "message": "Missing device id"}, HTTPStatus.BAD_REQUEST)
                return
            ok = revoke_mobile_device(dev_id)
            self._send_json({"ok": ok, "message": "Device revoked" if ok else "Device id not found"})
            return

        if path == "/api/feedback":
            ip = self._client_ip()
            now = time.time()
            with _AUTH_LOCK:
                if len(_FEEDBACK_HISTORY) > 1000:
                    oldest_ip = min(_FEEDBACK_HISTORY, key=lambda k: (_FEEDBACK_HISTORY[k][-1] if _FEEDBACK_HISTORY[k] else 0))
                    _FEEDBACK_HISTORY.pop(oldest_ip, None)
                hist = [t for t in _FEEDBACK_HISTORY.get(ip, []) if (now - t) < 600]
                if len(hist) >= 5:
                    _FEEDBACK_HISTORY[ip] = hist
                    self._send_json({"ok": False, "message": "Feedback rate limit reached. Try again later."}, HTTPStatus.TOO_MANY_REQUESTS)
                    return

            category = str(data.get("category", "other")).strip().lower()
            if category not in ("suggestion", "bug", "other"):
                category = "other"
            subject = re.sub(r"[\r\n]+", " ", str(data.get("subject", ""))).strip()
            message = str(data.get("message", "")).strip()
            reply_to = re.sub(r"[\r\n]+", "", str(data.get("reply_to", ""))).strip()[:120]
            if not (1 <= len(subject) <= 120):
                self._send_json({"ok": False, "message": "Subject must be 1-120 characters"}, HTTPStatus.BAD_REQUEST)
                return
            if not (3 <= len(message) <= 4000):
                self._send_json({"ok": False, "message": "Message must be 3-4000 characters"}, HTTPStatus.BAD_REQUEST)
                return
            if reply_to and ("@" not in reply_to or any(c.isspace() for c in reply_to)):
                self._send_json({"ok": False, "message": "Invalid reply email address"}, HTTPStatus.BAD_REQUEST)
                return
            with _AUTH_LOCK:
                hist = [t for t in _FEEDBACK_HISTORY.get(ip, []) if (now - t) < 600]
                if len(hist) >= 5:
                    _FEEDBACK_HISTORY[ip] = hist
                    self._send_json({"ok": False, "message": "Feedback rate limit reached. Try again later."}, HTTPStatus.TOO_MANY_REQUESTS)
                    return
                hist.append(now)
                _FEEDBACK_HISTORY[ip] = hist
            include_sysinfo = bool(data.get("include_sysinfo", False))
            res = send_feedback_report(category, subject, message, reply_to=reply_to, include_sysinfo=include_sysinfo)
            self._send_json(res)
            return

        if path == "/api/services":
            ok, msg = control_service(data.get("name", ""), data.get("action", ""))
            status = HTTPStatus.OK if ok else (HTTPStatus.BAD_REQUEST if msg.startswith("Invalid") else HTTPStatus.OK)
            self._send_json({"ok": ok, "message": msg}, status)
            return

        if path == "/api/process/kill":
            ok, msg = kill_process(data.get("pid"), data.get("signal", "TERM"))
            self._send_json({"ok": ok, "message": msg})
            return

        if path == "/api/input":
            ok, msg = send_remote_input(data.get("kind", ""), data)
            self._send_json({"ok": ok, "message": msg})
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")


def main():
    _ensure_config_dir()
    if get_pin_mode() == "static":
        get_pin()
    get_termux_token()
    get_ntfy_topic()
    get_cpu_percent()
    record_audit_event("INFO", f"Mobile-RC server listening on 0.0.0.0:{PORT}")
    threading.Thread(target=_tunnel_watchdog, daemon=True).start()
    threading.Thread(target=_discovery_worker, daemon=True).start()
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

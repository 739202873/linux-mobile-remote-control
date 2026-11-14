//! Configuration persistence, secure file handling, TTL caching, and identity helpers.

use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{HashMap, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

#[derive(Clone, Debug)]
pub struct Settings {
    pub port: u16,
    pub discovery_port: u16,
    pub discovery_enabled: bool,
    pub config_dir: PathBuf,
    pub config_file: PathBuf,
    pub pin_file: PathBuf,
    pub ssh_key_file: PathBuf,
    pub ssh_known_hosts: PathBuf,
    pub max_json_bytes: usize,
    pub max_upload_bytes: u64,
    pub session_ttl_sec: f64,
    pub code_ttl_sec: u64,
    pub login_max_fails: u32,
    pub login_lockout_sec: u64,
    pub feedback_target_email: String,
    pub feedback_webhook_url: String,
    pub email_cooldown_sec: u64,
    pub email_hourly_max: usize,
    pub disable_shell: bool,
}

impl Settings {
    /// Load daemon configuration settings from environment variables with secure defaults.
    pub fn from_env() -> Self {
        let port = std::env::var("MRC_PORT")
            .ok()
            .and_then(|s| s.trim().parse::<u16>().ok())
            .filter(|&p| p > 0)
            .unwrap_or(8000);
        let discovery_port = std::env::var("MRC_DISCOVERY_PORT")
            .ok()
            .and_then(|s| s.trim().parse::<u16>().ok())
            .filter(|&p| p > 0)
            .unwrap_or(8001);
        let discovery_enabled = !matches!(
            std::env::var("MRC_DISCOVERY")
                .unwrap_or_else(|_| "1".into())
                .trim()
                .to_ascii_lowercase()
                .as_str(),
            "0" | "false" | "no"
        );
        let config_dir = default_config_dir();
        let config_file = config_dir.join("config.json");
        let pin_file = config_dir.join("pin.txt");
        let ssh_key_file = config_dir.join("ssh_id_ed25519");
        let ssh_known_hosts = config_dir.join("ssh_known_hosts");

        let max_upload_mb = std::env::var("MRC_MAX_UPLOAD_MB")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(500);
        let code_ttl_sec = std::env::var("MRC_CODE_TTL")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(180)
            .clamp(30, 600);
        let feedback_target_email = std::env::var("MRC_FEEDBACK_EMAIL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "brypra4@gmail.com".to_string());
        let feedback_webhook_url = std::env::var("MRC_FEEDBACK_WEBHOOK")
            .ok()
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let email_cooldown_sec = std::env::var("MRC_EMAIL_COOLDOWN")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(30)
            .max(10);
        let email_hourly_max = std::env::var("MRC_EMAIL_HOURLY_MAX")
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .unwrap_or(12)
            .max(3);
        let disable_shell = matches!(
            std::env::var("MRC_DISABLE_SHELL")
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
                .as_str(),
            "1" | "true" | "yes"
        );

        Self {
            port,
            discovery_port,
            discovery_enabled,
            config_dir,
            config_file,
            pin_file,
            ssh_key_file,
            ssh_known_hosts,
            max_json_bytes: 1024 * 1024,
            max_upload_bytes: max_upload_mb.saturating_mul(1024 * 1024),
            session_ttl_sec: 86400.0,
            code_ttl_sec,
            login_max_fails: 5,
            login_lockout_sec: 120,
            feedback_target_email,
            feedback_webhook_url,
            email_cooldown_sec,
            email_hourly_max,
            disable_shell,
        }
    }
}

fn default_config_dir() -> PathBuf {
    if let Ok(env_dir) = std::env::var("MRC_CONFIG_DIR") {
        let trimmed = env_dir.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    #[cfg(windows)]
    {
        let prog_data = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
        let cand = PathBuf::from(prog_data).join("Mobile-RC");
        if fs::create_dir_all(&cand).is_ok() {
            let test_f = cand.join(".perm_check");
            if fs::write(&test_f, "ok").is_ok() {
                let _ = fs::remove_file(&test_f);
                return cand;
            }
        }
        let local_app = std::env::var("LOCALAPPDATA")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".into());
        return PathBuf::from(local_app).join("Mobile-RC");
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/opt/mobile-rc")
    }
}

/// Return true if the current process runs as root (Unix) or Administrator (Windows).
pub fn is_root_or_admin() -> bool {
    #[cfg(unix)]
    unsafe {
        libc::geteuid() == 0
    }
    #[cfg(windows)]
    {
        #[link(name = "shell32")]
        extern "system" {
            fn IsUserAnAdmin() -> i32;
        }
        unsafe { IsUserAnAdmin() != 0 }
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts: String,
    pub source: String,
    pub level: String,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct TargetUserInfo {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
}

#[derive(Clone, Debug)]
pub struct EmailOtpSettings {
    pub configured: bool,
    pub enabled: bool,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_pass: String,
    pub allowed_emails: Vec<String>,
}

#[derive(Clone)]
struct ConfigCacheEntry {
    path: PathBuf,
    mtime: SystemTime,
    len: u64,
    data: Map<String, Value>,
}

pub struct ConfigStore {
    pub settings: Settings,
    config_lock: Mutex<Option<ConfigCacheEntry>>,
    ttl_cache: Mutex<HashMap<String, (Instant, Value)>>,
    target_user_cache: Mutex<Option<(String, Instant, TargetUserInfo)>>,
    audit_log: Mutex<VecDeque<AuditEntry>>,
    auto_tunnel_override: Mutex<Option<bool>>,
}

impl ConfigStore {
    /// Initialize a thread-safe configuration, caching, and audit store.
    pub fn new(settings: Settings) -> Self {
        Self {
            settings,
            config_lock: Mutex::new(None),
            ttl_cache: Mutex::new(HashMap::new()),
            target_user_cache: Mutex::new(None),
            audit_log: Mutex::new(VecDeque::with_capacity(150)),
            auto_tunnel_override: Mutex::new(None),
        }
    }

    pub fn ensure_config_dir(&self) -> std::io::Result<()> {
        ensure_dir_secure(&self.settings.config_dir)
    }

    /// Read `config.json` with `(path, mtime, size)` validation to avoid unnecessary disk reads.
    pub fn get_config(&self) -> Map<String, Value> {
        let mut guard = self.config_lock.lock().unwrap();
        let path = &self.settings.config_file;
        let Ok(meta) = fs::metadata(path) else {
            return Map::new();
        };
        let Ok(mtime) = meta.modified() else {
            return Map::new();
        };
        let len = meta.len();

        if let Some(cached) = guard.as_ref() {
            if cached.path == *path && cached.mtime == mtime && cached.len == len {
                return cached.data.clone();
            }
        }

        if let Ok(raw) = fs::read_to_string(path) {
            if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&raw) {
                *guard = Some(ConfigCacheEntry {
                    path: path.clone(),
                    mtime,
                    len,
                    data: map.clone(),
                });
                return map;
            }
        }
        Map::new()
    }

    /// Persist `config.json` strictly with `0600` permissions and update mtime cache.
    pub fn save_config(&self, data: &Map<String, Value>) {
        {
            let mut guard = self.config_lock.lock().unwrap();
            let _ = self.ensure_config_dir();
            if let Ok(mut json_txt) = serde_json::to_string_pretty(data) {
                json_txt.push('\n');
                if write_secure_file(&self.settings.config_file, json_txt.as_bytes(), 0o600).is_ok() {
                    if let Ok(meta) = fs::metadata(&self.settings.config_file) {
                        if let Ok(mtime) = meta.modified() {
                            *guard = Some(ConfigCacheEntry {
                                path: self.settings.config_file.clone(),
                                mtime,
                                len: meta.len(),
                                data: data.clone(),
                            });
                        } else {
                            *guard = None;
                        }
                    } else {
                        *guard = None;
                    }
                } else {
                    *guard = None;
                }
            } else {
                *guard = None;
            }
        }
        *self.target_user_cache.lock().unwrap() = None;
        self.invalidate_cache(&["target_user"]);
    }

    /// Evaluate a computation function with a per-key TTL cache.
    pub fn cached<F>(&self, key: &str, ttl_sec: f64, force: bool, compute: F) -> Value
    where
        F: FnOnce() -> Value,
    {
        if !force {
            let guard = self.ttl_cache.lock().unwrap();
            if let Some((expires_at, val)) = guard.get(key) {
                if Instant::now() < *expires_at {
                    return val.clone();
                }
            }
        }
        let val = compute();
        let mut guard = self.ttl_cache.lock().unwrap();
        if guard.len() > 256 {
            let now = Instant::now();
            guard.retain(|_, (exp, _)| *exp > now);
            if guard.len() > 256 {
                guard.clear();
            }
        }
        guard.insert(
            key.to_string(),
            (Instant::now() + Duration::from_secs_f64(ttl_sec.max(0.0)), val.clone()),
        );
        val
    }

    /// Invalidate cached entries whose key starts with any supplied prefix.
    pub fn invalidate_cache(&self, prefixes: &[&str]) {
        let mut guard = self.ttl_cache.lock().unwrap();
        if prefixes.is_empty() {
            guard.clear();
            return;
        }
        guard.retain(|k, _| !prefixes.iter().any(|p| k.starts_with(p)));
    }

    /// Append a timestamped entry to the in-memory bounded audit ring buffer.
    pub fn record_audit_event(&self, level: &str, message: impl Into<String>) {
        let lvl = level.trim().to_ascii_uppercase();
        let entry = AuditEntry {
            ts: local_datetime_string(),
            source: "mobile-rc".to_string(),
            level: if lvl.is_empty() { "INFO".to_string() } else { lvl },
            message: message.into(),
        };
        let mut guard = self.audit_log.lock().unwrap();
        if guard.len() >= 150 {
            guard.pop_front();
        }
        guard.push_back(entry);
    }

    pub fn audit_log_tail(&self, max_items: usize) -> Vec<AuditEntry> {
        let guard = self.audit_log.lock().unwrap();
        let skip = guard.len().saturating_sub(max_items);
        guard.iter().skip(skip).cloned().collect()
    }

    pub fn is_auto_tunnel_enabled(&self) -> bool {
        let mut guard = self.auto_tunnel_override.lock().unwrap();
        if let Some(v) = *guard {
            return v;
        }
        let enabled = match std::env::var("MRC_AUTO_TUNNEL")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "1" | "true" | "yes" => true,
            "0" | "false" | "no" => false,
            _ => self
                .get_config()
                .get("auto_tunnel")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        };
        *guard = Some(enabled);
        enabled
    }

    pub fn set_auto_tunnel_override(&self, enabled: bool) {
        *self.auto_tunnel_override.lock().unwrap() = Some(enabled);
    }

    /// Return `(username, uid, gid, home_dir)` of the target desktop user (cached 30s).
    pub fn get_target_user_info(&self) -> TargetUserInfo {
        let mrc_user = std::env::var("MRC_USER").unwrap_or_default();
        let cache_key = format!(
            "{}:{}",
            self.settings.config_file.display(),
            mrc_user.trim()
        );
        {
            let guard = self.target_user_cache.lock().unwrap();
            if let Some((k, exp, info)) = guard.as_ref() {
                if k == &cache_key && Instant::now() < *exp {
                    return info.clone();
                }
            }
        }
        let info = self.compute_target_user_info();
        *self.target_user_cache.lock().unwrap() = Some((
            cache_key,
            Instant::now() + Duration::from_secs(30),
            info.clone(),
        ));
        info
    }

    fn compute_target_user_info(&self) -> TargetUserInfo {
        #[cfg(windows)]
        {
            let user = std::env::var("MRC_USER")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    std::env::var("USERNAME")
                        .ok()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                })
                .or_else(|| {
                    std::env::var("USER")
                        .ok()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                })
                .unwrap_or_else(|| "user".to_string());
            let home = std::env::var("USERPROFILE")
                .or_else(|_| std::env::var("HOME"))
                .unwrap_or_else(|_| r"C:\Users\Default".to_string());
            return TargetUserInfo {
                username: user,
                uid: 0,
                gid: 0,
                home,
            };
        }

        #[cfg(unix)]
        {
            let cfg = self.get_config();
            let cfg_user = cfg
                .get("target_user")
                .or_else(|| cfg.get("user"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            let candidates = [
                std::env::var("MRC_USER").unwrap_or_default().trim().to_string(),
                cfg_user,
                std::env::var("SUDO_USER").unwrap_or_default().trim().to_string(),
                std::env::var("USER").unwrap_or_default().trim().to_string(),
            ];
            for cand in candidates {
                if cand.is_empty() || cand == "root" {
                    continue;
                }
                if let Some(info) = lookup_unix_user(&cand) {
                    if info.uid != 0 {
                        return info;
                    }
                }
            }
            if let Ok(entries) = fs::read_dir("/home") {
                let mut names: Vec<String> = entries
                    .flatten()
                    .filter(|e| e.path().is_dir())
                    .filter_map(|e| e.file_name().into_string().ok())
                    .collect();
                names.sort();
                for name in names {
                    if let Some(info) = lookup_unix_user(&name) {
                        if info.uid >= 1000 {
                            return info;
                        }
                    }
                }
            }
            if let Some(info) = first_human_passwd_user() {
                return info;
            }
            TargetUserInfo {
                username: "root".to_string(),
                uid: 0,
                gid: 0,
                home: "/root".to_string(),
            }
        }
    }

    /// Locate target user's Downloads directory and ensure appropriate ownership.
    pub fn get_downloads_dir(&self) -> PathBuf {
        let user = self.get_target_user_info();
        #[cfg(unix)]
        {
            let xdg_file = Path::new(&user.home).join(".config/user-dirs.dirs");
            if let Ok(raw) = fs::read_to_string(&xdg_file) {
                for line in raw.lines() {
                    let s = line.trim();
                    if let Some(rest) = s.strip_prefix("XDG_DOWNLOAD_DIR=") {
                        let cleaned = rest
                            .trim()
                            .trim_matches('"')
                            .trim_matches('\'')
                            .replace("$HOME", &user.home);
                        let p = PathBuf::from(&cleaned);
                        if p.is_dir() {
                            return p;
                        }
                    }
                }
            }
        }
        let dl = Path::new(&user.home).join("Downloads");
        let _ = fs::create_dir_all(&dl);
        #[cfg(unix)]
        if is_root_or_admin() && user.uid != 0 {
            chown_path(&dl, user.uid, user.gid);
        }
        dl
    }

    pub fn get_ntfy_topic(&self) -> String {
        if let Ok(env_t) = std::env::var("MRC_NTFY_TOPIC") {
            let trimmed = env_t.trim().to_string();
            if !trimmed.is_empty() {
                return trimmed;
            }
        }
        let mut cfg = self.get_config();
        if let Some(t) = cfg.get("ntfy_topic").and_then(|v| v.as_str()) {
            let trimmed = t.trim().to_string();
            if !trimmed.is_empty() {
                return trimmed;
            }
        }
        let topic = format!("mobile-rc-{}", random_hex(12));
        cfg.insert("ntfy_topic".into(), Value::String(topic.clone()));
        self.save_config(&cfg);
        topic
    }

    pub fn get_pin_mode(&self) -> &'static str {
        if let Ok(v) = std::env::var("MRC_PIN") {
            if !v.trim().is_empty() {
                return "static";
            }
        }
        let mode = self
            .get_config()
            .get("pin_mode")
            .and_then(|v| v.as_str())
            .unwrap_or("on_demand")
            .trim()
            .to_ascii_lowercase();
        if mode == "static" {
            "static"
        } else {
            "on_demand"
        }
    }

    pub fn get_termux_token(&self) -> String {
        if let Ok(v) = std::env::var("MRC_TERMUX_TOKEN") {
            let t = v.trim().to_string();
            if !t.is_empty() {
                return t;
            }
        }
        let mut cfg = self.get_config();
        if let Some(t) = cfg.get("termux_token").and_then(|v| v.as_str()) {
            let trimmed = t.trim().to_string();
            if !trimmed.is_empty() {
                return trimmed;
            }
        }
        let tok = random_urlsafe(32);
        cfg.insert("termux_token".into(), Value::String(tok.clone()));
        cfg.entry("pin_mode")
            .or_insert_with(|| Value::String("on_demand".into()));
        self.save_config(&cfg);
        tok
    }

    pub fn get_pin(&self) -> String {
        if let Ok(v) = std::env::var("MRC_PIN") {
            let t = v.trim().to_string();
            if !t.is_empty() {
                return t;
            }
        }
        if let Ok(raw) = fs::read_to_string(&self.settings.pin_file) {
            let pin = raw.trim().to_string();
            if !pin.is_empty() {
                #[cfg(unix)]
                let _ = fs::set_permissions(&self.settings.pin_file, fs::Permissions::from_mode(0o600));
                return pin;
            }
        }
        let pin = random_6digit_code();
        let _ = self.ensure_config_dir();
        let _ = write_secure_file(&self.settings.pin_file, format!("{pin}\n").as_bytes(), 0o600);
        pin
    }

    #[allow(dead_code)]
    pub fn set_pin(&self, new_pin: &str) {
        let _ = self.ensure_config_dir();
        let _ = write_secure_file(
            &self.settings.pin_file,
            format!("{}\n", new_pin.trim()).as_bytes(),
            0o600,
        );
    }

    /// Read merged SMTP + allowed email configuration (environment overrides `config.json`).
    pub fn get_email_otp_settings(&self) -> EmailOtpSettings {
        let cfg = self.get_config();
        let sec = cfg.get("email_otp").and_then(|v| v.as_object());

        let mut enabled = sec
            .and_then(|o| o.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        if let Ok(env_en) = std::env::var("MRC_EMAIL_OTP_ENABLED") {
            match env_en.trim().to_ascii_lowercase().as_str() {
                "0" | "false" | "no" => enabled = false,
                "1" | "true" | "yes" => enabled = true,
                _ => {}
            }
        }

        let smtp_host = std::env::var("MRC_SMTP_HOST")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| {
                sec.and_then(|o| o.get("smtp_host"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .filter(|s| !s.trim().is_empty())
            })
            .unwrap_or_else(|| "smtp.gmail.com".to_string())
            .trim()
            .to_string();

        let smtp_port = std::env::var("MRC_SMTP_PORT")
            .ok()
            .and_then(|s| s.trim().parse::<u16>().ok())
            .or_else(|| {
                sec.and_then(|o| o.get("smtp_port")).and_then(|v| {
                    v.as_u64()
                        .and_then(|n| u16::try_from(n).ok())
                        .or_else(|| v.as_str().and_then(|s| s.trim().parse::<u16>().ok()))
                })
            })
            .filter(|&p| p >= 1)
            .unwrap_or(587);

        let raw_user = std::env::var("MRC_SMTP_USER")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| {
                sec.and_then(|o| o.get("smtp_user"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_default();
        let smtp_user = normalize_email(&raw_user);

        let mut smtp_pass = std::env::var("MRC_SMTP_PASS")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| {
                sec.and_then(|o| o.get("smtp_pass"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_default()
            .trim()
            .to_string();
        if smtp_host.to_ascii_lowercase().ends_with("gmail.com") {
            smtp_pass = smtp_pass.replace(' ', "");
        }

        let mut candidates: Vec<String> = Vec::new();
        if let Ok(raw_allowed) = std::env::var("MRC_ALLOWED_EMAILS") {
            candidates.extend(raw_allowed.split(',').map(|s| s.trim().to_string()));
        } else if let Some(val) = sec.and_then(|o| o.get("allowed_emails")) {
            match val {
                Value::String(s) => candidates.extend(s.split(',').map(|x| x.trim().to_string())),
                Value::Array(arr) => {
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            candidates.push(s.trim().to_string());
                        }
                    }
                }
                _ => {}
            }
        }

        let mut allowed_emails = Vec::new();
        for cand in candidates {
            let norm = normalize_email(&cand);
            if !norm.is_empty() && !allowed_emails.contains(&norm) {
                allowed_emails.push(norm);
            }
        }

        let configured = enabled
            && !smtp_host.is_empty()
            && !smtp_user.is_empty()
            && !smtp_pass.is_empty()
            && !allowed_emails.is_empty();

        EmailOtpSettings {
            configured,
            enabled,
            smtp_host,
            smtp_port,
            smtp_user,
            smtp_pass,
            allowed_emails,
        }
    }
}

/// Validate and normalize an email address, rejecting header injection characters.
pub fn normalize_email(val: &str) -> String {
    let s = val.trim().to_ascii_lowercase();
    if s.is_empty()
        || s.len() > 254
        || s.chars()
            .any(|ch| matches!(ch, '\r' | '\n' | '\0' | '<' | '>' | ' '))
    {
        return String::new();
    }
    let Some((local, domain)) = s.split_once('@') else {
        return String::new();
    };
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return String::new();
    }
    let local_ok = local.chars().all(|c| {
        c.is_ascii_alphanumeric() || ".!#$%&'*+/=?^_`{|}~-".contains(c)
    });
    if !local_ok {
        return String::new();
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2
        || labels
            .iter()
            .any(|l| l.is_empty() || !l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
    {
        return String::new();
    }
    s
}

/// Constant-time allowlist check across normalized recipient addresses.
pub fn is_allowed_email(email_norm: &str, allowed_list: &[String]) -> bool {
    let mut matched = false;
    for cand in allowed_list {
        if ct_eq_str(email_norm, cand) {
            matched = true;
        }
    }
    matched
}

/// Constant-time string comparison.
pub fn ct_eq_str(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    if ab.len() != bb.len() {
        return false;
    }
    bool::from(ab.ct_eq(bb))
}

pub fn ensure_dir_secure(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Create or overwrite a file strictly with private Unix permissions.
pub fn write_secure_file(path: &Path, content: &[u8], mode: u32) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_dir_secure(parent)?;
        }
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(mode);
    let mut f = opts.open(path)?;
    f.write_all(content)?;
    f.sync_all()?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(unix)]
pub fn chown_path(path: &Path, uid: u32, gid: u32) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    if let Ok(cpath) = CString::new(path.as_os_str().as_bytes()) {
        unsafe {
            libc::chown(cpath.as_ptr(), uid as libc::uid_t, gid as libc::gid_t);
        }
    }
}

#[cfg(unix)]
fn lookup_unix_user(name: &str) -> Option<TargetUserInfo> {
    use std::ffi::{CStr, CString};
    static PWD_LOCK: Mutex<()> = Mutex::new(());
    let _g = PWD_LOCK.lock().unwrap();
    let cname = CString::new(name).ok()?;
    unsafe {
        let mut pwd = std::mem::zeroed::<libc::passwd>();
        let mut ptr: *mut libc::passwd = std::ptr::null_mut();
        let mut buf = vec![0 as libc::c_char; 4096];
        let rc = libc::getpwnam_r(
            cname.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut ptr,
        );
        if rc != 0 || ptr.is_null() {
            return None;
        }
        let pw_name = CStr::from_ptr(pwd.pw_name).to_string_lossy().into_owned();
        let pw_dir = CStr::from_ptr(pwd.pw_dir).to_string_lossy().into_owned();
        Some(TargetUserInfo {
            username: pw_name,
            uid: pwd.pw_uid,
            gid: pwd.pw_gid,
            home: pw_dir,
        })
    }
}

#[cfg(unix)]
fn first_human_passwd_user() -> Option<TargetUserInfo> {
    use std::ffi::CStr;
    static PWENT_LOCK: Mutex<()> = Mutex::new(());
    let _g = PWENT_LOCK.lock().unwrap();
    unsafe {
        libc::setpwent();
        let mut found = None;
        loop {
            let ptr = libc::getpwent();
            if ptr.is_null() {
                break;
            }
            let pwd = &*ptr;
            let uid = pwd.pw_uid;
            if (1000..60000).contains(&uid) {
                let shell = if pwd.pw_shell.is_null() {
                    String::new()
                } else {
                    CStr::from_ptr(pwd.pw_shell).to_string_lossy().into_owned()
                };
                if !shell.ends_with("nologin") && !shell.ends_with("false") {
                    found = Some(TargetUserInfo {
                        username: CStr::from_ptr(pwd.pw_name).to_string_lossy().into_owned(),
                        uid,
                        gid: pwd.pw_gid,
                        home: CStr::from_ptr(pwd.pw_dir).to_string_lossy().into_owned(),
                    });
                    break;
                }
            }
        }
        libc::endpwent();
        found
    }
}

pub fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn unix_secs_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Format local wall-clock timestamp as `YYYY-MM-DD HH:MM:SS` without external date crates.
pub fn local_datetime_string() -> String {
    #[cfg(unix)]
    unsafe {
        let now = unix_secs() as libc::time_t;
        let mut tm: libc::tm = std::mem::zeroed();
        if !libc::localtime_r(&now, &mut tm).is_null() {
            return format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                tm.tm_year + 1900,
                tm.tm_mon + 1,
                tm.tm_mday,
                tm.tm_hour,
                tm.tm_min,
                tm.tm_sec
            );
        }
    }
    #[cfg(windows)]
    unsafe {
        #[repr(C)]
        struct SystemTimeWin {
            year: u16,
            month: u16,
            day_of_week: u16,
            day: u16,
            hour: u16,
            minute: u16,
            second: u16,
            milliseconds: u16,
        }
        #[link(name = "kernel32")]
        extern "system" {
            fn GetLocalTime(lp: *mut SystemTimeWin);
        }
        let mut st: SystemTimeWin = std::mem::zeroed();
        GetLocalTime(&mut st);
        return format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            st.year, st.month, st.day, st.hour, st.minute, st.second
        );
    }
    #[allow(unreachable_code)]
    unix_secs().to_string()
}

/// Encode random bytes using unpadded URL-safe Base64 (matching Python `secrets.token_urlsafe`).
pub fn base64url_encode(bytes: &[u8]) -> String {
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = *chunk.get(1).unwrap_or(&0) as usize;
        let b2 = *chunk.get(2).unwrap_or(&0) as usize;
        out.push(TBL[b0 >> 2] as char);
        out.push(TBL[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        if chunk.len() > 1 {
            out.push(TBL[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        }
        if chunk.len() > 2 {
            out.push(TBL[b2 & 0x3f] as char);
        }
    }
    out
}

pub fn random_urlsafe(num_bytes: usize) -> String {
    let mut buf = vec![0u8; num_bytes];
    rand::thread_rng().fill(&mut buf[..]);
    base64url_encode(&buf)
}

pub fn random_hex(num_bytes: usize) -> String {
    let mut buf = vec![0u8; num_bytes];
    rand::thread_rng().fill(&mut buf[..]);
    let mut s = String::with_capacity(num_bytes * 2);
    for b in buf {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

pub fn random_6digit_code() -> String {
    let val: u32 = rand::thread_rng().gen_range(0..1_000_000);
    format!("{val:06}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_email_and_allowlist() {
        assert_eq!(normalize_email("  Alice@Example.COM "), "alice@example.com");
        assert_eq!(normalize_email("bad\r\nheader@example.com"), "");
        assert_eq!(normalize_email("missing-tld@localhost"), "");
        let allowed = vec!["alice@example.com".to_string()];
        assert!(is_allowed_email("alice@example.com", &allowed));
        assert!(!is_allowed_email("bob@example.com", &allowed));
    }

    #[test]
    fn test_ct_eq_and_random_tokens() {
        assert!(ct_eq_str("123456", "123456"));
        assert!(!ct_eq_str("123456", "123457"));
        assert!(!ct_eq_str("123456", "12345"));
        let code = random_6digit_code();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(random_hex(8).len(), 16);
        assert!(random_urlsafe(24).len() >= 32);
    }

    #[test]
    fn test_config_save_and_mtime_cache() {
        let tmp = std::env::temp_dir().join(format!("mrc-test-cfg-{}", random_hex(6)));
        let mut settings = Settings::from_env();
        settings.config_dir = tmp.clone();
        settings.config_file = tmp.join("config.json");
        settings.pin_file = tmp.join("pin.txt");

        let store = ConfigStore::new(settings);
        let mut map = Map::new();
        map.insert("pin_mode".into(), Value::String("on_demand".into()));
        store.save_config(&map);

        let loaded = store.get_config();
        assert_eq!(loaded.get("pin_mode").and_then(|v| v.as_str()), Some("on_demand"));
        #[cfg(unix)]
        {
            let mode = fs::metadata(&store.settings.config_file)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = fs::remove_dir_all(&tmp);
    }
}

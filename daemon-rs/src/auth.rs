//! Authentication, RAC/Email OTP, mobile device Bearer tokens, CSRF/Origin checks, and feedback delivery.

use crate::config::{
    ct_eq_str, normalize_email, random_6digit_code, random_hex, random_urlsafe, unix_secs,
    unix_secs_f64, write_secure_file, ConfigStore, EmailOtpSettings,
};
use crate::telemetry::{
    exec_cmd_blocking, find_bin, get_active_compositor, get_desktop_env, get_hostname,
    get_system_path, url_encode, TelemetryState, IS_WINDOWS,
};
use axum::http::HeaderMap;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::sync::Mutex;

#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub expires: f64,
    pub csrf: String,
    #[allow(dead_code)]
    pub ip: String,
    pub is_bearer: bool,
}

#[derive(Clone, Debug)]
struct AttemptRecord {
    fails: u32,
    locked_until: f64,
}

#[derive(Clone, Debug)]
struct ActiveCode {
    code: String,
    expires: f64,
    source: String,
}

pub struct AuthState {
    sessions: Mutex<HashMap<String, SessionRecord>>,
    handoff_tickets: Mutex<HashMap<String, (f64, String)>>,
    login_attempts: Mutex<HashMap<String, AttemptRecord>>,
    pairing_attempts: Mutex<HashMap<String, AttemptRecord>>,
    email_cooldowns: Mutex<HashMap<String, f64>>,
    email_hourly_ts: Mutex<Vec<f64>>,
    active_code: Mutex<Option<ActiveCode>>,
    feedback_history: Mutex<HashMap<String, Vec<f64>>>,
}

impl Default for AuthState {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthState {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            handoff_tickets: Mutex::new(HashMap::new()),
            login_attempts: Mutex::new(HashMap::new()),
            pairing_attempts: Mutex::new(HashMap::new()),
            email_cooldowns: Mutex::new(HashMap::new()),
            email_hourly_ts: Mutex::new(Vec::new()),
            active_code: Mutex::new(None),
            feedback_history: Mutex::new(HashMap::new()),
        }
    }

    pub fn store_one_time_code(&self, code: String, ttl_sec: u64, source: &str) {
        let mut guard = self.active_code.lock().unwrap();
        *guard = Some(ActiveCode {
            code,
            expires: unix_secs_f64() + ttl_sec as f64,
            source: source.to_string(),
        });
    }

    pub fn issue_one_time_code(&self, cfg: &ConfigStore, source: &str) -> (String, u64) {
        let code = random_6digit_code();
        let ttl = cfg.settings.code_ttl_sec;
        self.store_one_time_code(code.clone(), ttl, source);
        (code, ttl)
    }

    /// Verify supplied access code against active Email RAC, local RAC, or static PIN.
    pub fn verify_login_code(
        &self,
        cfg: &ConfigStore,
        supplied_pin: &str,
        require_email: bool,
    ) -> (bool, &'static str) {
        let now = unix_secs_f64();
        if require_email {
            let mut guard = self.active_code.lock().unwrap();
            let Some(ref ac) = *guard else {
                return (false, "missing");
            };
            if ac.source != "email" {
                return (false, "missing");
            }
            if now >= ac.expires {
                *guard = None;
                return (false, "expired");
            }
            if ct_eq_str(supplied_pin, &ac.code) {
                *guard = None;
                return (true, "ok");
            }
            return (false, "invalid");
        }

        if cfg.get_pin_mode() == "static" {
            {
                let mut guard = self.active_code.lock().unwrap();
                if let Some(ref ac) = *guard {
                    if ac.source == "email" {
                        if now >= ac.expires {
                            *guard = None;
                        } else if ct_eq_str(supplied_pin, &ac.code) {
                            *guard = None;
                            return (true, "ok");
                        }
                    }
                }
            }
            let expected = cfg.get_pin();
            let ok = ct_eq_str(supplied_pin, &expected);
            return (ok, if ok { "ok" } else { "invalid" });
        }

        let mut guard = self.active_code.lock().unwrap();
        let Some(ref ac) = *guard else {
            return (false, "missing");
        };
        if now >= ac.expires {
            *guard = None;
            return (false, "expired");
        }
        if ct_eq_str(supplied_pin, &ac.code) {
            *guard = None;
            return (true, "ok");
        }
        (false, "invalid")
    }

    pub fn get_session_by_cookie(&self, token: &str) -> Option<SessionRecord> {
        let now = unix_secs_f64();
        let mut guard = self.sessions.lock().unwrap();
        let sess = guard.get(token)?.clone();
        if now >= sess.expires {
            guard.remove(token);
            return None;
        }
        Some(sess)
    }

    pub fn create_session(
        &self,
        cfg: &ConfigStore,
        ip: &str,
        clear_login_fails: bool,
        with_handoff: bool,
    ) -> (String, String, Option<String>) {
        let now = unix_secs_f64();
        let session_token = random_urlsafe(32);
        let csrf_token = random_urlsafe(24);
        if clear_login_fails {
            self.login_attempts.lock().unwrap().remove(ip);
        }
        {
            let mut guard = self.sessions.lock().unwrap();
            guard.retain(|_, s| now < s.expires);
            guard.insert(
                session_token.clone(),
                SessionRecord {
                    expires: now + cfg.settings.session_ttl_sec,
                    csrf: csrf_token.clone(),
                    ip: ip.to_string(),
                    is_bearer: false,
                },
            );
        }
        let handoff = if with_handoff {
            let tok = random_urlsafe(24);
            let mut hguard = self.handoff_tickets.lock().unwrap();
            hguard.retain(|_, (exp, _)| now < *exp);
            hguard.insert(tok.clone(), (now + 45.0, ip.to_string()));
            Some(tok)
        } else {
            None
        };
        (session_token, csrf_token, handoff)
    }

    pub fn redeem_handoff(&self, cfg: &ConfigStore, ticket_tok: &str, ip: &str) -> Option<(String, String)> {
        let now = unix_secs_f64();
        let ticket = {
            let mut guard = self.handoff_tickets.lock().unwrap();
            guard.retain(|_, (exp, _)| now < *exp);
            guard.remove(ticket_tok)
        };
        let (exp, _) = ticket?;
        if now >= exp {
            return None;
        }
        let (sess_tok, csrf_tok, _) = self.create_session(cfg, ip, true, false);
        Some((sess_tok, csrf_tok))
    }

    pub fn remove_session(&self, token: &str) {
        self.sessions.lock().unwrap().remove(token);
    }

    pub fn check_login_rate_limit(&self, ip: &str) -> u64 {
        check_rate_limit(&self.login_attempts, ip)
    }

    pub fn record_login_failure(&self, cfg: &ConfigStore, ip: &str) -> bool {
        record_failure(
            &self.login_attempts,
            ip,
            cfg.settings.login_max_fails,
            cfg.settings.login_lockout_sec,
            Some(&self.active_code),
        )
    }

    pub fn check_pairing_rate_limit(&self, ip: &str) -> u64 {
        check_rate_limit(&self.pairing_attempts, ip)
    }

    pub fn record_pairing_failure(&self, cfg: &ConfigStore, ip: &str, invalidate_code: bool) -> bool {
        record_failure(
            &self.pairing_attempts,
            ip,
            cfg.settings.login_max_fails,
            cfg.settings.login_lockout_sec,
            if invalidate_code {
                Some(&self.active_code)
            } else {
                None
            },
        )
    }

    pub fn clear_pairing_failures(&self, ip: &str) {
        self.pairing_attempts.lock().unwrap().remove(ip);
    }

    /// Enforce per-IP cooldown and hourly OTP quota. On success, records cooldown immediately.
    pub fn reserve_email_slot(&self, cfg: &ConfigStore, ip: &str) -> Result<f64, String> {
        let now = unix_secs_f64();
        let mut hguard = self.email_hourly_ts.lock().unwrap();
        hguard.retain(|&t| now - t < 3600.0);

        let mut cguard = self.email_cooldowns.lock().unwrap();
        if cguard.len() > 1000 {
            if let Some(oldest_ip) = cguard
                .iter()
                .min_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(k, _)| k.clone())
            {
                cguard.remove(&oldest_ip);
            }
        }
        let last_ip = cguard.get(ip).copied().unwrap_or(0.0);
        let cooldown = cfg.settings.email_cooldown_sec as f64;
        if now - last_ip < cooldown {
            let wait_s = (cooldown - (now - last_ip)).max(1.0) as u64;
            return Err(format!("Please wait {wait_s}s before requesting another code."));
        }
        if hguard.len() >= cfg.settings.email_hourly_max {
            return Err("Hourly email OTP limit reached. Try again later.".into());
        }
        cguard.insert(ip.to_string(), now);
        Ok(now)
    }

    pub fn commit_email_hourly(&self, ts: f64) {
        self.email_hourly_ts.lock().unwrap().push(ts);
    }

    pub fn check_feedback_rate_limit(&self, ip: &str) -> bool {
        let now = unix_secs_f64();
        let mut guard = self.feedback_history.lock().unwrap();
        if guard.len() > 1000 {
            if let Some(oldest_ip) = guard
                .iter()
                .min_by(|a, b| {
                    let av = a.1.last().copied().unwrap_or(0.0);
                    let bv = b.1.last().copied().unwrap_or(0.0);
                    av.partial_cmp(&bv).unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|(k, _)| k.clone())
            {
                guard.remove(&oldest_ip);
            }
        }
        let hist = guard.entry(ip.to_string()).or_default();
        hist.retain(|&t| (now - t) < 600.0);
        hist.len() < 5
    }

    pub fn record_feedback_submission(&self, ip: &str) -> bool {
        let now = unix_secs_f64();
        let mut guard = self.feedback_history.lock().unwrap();
        let hist = guard.entry(ip.to_string()).or_default();
        hist.retain(|&t| (now - t) < 600.0);
        if hist.len() >= 5 {
            return false;
        }
        hist.push(now);
        true
    }
}

fn check_rate_limit(map: &Mutex<HashMap<String, AttemptRecord>>, ip: &str) -> u64 {
    let now = unix_secs_f64();
    let mut guard = map.lock().unwrap();
    if guard.len() > 1000 {
        if let Some(oldest) = guard
            .iter()
            .min_by(|a, b| {
                a.1.locked_until
                    .partial_cmp(&b.1.locked_until)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(k, _)| k.clone())
        {
            guard.remove(&oldest);
        }
    }
    if let Some(rec) = guard.get(ip) {
        if now < rec.locked_until {
            return (rec.locked_until - now).max(1.0) as u64;
        }
    }
    0
}

fn record_failure(
    map: &Mutex<HashMap<String, AttemptRecord>>,
    ip: &str,
    max_fails: u32,
    lockout_sec: u64,
    active_code: Option<&Mutex<Option<ActiveCode>>>,
) -> bool {
    let now = unix_secs_f64();
    let mut guard = map.lock().unwrap();
    let rec = guard.entry(ip.to_string()).or_insert(AttemptRecord {
        fails: 0,
        locked_until: 0.0,
    });
    rec.fails += 1;
    if rec.fails >= max_fails {
        rec.locked_until = now + lockout_sec as f64;
        rec.fails = 0;
        if let Some(ac) = active_code {
            *ac.lock().unwrap() = None;
        }
        return true;
    }
    false
}

pub fn hash_device_token(raw_token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw_token.as_bytes());
    let digest = hasher.finalize();
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

pub fn register_mobile_device(cfg: &ConfigStore, device_name: &str) -> (String, String) {
    let cleaned: String = device_name
        .chars()
        .map(|c| if matches!(c, '\r' | '\n' | '\t') { ' ' } else { c })
        .collect::<String>()
        .trim()
        .chars()
        .take(64)
        .collect();
    let safe_name = if cleaned.is_empty() {
        "Android Device".to_string()
    } else {
        cleaned
    };

    let raw_token = random_urlsafe(32);
    let dev_id = random_hex(8);
    let now = unix_secs();

    let mut conf = cfg.get_config();
    let mut devices = conf
        .get("mobile_devices")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    devices.push(json!({
        "id": dev_id,
        "name": safe_name,
        "token_hash": hash_device_token(&raw_token),
        "created_at": now,
        "last_seen": now,
    }));
    if devices.len() > 25 {
        devices.drain(0..devices.len() - 25);
    }
    conf.insert("mobile_devices".into(), Value::Array(devices));
    cfg.save_config(&conf);
    cfg.record_audit_event("INFO", format!("Paired mobile device '{safe_name}' (id={dev_id})"));
    (dev_id, raw_token)
}

pub fn verify_mobile_device_token(cfg: &ConfigStore, raw_token: &str) -> Option<Value> {
    if raw_token.len() < 16 {
        return None;
    }
    let supplied_hash = hash_device_token(raw_token);
    let mut conf = cfg.get_config();
    let devices = conf
        .get("mobile_devices")
        .and_then(|v| v.as_array())
        .cloned()?;
    for (idx, dev) in devices.iter().enumerate() {
        let Some(obj) = dev.as_object() else {
            continue;
        };
        let expected_hash = obj.get("token_hash").and_then(|v| v.as_str()).unwrap_or("");
        if !expected_hash.is_empty() && ct_eq_str(&supplied_hash, expected_hash) {
            let now = unix_secs();
            let last_seen = obj.get("last_seen").and_then(|v| v.as_u64()).unwrap_or(0);
            let dev_clone = dev.clone();
            if now.saturating_sub(last_seen) > 300 {
                let mut updated = devices.clone();
                if let Some(m) = updated[idx].as_object_mut() {
                    m.insert("last_seen".into(), json!(now));
                }
                conf.insert("mobile_devices".into(), Value::Array(updated));
                cfg.save_config(&conf);
            }
            return Some(dev_clone);
        }
    }
    None
}

pub fn list_mobile_devices(cfg: &ConfigStore) -> Vec<Value> {
    let conf = cfg.get_config();
    let Some(arr) = conf.get("mobile_devices").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|dev| {
            let obj = dev.as_object()?;
            Some(json!({
                "id": obj.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                "name": obj.get("name").and_then(|v| v.as_str()).unwrap_or("Mobile Device"),
                "created_at": obj.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0),
                "last_seen": obj.get("last_seen").and_then(|v| v.as_u64()).unwrap_or(0),
            }))
        })
        .collect()
}

pub fn revoke_mobile_device(cfg: &ConfigStore, dev_id: &str) -> bool {
    let mut conf = cfg.get_config();
    let Some(devices) = conf.get("mobile_devices").and_then(|v| v.as_array()) else {
        return false;
    };
    let orig_len = devices.len();
    let remaining: Vec<Value> = devices
        .iter()
        .filter(|d| {
            d.as_object()
                .map(|o| o.get("id").and_then(|v| v.as_str()).unwrap_or("") != dev_id)
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    if remaining.len() == orig_len {
        return false;
    }
    conf.insert("mobile_devices".into(), Value::Array(remaining));
    cfg.save_config(&conf);
    cfg.record_audit_event("INFO", format!("Revoked mobile device id={dev_id}"));
    true
}

pub fn is_private_or_loopback(ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return true;
            }
            let segs = v6.segments();
            // fc00::/7 unique local or fe80::/10 link-local
            (segs[0] & 0xfe00) == 0xfc00 || (segs[0] & 0xffc0) == 0xfe80
        }
    }
}

pub fn is_private_or_loopback_str(s: &str) -> bool {
    s.trim()
        .parse::<IpAddr>()
        .map(is_private_or_loopback)
        .unwrap_or(false)
}

pub fn header_str(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

pub fn client_ip(peer: IpAddr, headers: &HeaderMap) -> String {
    let canonical = peer.to_canonical();
    let peer_str = canonical.to_string();
    if is_private_or_loopback(canonical) {
        let cf_ip = header_str(headers, "cf-connecting-ip");
        if !cf_ip.is_empty() {
            return format!("{peer_str}|cf:{cf_ip}");
        }
        let xff = header_str(headers, "x-forwarded-for");
        if let Some(first) = xff.split(',').next().map(str::trim) {
            if !first.is_empty() {
                return format!("{peer_str}|xff:{first}");
            }
        }
    }
    peer_str
}

const PROXY_HEADERS: &[&str] = &[
    "cf-connecting-ip",
    "cf-ray",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "forwarded",
];

pub fn is_loopback_request(peer: IpAddr, headers: &HeaderMap) -> bool {
    if !peer.to_canonical().is_loopback() {
        return false;
    }
    for hdr in PROXY_HEADERS {
        if !header_str(headers, hdr).is_empty() {
            return false;
        }
    }
    true
}

pub fn is_non_local_request(peer: IpAddr, headers: &HeaderMap) -> bool {
    let canonical = peer.to_canonical();
    if !is_private_or_loopback(canonical) {
        return true;
    }
    for hdr in PROXY_HEADERS {
        if !header_str(headers, hdr).is_empty() {
            return true;
        }
    }
    let host_hdr = header_str(headers, "host");
    if !host_hdr.is_empty() {
        let hostname = extract_host_without_port(&host_hdr).to_ascii_lowercase();
        if !hostname.is_empty()
            && hostname != "localhost"
            && !hostname.ends_with(".local")
            && !is_private_or_loopback_str(&hostname)
        {
            return true;
        }
    }
    false
}

fn extract_host_without_port(authority: &str) -> &str {
    let a = authority.trim();
    if let Some(rest) = a.strip_prefix('[') {
        return rest.split(']').next().unwrap_or("");
    }
    a.split(':').next().unwrap_or("")
}

fn extract_url_netloc(url: &str) -> Option<&str> {
    let (_, after_scheme) = url.trim().split_once("://")?;
    let auth = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    if auth.is_empty() {
        None
    } else {
        Some(auth)
    }
}

pub fn check_origin(headers: &HeaderMap) -> Result<(), &'static str> {
    let host = header_str(headers, "host").to_ascii_lowercase();
    let origin = header_str(headers, "origin");
    if !origin.is_empty() {
        let netloc = extract_url_netloc(&origin).unwrap_or("").to_ascii_lowercase();
        if host.is_empty() || netloc != host {
            return Err("Origin mismatch");
        }
        return Ok(());
    }
    let referer = header_str(headers, "referer");
    if !referer.is_empty() {
        let netloc = extract_url_netloc(&referer).unwrap_or("").to_ascii_lowercase();
        if host.is_empty() || netloc != host {
            return Err("Referer mismatch");
        }
    }
    Ok(())
}

pub fn safe_filename(raw_name: &str) -> String {
    let decoded = percent_decode_str(raw_name).trim().to_string();
    if decoded.is_empty()
        || decoded.contains('/')
        || decoded.contains('\\')
        || decoded == "."
        || decoded == ".."
        || decoded.chars().any(|ch| (ch as u32) < 32)
    {
        return String::new();
    }
    decoded
}

pub fn percent_decode_str(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie_hdr = headers.get("cookie").and_then(|v| v.to_str().ok())?;
    for part in cookie_hdr.split(';') {
        if let Some((k, v)) = part.trim().split_once('=') {
            if k.trim() == name {
                let val = v.trim().trim_matches('"');
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

/// Deliver an RFC 5322 email over SMTP TLS/STARTTLS using `curl` (stdin `-K -` hides credentials).
pub fn deliver_smtp_message(
    cfg: &ConfigStore,
    smtp: &EmailOtpSettings,
    to_email: &str,
    subject: &str,
    reply_to: Option<&str>,
    body: &str,
    context_label: &str,
) -> (bool, String) {
    let Some(curl_bin) = find_bin(cfg, "curl", None) else {
        return (false, "curl utility unavailable for SMTP delivery".into());
    };
    let strip_crlf = |s: &str| -> String { s.chars().filter(|&c| c != '\r' && c != '\n').collect() };
    let clean_subject = strip_crlf(subject);
    let smtp_user_clean = strip_crlf(smtp.smtp_user.trim());
    let smtp_pass_clean = strip_crlf(&smtp.smtp_pass);
    let smtp_host_clean = strip_crlf(smtp.smtp_host.trim());
    let clean_to = normalize_email(to_email);
    let recipient = if !clean_to.is_empty() {
        clean_to
    } else {
        strip_crlf(to_email.trim())
    };

    let mut rfc5322 = format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\n",
        smtp_user_clean, recipient, clean_subject
    );
    if let Some(rt) = reply_to {
        let rt_clean = strip_crlf(rt);
        if !rt_clean.is_empty() {
            rfc5322.push_str(&format!("Reply-To: {rt_clean}\r\n"));
        }
    }
    rfc5322.push_str("Content-Type: text/plain; charset=utf-8\r\n\r\n");
    for line in body.lines() {
        rfc5322.push_str(line);
        rfc5322.push_str("\r\n");
    }

    let tmp_mail = std::env::temp_dir().join(format!("mrc-mail-{}.eml", random_hex(8)));
    if let Err(e) = write_secure_file(&tmp_mail, rfc5322.as_bytes(), 0o600) {
        return (false, e.to_string());
    }

    let scheme = if smtp.smtp_port == 465 { "smtps" } else { "smtp" };
    let url = format!("{scheme}://{}:{}", smtp_host_clean, smtp.smtp_port);
    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let cfg_stdin = format!(
        "user = \"{}:{}\"\n",
        esc(&smtp_user_clean),
        esc(&smtp_pass_clean)
    );
    let tmp_str = tmp_mail.to_string_lossy().into_owned();

    let mut env: HashMap<String, String> = std::env::vars().collect();
    env.insert("PATH".into(), get_system_path());
    let (rc, _out, err) = exec_cmd_blocking(
        &curl_bin,
        &[
            "-fsS",
            "--max-time",
            "12",
            "--ssl-reqd",
            "--url",
            &url,
            "--mail-from",
            &smtp_user_clean,
            "--mail-rcpt",
            &recipient,
            "--upload-file",
            &tmp_str,
            "-K",
            "-",
        ],
        &env,
        None,
        14.0,
        Some(cfg_stdin.as_bytes()),
        None,
        false,
        false,
    );
    let _ = fs::remove_file(&tmp_mail);
    if rc == 0 {
        return (true, String::new());
    }
    eprintln!(
        "[Mobile-RC] {context_label} SMTP error ({}:{}): {err}",
        smtp.smtp_host, smtp.smtp_port
    );
    (false, err)
}

pub fn send_otp_email(
    cfg: &ConfigStore,
    to_email: &str,
    code: &str,
    ttl: u64,
    client_hint: &str,
    settings: &EmailOtpSettings,
) -> (bool, String) {
    if !settings.configured {
        return (false, "Email OTP is not configured on host".into());
    }
    let host_name = get_hostname();
    let subject = format!("[Mobile-RC] Access Code: {code}");
    let hint = if client_hint.is_empty() {
        "Remote browser"
    } else {
        client_hint
    };
    let body = format!(
        "Your Mobile-RC one-time access code for {host_name} is:\n\n    {code}\n\nValid for {ttl} seconds (single-use).\nRequested from: {hint}\n\nIf you did not request this code, someone attempted to access your remote dashboard URL.\n"
    );
    deliver_smtp_message(cfg, settings, to_email, &subject, None, &body, "Email OTP")
}

pub fn build_feedback_fallbacks(
    target_email: &str,
    category: &str,
    subject: &str,
    message: &str,
    sysinfo_text: &str,
) -> (String, String) {
    let mut cat_chars = category.chars();
    let cat_title = match cat_chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().collect::<String>() + &cat_chars.as_str().to_ascii_lowercase(),
    };
    let full_subject = format!("[Mobile-RC {cat_title}] {subject}");
    let mut full_body = message.to_string();
    if !sysinfo_text.is_empty() {
        full_body.push_str("\n\n--- System Info ---\n");
        full_body.push_str(sysinfo_text);
    }
    let mailto_url = format!(
        "mailto:{}?subject={}&body={}",
        url_encode(target_email, "@"),
        url_encode(&full_subject, ""),
        url_encode(&full_body, "")
    );
    let github_url = format!(
        "https://github.com/739202873/linux-mobile-remote-control/issues/new?title={}&body={}",
        url_encode(&full_subject, ""),
        url_encode(&full_body, "")
    );
    (mailto_url, github_url)
}

pub fn send_feedback_report(
    cfg: &ConfigStore,
    tel: &TelemetryState,
    category: &str,
    subject: &str,
    message: &str,
    reply_to: &str,
    include_sysinfo: bool,
) -> Value {
    let sysinfo_text = if include_sysinfo {
        let os_info = tel.get_os_info(cfg);
        let env = get_desktop_env(cfg);
        let comp = get_active_compositor(&env);
        format!(
            "OS: {}\nKernel: {}\nInit: {}\nCompositor: {}",
            os_info.get("name").and_then(|v| v.as_str()).unwrap_or(if IS_WINDOWS { "Windows" } else { "Linux" }),
            os_info.get("kernel").and_then(|v| v.as_str()).unwrap_or("-"),
            tel.detect_init_system(cfg),
            if comp.is_empty() { "unknown" } else { comp }
        )
    } else {
        String::new()
    };

    let target_email = &cfg.settings.feedback_target_email;
    let smtp_cfg = cfg.get_email_otp_settings();
    let has_smtp_bot = smtp_cfg.enabled
        && !smtp_cfg.smtp_host.is_empty()
        && !smtp_cfg.smtp_user.is_empty()
        && !smtp_cfg.smtp_pass.is_empty();

    if has_smtp_bot {
        let mut cat_chars = category.chars();
        let cat_title = match cat_chars.next() {
            None => String::new(),
            Some(c) => c.to_uppercase().collect::<String>() + &cat_chars.as_str().to_ascii_lowercase(),
        };
        let mail_subj = format!("[Mobile-RC {cat_title}] {subject}");
        let mut body = format!("Category: {category}\nSubject: {subject}\n");
        if !reply_to.is_empty() {
            body.push_str(&format!("Reply-To: {reply_to}\n"));
        }
        body.push('\n');
        body.push_str(message);
        if !sysinfo_text.is_empty() {
            body.push_str("\n\n--- Host Environment ---\n");
            body.push_str(&sysinfo_text);
        }
        let (ok, _) = deliver_smtp_message(
            cfg,
            &smtp_cfg,
            target_email,
            &mail_subj,
            (!reply_to.is_empty()).then_some(reply_to),
            &body,
            "Feedback",
        );
        if ok {
            cfg.record_audit_event(
                "INFO",
                format!("Sent {category} feedback via local SMTP to {target_email}"),
            );
            return json!({"ok": true, "delivery": "smtp", "message": format!("Feedback sent to {target_email}!")});
        }
    }

    let mut webhook = cfg.settings.feedback_webhook_url.clone();
    if webhook.is_empty() {
        webhook = cfg
            .get_config()
            .get("feedback_webhook")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
    }
    if webhook.starts_with("https://") || webhook.starts_with("http://") {
        if let Some(curl_bin) = find_bin(cfg, "curl", None) {
            let payload = serde_json::to_vec(&json!({
                "source": "mobile-rc",
                "category": category,
                "subject": subject,
                "message": message,
                "reply_to": reply_to,
                "target_email": target_email,
                "sysinfo": sysinfo_text,
            }))
            .unwrap_or_default();
            let mut env: HashMap<String, String> = std::env::vars().collect();
            env.insert("PATH".into(), get_system_path());
            let (rc, _, err) = exec_cmd_blocking(
                &curl_bin,
                &[
                    "-fsS",
                    "--max-time",
                    "10",
                    "-X",
                    "POST",
                    "-H",
                    "Content-Type: application/json",
                    "-H",
                    "Accept: application/json",
                    "--data-binary",
                    "@-",
                    &webhook,
                ],
                &env,
                None,
                11.0,
                Some(&payload),
                None,
                false,
                false,
            );
            if rc == 0 {
                cfg.record_audit_event("INFO", format!("Sent {category} feedback via configured webhook"));
                return json!({"ok": true, "delivery": "webhook", "message": "Feedback delivered via relay webhook!"});
            }
            cfg.record_audit_event("WARN", format!("Feedback webhook delivery failed: {err}"));
        }
    }

    let (mailto_url, github_url) =
        build_feedback_fallbacks(target_email, category, subject, message, &sysinfo_text);
    json!({
        "ok": false,
        "delivery": "fallback",
        "target_email": target_email,
        "mailto": mailto_url,
        "github_issue": github_url,
        "message": "Local SMTP/webhook is not configured on this host; use the Email App or GitHub Issue button below.",
    })
}

/// Inspect Termux helper script candidates on disk cleanly before falling back to embedded script.
pub fn load_control_access_script(cfg: &ConfigStore) -> Vec<u8> {
    let mut candidates = vec![cfg.settings.config_dir.join("termux-control-access.sh")];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("termux").join("control-access"));
            if let Some(parent) = dir.parent() {
                candidates.push(parent.join("share/mobile-rc/termux-control-access.sh"));
            }
        }
    }
    for cand in candidates {
        if cand.is_file() {
            if let Ok(bytes) = fs::read(&cand) {
                return bytes;
            }
        }
    }
    include_bytes!("../../termux/control-access").to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;
    use axum::http::HeaderValue;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn test_store(tag: &str) -> (std::path::PathBuf, ConfigStore) {
        let dir = std::env::temp_dir().join(format!("mrc-auth-{tag}-{}", random_hex(5)));
        let mut s = Settings::from_env();
        s.config_dir = dir.clone();
        s.config_file = dir.join("config.json");
        s.pin_file = dir.join("pin.txt");
        (dir, ConfigStore::new(s))
    }

    #[test]
    fn test_loopback_non_local_and_origin_checks() {
        let mut hdrs = HeaderMap::new();
        hdrs.insert("host", HeaderValue::from_static("127.0.0.1:8000"));
        assert!(is_loopback_request(IpAddr::V4(Ipv4Addr::LOCALHOST), &hdrs));
        assert!(is_loopback_request(
            "::ffff:127.0.0.1".parse().unwrap(),
            &hdrs
        ));
        assert!(!is_non_local_request(IpAddr::V4(Ipv4Addr::LOCALHOST), &hdrs));

        hdrs.insert("cf-connecting-ip", HeaderValue::from_static("1.2.3.4"));
        assert!(!is_loopback_request(IpAddr::V4(Ipv4Addr::LOCALHOST), &hdrs));
        assert!(is_non_local_request(IpAddr::V4(Ipv4Addr::LOCALHOST), &hdrs));

        let mut remote_host = HeaderMap::new();
        remote_host.insert("host", HeaderValue::from_static("demo.lhr.life"));
        assert!(is_non_local_request(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            &remote_host
        ));

        let mut origin_hdrs = HeaderMap::new();
        origin_hdrs.insert("host", HeaderValue::from_static("127.0.0.1:8000"));
        origin_hdrs.insert("origin", HeaderValue::from_static("http://127.0.0.1:8000"));
        assert!(check_origin(&origin_hdrs).is_ok());
        origin_hdrs.insert("origin", HeaderValue::from_static("https://evil.example"));
        assert!(check_origin(&origin_hdrs).is_err());

        assert!(is_private_or_loopback(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_private_or_loopback(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn test_safe_filename_and_fallbacks() {
        assert_eq!(safe_filename("hello%20world.txt"), "hello world.txt");
        assert_eq!(safe_filename("../etc/passwd"), "");
        assert_eq!(safe_filename("bad/name"), "");
        assert_eq!(safe_filename(".."), "");
        let (mailto, gh) =
            build_feedback_fallbacks("a@b.com", "bug", "Title", "Body line", "OS: Linux");
        assert!(mailto.starts_with("mailto:a@b.com?subject=%5BMobile-RC%20Bug%5D"));
        assert!(gh.contains("/issues/new?title="));
    }

    #[test]
    fn test_device_pairing_and_rac_single_use() {
        let (dir, cfg) = test_store("pair");
        let auth = AuthState::new();

        let (code, _ttl) = auth.issue_one_time_code(&cfg, "cli");
        assert_eq!(auth.verify_login_code(&cfg, &code, false), (true, "ok"));
        assert_eq!(auth.verify_login_code(&cfg, &code, false), (false, "missing"));

        auth.store_one_time_code("654321".into(), 180, "cli");
        assert_eq!(auth.verify_login_code(&cfg, "654321", true), (false, "missing"));
        auth.store_one_time_code("112233".into(), 180, "email");
        assert_eq!(auth.verify_login_code(&cfg, "112233", true), (true, "ok"));

        let (id, raw_tok) = register_mobile_device(&cfg, "Pixel Test");
        assert!(verify_mobile_device_token(&cfg, &raw_tok).is_some());
        assert_eq!(list_mobile_devices(&cfg).len(), 1);
        assert!(revoke_mobile_device(&cfg, &id));
        assert!(verify_mobile_device_token(&cfg, &raw_tok).is_none());

        let _ = fs::remove_dir_all(&dir);
    }
}

//! Mobile-RC Cross-Platform Rust Daemon — Axum HTTP/1.1 + UDP LAN Discovery.

mod actions;
mod auth;
mod config;
mod telemetry;

use crate::actions::{
    adjust_brightness, capture_desktop_screenshot, control_service, delayed_power,
    get_window_action_cmds, is_valid_hypr_preset, kill_process, launch_preset_cmds,
    send_remote_input, spawn_terminal_with_command, spawn_tunnel_watchdog,
    spawn_windows_launch, switch_workspace, type_prompt_to_active_window, validate_open_url,
    win_dpms_off, win_lock_workstation, win_open_url, win_send_vk, TunnelManager,
};
use crate::auth::{
    check_origin, client_ip, extract_cookie, header_str, is_loopback_request,
    is_non_local_request, list_mobile_devices, load_control_access_script, register_mobile_device,
    revoke_mobile_device, safe_filename, send_feedback_report, send_otp_email,
    verify_mobile_device_token, AuthState, SessionRecord,
};
use crate::config::{
    ct_eq_str, is_allowed_email, normalize_email, random_6digit_code, unix_secs, ConfigStore,
    Settings,
};
use crate::telemetry::{
    find_bin, get_active_compositor, get_desktop_env, get_hostname, run_as_user, run_cmd,
    run_first_available, url_encode, TelemetryState, IS_WINDOWS,
};
use axum::body::Body;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use futures_util::StreamExt;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

const INDEX_HTML: &str = include_str!("../assets/index.html");

#[derive(Clone)]
struct AppState {
    cfg: Arc<ConfigStore>,
    auth: Arc<AuthState>,
    tel: Arc<TelemetryState>,
    tunnel: Arc<TunnelManager>,
}

fn json_response(status: StatusCode, data: Value, extra: &[(&str, &str)]) -> Response {
    let body = serde_json::to_vec(&data).unwrap_or_else(|_| b"{}".to_vec());
    let mut hdrs = HeaderMap::new();
    hdrs.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    hdrs.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    for (k, v) in extra {
        if let (Ok(hn), Ok(hv)) = (
            header::HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            hdrs.insert(hn, hv);
        }
    }
    (status, hdrs, body).into_response()
}

fn json_ok(data: Value) -> Response {
    json_response(StatusCode::OK, data, &[])
}

fn json_err(status: StatusCode, msg: impl AsRef<str>) -> Response {
    json_response(
        status,
        json!({"ok": false, "message": msg.as_ref()}),
        &[],
    )
}

async fn read_json_object(body: Body, max_bytes: usize) -> Result<Map<String, Value>, Response> {
    let bytes = match axum::body::to_bytes(body, max_bytes).await {
        Ok(b) => b,
        Err(_) => return Err(json_err(StatusCode::PAYLOAD_TOO_LARGE, "JSON request too large")),
    };
    if bytes.is_empty() {
        return Ok(Map::new());
    }
    let text = match std::str::from_utf8(&bytes) {
        Ok(t) => t,
        Err(_) => return Err(json_err(StatusCode::BAD_REQUEST, "Request body must be valid UTF-8")),
    };
    let parsed: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return Err(json_err(StatusCode::BAD_REQUEST, "Malformed JSON payload")),
    };
    match parsed {
        Value::Object(map) => Ok(map),
        _ => Err(json_err(StatusCode::BAD_REQUEST, "JSON payload must be an object")),
    }
}

fn resolve_session(
    state: &AppState,
    peer: IpAddr,
    headers: &HeaderMap,
    request_path: &str,
) -> Option<(String, SessionRecord)> {
    let auth_hdr = header_str(headers, "authorization");
    if let Some(raw_tok) = auth_hdr.strip_prefix("Bearer ").map(str::trim) {
        if !raw_tok.is_empty() && request_path.starts_with("/api/") {
            if let Some(dev) = verify_mobile_device_token(&state.cfg, raw_tok) {
                let dev_id = dev
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("device");
                return Some((
                    format!("bearer:{dev_id}"),
                    SessionRecord {
                        expires: crate::config::unix_secs_f64() + state.cfg.settings.session_ttl_sec,
                        csrf: String::new(),
                        ip: client_ip(peer, headers),
                        is_bearer: true,
                    },
                ));
            }
        }
        return None;
    }
    let tok = extract_cookie(headers, "mrc_session")?;
    let sess = state.auth.get_session_by_cookie(&tok)?;
    Some((tok, sess))
}

fn require_auth(
    state: &AppState,
    peer: IpAddr,
    headers: &HeaderMap,
    request_path: &str,
) -> Result<(String, SessionRecord), Response> {
    resolve_session(state, peer, headers, request_path)
        .ok_or_else(|| json_err(StatusCode::UNAUTHORIZED, "Authentication required"))
}

fn require_csrf(sess: &SessionRecord, headers: &HeaderMap) -> Result<(), Response> {
    if sess.is_bearer {
        return Ok(());
    }
    if let Err(msg) = check_origin(headers) {
        return Err(json_err(StatusCode::FORBIDDEN, msg));
    }
    let supplied = header_str(headers, "x-csrf-token");
    if supplied.is_empty() || !ct_eq_str(&supplied, &sess.csrf) {
        return Err(json_err(
            StatusCode::FORBIDDEN,
            "Invalid or missing CSRF token",
        ));
    }
    Ok(())
}

async fn run_blocking<F, R>(f: F) -> R
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .expect("blocking worker panicked")
}

// === PUBLIC GET ROUTES ===

async fn handle_index() -> Response {
    let mut hdrs = HeaderMap::new();
    hdrs.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    hdrs.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    hdrs.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    hdrs.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    (StatusCode::OK, hdrs, INDEX_HTML).into_response()
}

async fn handle_control_access_asset(State(state): State<AppState>) -> Response {
    let cfg = Arc::clone(&state.cfg);
    let body = run_blocking(move || load_control_access_script(&cfg)).await;
    if body.is_empty() {
        return (StatusCode::NOT_FOUND, "Termux helper script not installed").into_response();
    }
    let mut hdrs = HeaderMap::new();
    hdrs.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/x-shellscript; charset=utf-8"),
    );
    hdrs.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    hdrs.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    (StatusCode::OK, hdrs, body).into_response()
}

async fn handle_auth_status(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let peer = addr.ip();
    let sess = resolve_session(&state, peer, &headers, "/api/auth/status").map(|x| x.1);
    let st = state.clone();
    let non_local = is_non_local_request(peer, &headers);
    let payload = run_blocking(move || {
        let email_cfg = st.cfg.get_email_otp_settings();
        json!({
            "authenticated": sess.is_some(),
            "csrf_token": sess.as_ref().map(|s| s.csrf.as_str()).unwrap_or(""),
            "pin_mode": st.cfg.get_pin_mode(),
            "is_non_local": non_local,
            "email_otp_enabled": email_cfg.configured,
        })
    })
    .await;
    json_ok(payload)
}

// === AUTHENTICATED GET ROUTES ===

async fn handle_status(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(qs): Query<HashMap<String, String>>,
) -> Response {
    if let Err(r) = require_auth(&state, addr.ip(), &headers, "/api/status") {
        return r;
    }
    let refresh = matches!(
        qs.get("refresh")
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1" | "true" | "yes")
    );
    let data = run_blocking(move || {
        if refresh {
            state
                .cfg
                .invalidate_cache(&["local_ips", "gpu_info", "media_display"]);
        }
        json!({
            "os": state.tel.get_os_info(&state.cfg),
            "init_system": state.tel.detect_init_system(&state.cfg),
            "cpu_pct": state.tel.get_cpu_percent(),
            "cpu_temp": state.tel.get_cpu_temp(&state.cfg),
            "ram": state.tel.get_memory_info(),
            "swap": state.tel.get_swap_info(),
            "gpu": state.tel.get_gpu_info(&state.cfg),
            "battery": state.tel.get_battery_info(),
            "network": state.tel.get_network_telemetry(&state.cfg),
            "media": state.tel.get_media_and_display(&state.cfg),
            "workspaces": state.tel.get_workspaces_info(&state.cfg),
            "disks": state.tel.get_disks_info(&state.cfg, refresh),
            "boot_entries": state.tel.get_boot_entries(&state.cfg, refresh),
            "ips": state.tel.get_local_ips(&state.cfg),
            "tunnel": state.tunnel.get_tunnel_info(&state.cfg),
        })
    })
    .await;
    json_ok(data)
}

async fn handle_telemetry(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = require_auth(&state, addr.ip(), &headers, "/api/telemetry") {
        return r;
    }
    let data = run_blocking(move || {
        json!({
            "os": state.tel.get_os_info(&state.cfg),
            "init_system": state.tel.detect_init_system(&state.cfg),
            "cpu_pct": state.tel.get_cpu_percent(),
            "cpu_temp": state.tel.get_cpu_temp(&state.cfg),
            "ram": state.tel.get_memory_info(),
            "swap": state.tel.get_swap_info(),
            "gpu": state.tel.get_gpu_info(&state.cfg),
            "battery": state.tel.get_battery_info(),
            "network": state.tel.get_network_telemetry(&state.cfg),
            "media": state.tel.get_media_and_display(&state.cfg),
            "workspaces": state.tel.get_workspaces_info(&state.cfg),
            "disks": state.tel.get_disks_info(&state.cfg, false),
            "ips": state.tel.get_local_ips(&state.cfg),
            "tunnel": state.tunnel.get_tunnel_info(&state.cfg),
        })
    })
    .await;
    json_ok(data)
}

async fn handle_logs(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(qs): Query<HashMap<String, String>>,
) -> Response {
    if let Err(r) = require_auth(&state, addr.ip(), &headers, "/api/logs") {
        return r;
    }
    let src = qs.get("source").cloned().unwrap_or_else(|| "all".into());
    let lvl = qs.get("level").cloned().unwrap_or_else(|| "all".into());
    let q = qs.get("q").cloned().unwrap_or_default();
    let lines = qs.get("lines").cloned().unwrap_or_else(|| "120".into());
    let data = run_blocking(move || state.tel.get_system_logs(&state.cfg, &src, &lvl, &q, &lines))
        .await;
    json_ok(data)
}

async fn handle_distros(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(qs): Query<HashMap<String, String>>,
) -> Response {
    if let Err(r) = require_auth(&state, addr.ip(), &headers, "/api/distros") {
        return r;
    }
    let deep = matches!(
        qs.get("deep").map(|s| s.trim().to_ascii_lowercase()).as_deref(),
        Some("1" | "true" | "yes")
    );
    let refresh = matches!(
        qs.get("refresh").map(|s| s.trim().to_ascii_lowercase()).as_deref(),
        Some("1" | "true" | "yes")
    );
    let data =
        run_blocking(move || state.tel.get_installed_distros_info(&state.cfg, deep, refresh)).await;
    json_ok(data)
}

async fn handle_services(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = require_auth(&state, addr.ip(), &headers, "/api/services") {
        return r;
    }
    let data = run_blocking(move || state.tel.get_services_info(&state.cfg)).await;
    json_ok(data)
}

async fn handle_processes(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(qs): Query<HashMap<String, String>>,
) -> Response {
    if let Err(r) = require_auth(&state, addr.ip(), &headers, "/api/processes") {
        return r;
    }
    let limit = qs
        .get("limit")
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(30);
    let data = run_blocking(move || state.tel.get_processes_info(limit)).await;
    json_ok(data)
}

async fn handle_mobile_devices(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = require_auth(&state, addr.ip(), &headers, "/api/mobile/devices") {
        return r;
    }
    let devices = run_blocking(move || list_mobile_devices(&state.cfg)).await;
    json_ok(json!({"ok": true, "devices": devices}))
}

async fn handle_screenshot(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = require_auth(&state, addr.ip(), &headers, "/api/screenshot") {
        return r;
    }
    let shot = run_blocking(move || capture_desktop_screenshot(&state.cfg)).await;
    let Some((img, ctype)) = shot else {
        return (StatusCode::NOT_FOUND, "Failed to capture desktop screen").into_response();
    };
    let mut hdrs = HeaderMap::new();
    hdrs.insert(header::CONTENT_TYPE, HeaderValue::from_static(ctype));
    hdrs.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    hdrs.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    (StatusCode::OK, hdrs, img).into_response()
}

async fn handle_files(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = require_auth(&state, addr.ip(), &headers, "/api/files") {
        return r;
    }
    let files = run_blocking(move || {
        let dl_dir = state.cfg.get_downloads_dir();
        let _ = fs::create_dir_all(&dl_dir);
        let mut items: Vec<(std::time::SystemTime, Value)> = Vec::new();
        if let Ok(rd) = fs::read_dir(&dl_dir) {
            for entry in rd.flatten() {
                let Ok(meta) = fs::symlink_metadata(entry.path()) else {
                    continue;
                };
                if meta.file_type().is_symlink() || !meta.is_file() {
                    continue;
                }
                let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
                let sz = meta.len();
                let sz_str = if sz >= 1024 * 1024 {
                    format!("{:.1} MB", sz as f64 / (1024.0 * 1024.0))
                } else {
                    format!("{:.1} KB", sz as f64 / 1024.0)
                };
                let name = entry.file_name().to_string_lossy().into_owned();
                items.push((mtime, json!({"name": name, "size": sz_str})));
            }
        }
        items.sort_by_key(|a| std::cmp::Reverse(a.0));
        items.into_iter().take(50).map(|x| x.1).collect::<Vec<Value>>()
    })
    .await;
    json_ok(json!({"files": files}))
}

fn guess_mime_type(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        "json" => "application/json",
        "txt" | "log" | "md" => "text/plain; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "tar" => "application/x-tar",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "apk" => "application/vnd.android.package-archive",
        _ => "application/octet-stream",
    }
}

async fn handle_download(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(qs): Query<HashMap<String, String>>,
) -> Response {
    if let Err(r) = require_auth(&state, addr.ip(), &headers, "/api/download") {
        return r;
    }
    let raw_name = qs.get("name").map(String::as_str).unwrap_or("");
    let name = safe_filename(raw_name);
    if name.is_empty() {
        return json_err(StatusCode::BAD_REQUEST, "Invalid file name");
    }
    let cfg = Arc::clone(&state.cfg);
    let name_c = name.clone();
    enum DownloadLookup {
        Symlink,
        NotFound,
        Ready { real_file: std::path::PathBuf, sz: u64 },
    }
    let lookup = run_blocking(move || {
        let dl_dir = cfg.get_downloads_dir();
        let fpath = dl_dir.join(&name_c);
        if let Ok(sm) = fs::symlink_metadata(&fpath) {
            if sm.file_type().is_symlink() {
                return DownloadLookup::Symlink;
            }
        }
        let Ok(real_base) = fs::canonicalize(&dl_dir) else {
            return DownloadLookup::NotFound;
        };
        let Ok(real_file) = fs::canonicalize(&fpath) else {
            return DownloadLookup::NotFound;
        };
        if !real_file.starts_with(&real_base) || !real_file.is_file() {
            return DownloadLookup::NotFound;
        }
        let sz = fs::metadata(&real_file).map(|m| m.len()).unwrap_or(0);
        DownloadLookup::Ready { real_file, sz }
    })
    .await;

    let (real_file, sz) = match lookup {
        DownloadLookup::Symlink => return json_err(StatusCode::FORBIDDEN, "Symlinks are not allowed"),
        DownloadLookup::NotFound => return (StatusCode::NOT_FOUND, "File not found").into_response(),
        DownloadLookup::Ready { real_file, sz } => (real_file, sz),
    };

    let Ok(file) = tokio::fs::File::open(&real_file).await else {
        return (StatusCode::NOT_FOUND, "File not found").into_response();
    };

    let stream = futures_util::stream::unfold(file, |mut f| async move {
        let mut buf = vec![0u8; 65536];
        match f.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((Ok::<Vec<u8>, std::io::Error>(buf), f))
            }
            Err(e) => Some((Err(e), f)),
        }
    });

    let ctype = guess_mime_type(&real_file);
    let safe_disp: String = name
        .chars()
        .filter(|&c| c != '"' && c != '\r' && c != '\n')
        .collect();
    let enc_name = url_encode(&name, "");
    let disp = format!("attachment; filename=\"{safe_disp}\"; filename*=UTF-8''{enc_name}");

    let mut hdrs = HeaderMap::new();
    hdrs.insert(header::CONTENT_TYPE, HeaderValue::from_static(ctype));
    if let Ok(hv) = HeaderValue::from_str(&sz.to_string()) {
        hdrs.insert(header::CONTENT_LENGTH, hv);
    }
    hdrs.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if let Ok(hv) = HeaderValue::from_str(&disp) {
        hdrs.insert(header::CONTENT_DISPOSITION, hv);
    }
    hdrs.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));

    (StatusCode::OK, hdrs, Body::from_stream(stream)).into_response()
}

// === PUBLIC / PAIRING POST ROUTES ===

async fn handle_mobile_pair(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Err(msg) = check_origin(&headers) {
        return json_err(StatusCode::FORBIDDEN, msg);
    }
    let peer = addr.ip();
    let ip = client_ip(peer, &headers);
    let wait_sec = state.auth.check_pairing_rate_limit(&ip);
    if wait_sec > 0 {
        return json_err(
            StatusCode::TOO_MANY_REQUESTS,
            format!("Too many pairing attempts. Try again in {wait_sec}s."),
        );
    }
    let data = match read_json_object(body, state.cfg.settings.max_json_bytes).await {
        Ok(m) => m,
        Err(r) => return r,
    };

    let device_name = data
        .get("device_name")
        .and_then(|v| v.as_str())
        .unwrap_or("Mobile-RC App")
        .trim()
        .to_string();
    let auth_hdr = header_str(&headers, "authorization");
    let supplied_tok = auth_hdr
        .strip_prefix("Bearer ")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| {
            data.get("pairing_token")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string()
        });

    let is_loopback = is_loopback_request(peer, &headers);
    let is_remote = is_non_local_request(peer, &headers);
    let expected_tok = state.cfg.get_termux_token();

    let mut authorized = false;
    let mut used_pin_auth = false;
    if !supplied_tok.is_empty() && is_loopback && ct_eq_str(&supplied_tok, &expected_tok) {
        authorized = true;
    } else if let Some(pin_val) = data.get("pin") {
        used_pin_auth = true;
        let pin_str = value_as_str(pin_val);
        let (pin_ok, _) = state
            .auth
            .verify_login_code(&state.cfg, &pin_str, is_remote);
        if pin_ok {
            authorized = true;
        }
    } else if let Some((_, sess)) = resolve_session(&state, peer, &headers, "/api/mobile/pair") {
        if sess.is_bearer {
            authorized = true;
        } else {
            let supplied_csrf = header_str(&headers, "x-csrf-token");
            if !supplied_csrf.is_empty() && ct_eq_str(&supplied_csrf, &sess.csrf) {
                authorized = true;
            }
        }
    }

    if !authorized {
        let invalidate = used_pin_auth && state.cfg.get_pin_mode() != "static";
        let locked = state
            .auth
            .record_pairing_failure(&state.cfg, &ip, invalidate);
        if locked {
            return json_err(
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "Too many invalid attempts. Locked for {}s.",
                    state.cfg.settings.login_lockout_sec
                ),
            );
        }
        return json_err(StatusCode::UNAUTHORIZED, "Invalid pairing token or PIN");
    }

    state.auth.clear_pairing_failures(&ip);
    let st = state.clone();
    let payload = run_blocking(move || {
        let (dev_id, raw_device_token) = register_mobile_device(&st.cfg, &device_name);
        json!({
            "ok": true,
            "token": raw_device_token,
            "device_id": dev_id,
            "device": {"id": dev_id, "name": if device_name.is_empty() { "Mobile-RC App" } else { &device_name }},
            "host": st.tel.get_os_info(&st.cfg),
            "init_system": st.tel.detect_init_system(&st.cfg),
            "macs": st.tel.get_mac_addresses(&st.cfg),
            "ips": st.tel.get_local_ips(&st.cfg),
            "port": st.cfg.settings.port,
        })
    })
    .await;
    json_ok(payload)
}

async fn handle_pairing_code(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let peer = addr.ip();
    let ip = client_ip(peer, &headers);
    if !is_loopback_request(peer, &headers) {
        state.cfg.record_audit_event(
            "WARN",
            format!("Blocked non-loopback RAC generation attempt from {ip}"),
        );
        return json_err(
            StatusCode::FORBIDDEN,
            "Random Access Code (RAC) can only be generated on the host PC/Laptop (sudo control-access).",
        );
    }
    if let Err(msg) = check_origin(&headers) {
        return json_err(StatusCode::FORBIDDEN, msg);
    }
    let wait_sec = state.auth.check_pairing_rate_limit(&ip);
    if wait_sec > 0 {
        return json_err(
            StatusCode::TOO_MANY_REQUESTS,
            format!("Too many invalid token attempts. Try again in {wait_sec}s."),
        );
    }
    let auth_hdr = header_str(&headers, "authorization");
    let supplied_tok = auth_hdr
        .strip_prefix("Bearer ")
        .map(str::trim)
        .unwrap_or("");
    let expected_tok = state.cfg.get_termux_token();
    if supplied_tok.is_empty() || !ct_eq_str(supplied_tok, &expected_tok) {
        let locked = state.auth.record_pairing_failure(&state.cfg, &ip, false);
        if locked {
            return json_err(
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "Too many invalid token attempts. Locked for {}s.",
                    state.cfg.settings.login_lockout_sec
                ),
            );
        }
        return json_err(
            StatusCode::UNAUTHORIZED,
            "Invalid or missing pairing token",
        );
    }
    state.auth.clear_pairing_failures(&ip);
    let st = state.clone();
    let payload = run_blocking(move || {
        let (code, ttl) = st.auth.issue_one_time_code(&st.cfg, "cli");
        let tunnel_info = st.tunnel.get_tunnel_info(&st.cfg);
        json!({
            "ok": true,
            "code": code,
            "expires_in": ttl,
            "ips": st.tel.get_local_ips(&st.cfg),
            "port": st.cfg.settings.port,
            "tunnel_url": tunnel_info.get("url").and_then(|v| v.as_str()).unwrap_or(""),
        })
    })
    .await;
    json_ok(payload)
}

async fn handle_pairing_email_code(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Err(msg) = check_origin(&headers) {
        return json_err(StatusCode::FORBIDDEN, msg);
    }
    let data = match read_json_object(body, state.cfg.settings.max_json_bytes).await {
        Ok(m) => m,
        Err(r) => return r,
    };
    let raw_email = data.get("email").and_then(|v| v.as_str()).unwrap_or("");
    let email_norm = normalize_email(raw_email);
    if email_norm.is_empty() {
        return json_err(StatusCode::BAD_REQUEST, "Please enter a valid email address.");
    }
    let email_cfg = state.cfg.get_email_otp_settings();
    if !email_cfg.configured {
        return json_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Email OTP is not configured on host. Run: sudo control-access --setup-email",
        );
    }
    let ip = client_ip(addr.ip(), &headers);
    let reserved_now = match state.auth.reserve_email_slot(&state.cfg, &ip) {
        Ok(t) => t,
        Err(msg) => return json_err(StatusCode::TOO_MANY_REQUESTS, msg),
    };
    let ttl = state.cfg.settings.code_ttl_sec;
    let generic_ok =
        format!("If this email is registered, a 6-digit code has been sent (valid {ttl}s).");
    if !is_allowed_email(&email_norm, &email_cfg.allowed_emails) {
        return json_ok(json!({"ok": true, "message": generic_ok}));
    }

    let code = random_6digit_code();
    let cfg = Arc::clone(&state.cfg);
    let e_clone = email_norm.clone();
    let c_clone = code.clone();
    let ip_clone = ip.clone();
    let (ok_send, _) = run_blocking(move || {
        send_otp_email(&cfg, &e_clone, &c_clone, ttl, &ip_clone, &email_cfg)
    })
    .await;
    if !ok_send {
        return json_err(
            StatusCode::BAD_GATEWAY,
            "Failed to send email via host SMTP. Check SMTP/App Password settings.",
        );
    }
    state.auth.commit_email_hourly(reserved_now);
    state.auth.store_one_time_code(code, ttl, "email");
    json_ok(json!({"ok": true, "message": generic_ok}))
}

async fn handle_login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Err(msg) = check_origin(&headers) {
        return json_err(StatusCode::FORBIDDEN, msg);
    }
    let data = match read_json_object(body, state.cfg.settings.max_json_bytes).await {
        Ok(m) => m,
        Err(r) => return r,
    };
    let peer = addr.ip();
    let ip = client_ip(peer, &headers);
    let wait_sec = state.auth.check_login_rate_limit(&ip);
    if wait_sec > 0 {
        return json_err(
            StatusCode::TOO_MANY_REQUESTS,
            format!("Too many failed attempts. Try again in {wait_sec}s."),
        );
    }

    let handoff_in = data
        .get("handoff_token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if !handoff_in.is_empty() {
        if let Some((sess_tok, csrf_tok)) = state.auth.redeem_handoff(&state.cfg, handoff_in, &ip) {
            let cookie = format!(
                "mrc_session={sess_tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
                state.cfg.settings.session_ttl_sec as u64
            );
            return json_response(
                StatusCode::OK,
                json!({"ok": true, "csrf_token": csrf_tok}),
                &[("Set-Cookie", &cookie)],
            );
        }
        return json_err(
            StatusCode::UNAUTHORIZED,
            "Invalid or expired login ticket",
        );
    }

    let is_remote = is_non_local_request(peer, &headers);
    let supplied_pin = data
        .get("pin")
        .map(value_as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    let (ok, reason) = state
        .auth
        .verify_login_code(&state.cfg, &supplied_pin, is_remote);
    if ok {
        let want_handoff = data
            .get("handoff")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let (sess_tok, csrf_tok, handoff_out) =
            state
                .auth
                .create_session(&state.cfg, &ip, true, want_handoff);
        let cookie = format!(
            "mrc_session={sess_tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
            state.cfg.settings.session_ttl_sec as u64
        );
        let mut resp_obj = Map::new();
        resp_obj.insert("ok".into(), Value::Bool(true));
        resp_obj.insert("csrf_token".into(), Value::String(csrf_tok));
        if let Some(h) = handoff_out {
            resp_obj.insert("handoff_token".into(), Value::String(h));
        }
        return json_response(
            StatusCode::OK,
            Value::Object(resp_obj),
            &[("Set-Cookie", &cookie)],
        );
    }

    let locked = state.auth.record_login_failure(&state.cfg, &ip);
    if locked {
        return json_err(
            StatusCode::TOO_MANY_REQUESTS,
            format!(
                "Too many failed attempts. Locked for {}s.",
                state.cfg.settings.login_lockout_sec
            ),
        );
    }

    let msg = match (is_remote, reason) {
        (true, "missing") => "No active Email RAC. Request a 6-digit code via Email above first.",
        (true, "expired") => "Email RAC expired. Request a new Email code to continue.",
        (false, "missing") => "No active RAC. Run 'sudo control-access' on your PC/Laptop first.",
        (false, "expired") => {
            "RAC expired. Run 'sudo control-access' on your PC/Laptop for a new one."
        }
        _ => "Invalid code",
    };
    json_err(StatusCode::UNAUTHORIZED, msg)
}

// === AUTHENTICATED POST ROUTES ===

async fn handle_logout(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let (token, sess) = match require_auth(&state, addr.ip(), &headers, "/api/logout") {
        Ok(x) => x,
        Err(r) => return r,
    };
    if let Err(r) = require_csrf(&sess, &headers) {
        return r;
    }
    state.auth.remove_session(&token);
    json_response(
        StatusCode::OK,
        json!({"ok": true, "message": "Locked"}),
        &[(
            "Set-Cookie",
            "mrc_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        )],
    )
}

async fn handle_upload(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(qs): Query<HashMap<String, String>>,
    body: Body,
) -> Response {
    let (_, sess) = match require_auth(&state, addr.ip(), &headers, "/api/upload") {
        Ok(x) => x,
        Err(r) => return r,
    };
    if let Err(r) = require_csrf(&sess, &headers) {
        return r;
    }

    let raw_name = qs
        .get("name")
        .filter(|s| !s.is_empty())
        .cloned()
        .unwrap_or_else(|| format!("upload_{}.bin", unix_secs()));
    let name = safe_filename(&raw_name);
    if name.is_empty() {
        return json_err(StatusCode::BAD_REQUEST, "Invalid upload filename");
    }

    let raw_len = header_str(&headers, "content-length");
    let length: u64 = match raw_len.parse::<u64>() {
        Ok(v) => v,
        Err(_) => return json_err(StatusCode::BAD_REQUEST, "Valid Content-Length required"),
    };
    let max_bytes = state.cfg.settings.max_upload_bytes;
    if length > max_bytes {
        return json_err(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("Upload exceeds {} MB limit", max_bytes / (1024 * 1024)),
        );
    }

    let cfg = Arc::clone(&state.cfg);
    let name_c = name.clone();
    let (dest, final_name, user_uid, user_gid) = run_blocking(move || {
        let dl_dir = cfg.get_downloads_dir();
        let user = cfg.get_target_user_info();
        let _ = fs::create_dir_all(&dl_dir);

        let p = Path::new(&name_c);
        let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or(&name_c);
        let ext = p.extension().and_then(|s| s.to_str()).map(|e| format!(".{e}")).unwrap_or_default();

        let mut final_name = name_c.clone();
        let mut dest = dl_dir.join(&final_name);
        let mut idx = 1usize;
        while dest.exists() || fs::symlink_metadata(&dest).is_ok() {
            final_name = format!("{stem}_{idx}{ext}");
            dest = dl_dir.join(&final_name);
            idx += 1;
        }
        (dest, final_name, user.uid, user.gid)
    })
    .await;

    let mut file = match tokio::fs::File::create(&dest).await {
        Ok(f) => f,
        Err(e) => return json_err(StatusCode::BAD_REQUEST, format!("Upload failed: {e}")),
    };

    let mut total_read = 0u64;
    let mut stream = body.into_data_stream();
    while let Some(chunk_res) = stream.next().await {
        let chunk = match chunk_res {
            Ok(c) => c,
            Err(e) => {
                let _ = tokio::fs::remove_file(&dest).await;
                return json_err(StatusCode::BAD_REQUEST, format!("Upload failed: {e}"));
            }
        };
        total_read = total_read.saturating_add(chunk.len() as u64);
        if total_read > max_bytes || total_read > length {
            let _ = tokio::fs::remove_file(&dest).await;
            let status = if total_read > max_bytes {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::BAD_REQUEST
            };
            let msg = if total_read > max_bytes {
                "Upload exceeded size limit"
            } else {
                "Upload exceeded Content-Length"
            };
            return json_err(status, msg);
        }
        if let Err(e) = file.write_all(&chunk).await {
            let _ = tokio::fs::remove_file(&dest).await;
            return json_err(StatusCode::BAD_REQUEST, format!("Upload failed: {e}"));
        }
    }
    if let Err(e) = file.flush().await {
        let _ = tokio::fs::remove_file(&dest).await;
        return json_err(StatusCode::BAD_REQUEST, format!("Upload failed: {e}"));
    }
    if total_read != length {
        let _ = tokio::fs::remove_file(&dest).await;
        return json_err(StatusCode::BAD_REQUEST, "Incomplete upload stream");
    }

    #[cfg(unix)]
    if crate::config::is_root_or_admin() && user_uid != 0 {
        crate::config::chown_path(&dest, user_uid, user_gid);
    }
    #[cfg(not(unix))]
    let _ = (user_uid, user_gid);

    json_ok(json!({
        "ok": true,
        "filename": final_name,
        "message": format!("File '{final_name}' saved to ~/Downloads!"),
    }))
}

async fn handle_media(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let (_, sess) = match require_auth(&state, addr.ip(), &headers, "/api/media") {
        Ok(x) => x,
        Err(r) => return r,
    };
    if let Err(r) = require_csrf(&sess, &headers) {
        return r;
    }
    let data = match read_json_object(body, state.cfg.settings.max_json_bytes).await {
        Ok(m) => m,
        Err(r) => return r,
    };

    let act = data
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let val = data.get("value").cloned().unwrap_or(Value::Null);

    run_blocking(move || {
        match act.as_str() {
            "play-pause" => {
                if IS_WINDOWS {
                    win_send_vk(0xB3, false);
                } else {
                    let _ = run_as_user(&state.cfg, &["playerctl", "play-pause"], 8.0, None, None, false, false);
                }
            }
            "next" => {
                if IS_WINDOWS {
                    win_send_vk(0xB0, false);
                } else {
                    let _ = run_as_user(&state.cfg, &["playerctl", "next"], 8.0, None, None, false, false);
                }
            }
            "prev" => {
                if IS_WINDOWS {
                    win_send_vk(0xB1, false);
                } else {
                    let _ = run_as_user(&state.cfg, &["playerctl", "previous"], 8.0, None, None, false, false);
                }
            }
            "mute" => {
                if IS_WINDOWS {
                    win_send_vk(0xAD, false);
                } else {
                    let cmds = vec![
                        vec!["wpctl".into(), "set-mute".into(), "@DEFAULT_AUDIO_SINK@".into(), "toggle".into()],
                        vec!["pactl".into(), "set-sink-mute".into(), "@DEFAULT_SINK@".into(), "toggle".into()],
                        vec!["amixer".into(), "set".into(), "Master".into(), "toggle".into()],
                    ];
                    let _ = run_first_available(&state.cfg, &cmds, 8.0, None, false, false);
                }
            }
            "vol_up" => {
                if IS_WINDOWS {
                    win_send_vk(0xAF, false);
                } else {
                    let cmds = vec![
                        vec!["wpctl".into(), "set-volume".into(), "-l".into(), "1.5".into(), "@DEFAULT_AUDIO_SINK@".into(), "5%+".into()],
                        vec!["pactl".into(), "set-sink-volume".into(), "@DEFAULT_SINK@".into(), "+5%".into()],
                        vec!["amixer".into(), "set".into(), "Master".into(), "5%+".into()],
                    ];
                    let _ = run_first_available(&state.cfg, &cmds, 8.0, None, false, false);
                }
            }
            "vol_down" => {
                if IS_WINDOWS {
                    win_send_vk(0xAE, false);
                } else {
                    let cmds = vec![
                        vec!["wpctl".into(), "set-volume".into(), "@DEFAULT_AUDIO_SINK@".into(), "5%-".into()],
                        vec!["pactl".into(), "set-sink-volume".into(), "@DEFAULT_SINK@".into(), "-5%".into()],
                        vec!["amixer".into(), "set".into(), "Master".into(), "5%-".into()],
                    ];
                    let _ = run_first_available(&state.cfg, &cmds, 8.0, None, false, false);
                }
            }
            "vol_set" => {
                let Some(pct_f) = crate::actions::val_as_f64(&val) else {
                    return json_err(StatusCode::BAD_REQUEST, "Invalid volume value");
                };
                let pct = (pct_f as i64).clamp(0, 150);
                if IS_WINDOWS {
                    crate::telemetry::win_coreaudio_set(&state.cfg, pct.min(100));
                } else {
                    let p_str = format!("{pct}%");
                    let cmds = vec![
                        vec!["wpctl".into(), "set-volume".into(), "@DEFAULT_AUDIO_SINK@".into(), p_str.clone()],
                        vec!["pactl".into(), "set-sink-volume".into(), "@DEFAULT_SINK@".into(), p_str],
                    ];
                    let _ = run_first_available(&state.cfg, &cmds, 8.0, None, false, false);
                }
            }
            "bright_up" => {
                if !adjust_brightness(&state.cfg, "up", None) {
                    return json_err(
                        StatusCode::NOT_IMPLEMENTED,
                        "Brightness control unavailable (internal backlight or ddcutil required)",
                    );
                }
            }
            "bright_down" => {
                if !adjust_brightness(&state.cfg, "down", None) {
                    return json_err(
                        StatusCode::NOT_IMPLEMENTED,
                        "Brightness control unavailable (internal backlight or ddcutil required)",
                    );
                }
            }
            "bright_set" => {
                let Some(pct_f) = crate::actions::val_as_f64(&val) else {
                    return json_err(StatusCode::BAD_REQUEST, "Invalid brightness value");
                };
                let pct = (pct_f as i64).clamp(5, 100);
                if !adjust_brightness(&state.cfg, "set", Some(pct)) {
                    return json_err(
                        StatusCode::NOT_IMPLEMENTED,
                        "Brightness control unavailable (backlight, ddcutil, or hyprsunset required)",
                    );
                }
            }
            _ => return json_err(StatusCode::BAD_REQUEST, "Unsupported media action"),
        }
        state.cfg.invalidate_cache(&["media_display"]);
        json_ok(json!({"ok": true, "message": format!("Action {act} executed")}))
    })
    .await
}

async fn handle_power(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let (_, sess) = match require_auth(&state, addr.ip(), &headers, "/api/power") {
        Ok(x) => x,
        Err(r) => return r,
    };
    if let Err(r) = require_csrf(&sess, &headers) {
        return r;
    }
    let data = match read_json_object(body, state.cfg.settings.max_json_bytes).await {
        Ok(m) => m,
        Err(r) => return r,
    };

    let target = data
        .get("target")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let bootnum = data
        .get("bootnum")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let name_opt = data
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    run_blocking(move || {
        let reboot_cmds = || {
            vec![
                vec!["systemctl", "reboot"],
                vec!["loginctl", "reboot"],
                vec!["reboot"],
            ]
        };

        if target == "bootnum" {
            if IS_WINDOWS {
                return json_err(
                    StatusCode::NOT_IMPLEMENTED,
                    "Per-entry efibootmgr switching is Linux-only; use UEFI Firmware Reboot instead",
                );
            }
            if bootnum.len() != 4 || !bootnum.chars().all(|c| c.is_ascii_hexdigit()) {
                return json_err(StatusCode::BAD_REQUEST, "Invalid UEFI boot number");
            }
            let norm = bootnum.to_ascii_uppercase();
            let (rc, _, err) = run_cmd(&["efibootmgr", "-n", &norm], 8.0);
            if rc != 0 {
                return json_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("efibootmgr failed: {err}"),
                );
            }
            state.cfg.invalidate_cache(&["boot_entries"]);
            let disp_name: String = name_opt
                .unwrap_or_else(|| format!("Boot{norm}"))
                .chars()
                .take(64)
                .collect();
            delayed_power(Arc::clone(&state.cfg), reboot_cmds());
            return json_ok(json!({
                "ok": true,
                "message": format!("BootNext set to {norm} ({disp_name}). Rebooting..."),
            }));
        }

        if matches!(
            target.as_str(),
            "arch" | "cachyos" | "garuda" | "gentoo" | "nixos" | "ubuntu" | "fedora" | "debian" | "windows"
        ) {
            if IS_WINDOWS {
                return json_err(
                    StatusCode::NOT_IMPLEMENTED,
                    "OS BootNext switching via efibootmgr is Linux-only",
                );
            }
            let (_, out, _) = run_cmd(&["efibootmgr"], 6.0);
            let found = out.lines().find_map(|line| {
                let rest = line.strip_prefix("Boot")?;
                if rest.len() >= 4
                    && rest.is_char_boundary(4)
                    && rest[..4].chars().all(|c| c.is_ascii_hexdigit())
                    && line.to_ascii_lowercase().contains(&target)
                {
                    return Some(rest[..4].to_ascii_uppercase());
                }
                None
            });
            let Some(found_num) = found else {
                return json_err(
                    StatusCode::BAD_REQUEST,
                    format!("UEFI boot entry for '{target}' not found on this system!"),
                );
            };
            let (rc, _, err) = run_cmd(&["efibootmgr", "-n", &found_num], 8.0);
            if rc != 0 {
                return json_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("efibootmgr failed: {err}"),
                );
            }
            state.cfg.invalidate_cache(&["boot_entries"]);
            delayed_power(Arc::clone(&state.cfg), reboot_cmds());
            return json_ok(json!({
                "ok": true,
                "message": format!("BootNext set to {found_num} ({}). Rebooting...", target.to_ascii_uppercase()),
            }));
        }

        match target.as_str() {
            "uefi" => {
                let cmds = if IS_WINDOWS {
                    vec![vec!["shutdown", "/r", "/fw", "/t", "1"]]
                } else {
                    vec![
                        vec!["systemctl", "reboot", "--firmware-setup"],
                        vec!["loginctl", "reboot", "--firmware-setup"],
                    ]
                };
                delayed_power(Arc::clone(&state.cfg), cmds);
                json_ok(json!({"ok": true, "message": "Rebooting into BIOS / UEFI setup..."}))
            }
            "reboot" => {
                let cmds = if IS_WINDOWS {
                    vec![vec!["shutdown", "/r", "/t", "1", "/c", "Mobile-RC reboot"]]
                } else {
                    reboot_cmds()
                };
                delayed_power(Arc::clone(&state.cfg), cmds);
                json_ok(json!({"ok": true, "message": "Rebooting system..."}))
            }
            "poweroff" => {
                let cmds = if IS_WINDOWS {
                    vec![vec!["shutdown", "/s", "/t", "1", "/c", "Mobile-RC shutdown"]]
                } else {
                    vec![
                        vec!["systemctl", "poweroff"],
                        vec!["loginctl", "poweroff"],
                        vec!["poweroff"],
                    ]
                };
                delayed_power(Arc::clone(&state.cfg), cmds);
                json_ok(json!({"ok": true, "message": "Shutting down system..."}))
            }
            "lock" => {
                if IS_WINDOWS {
                    if !win_lock_workstation() {
                        let _ = run_cmd(&["rundll32.exe", "user32.dll,LockWorkStation"], 5.0);
                    }
                    return json_ok(json!({"ok": true, "message": "Screen locked!"}));
                }
                let env = get_desktop_env(&state.cfg);
                let comp = get_active_compositor(&env);
                let mut lock_cmds = vec![
                    vec!["hyprlock".into()],
                    vec!["swaylock".into()],
                    vec!["waylock".into()],
                    vec!["gtklock".into()],
                    vec!["i3lock".into()],
                    vec!["loginctl".into(), "lock-session".into()],
                ];
                if comp == "kde" {
                    let mut kde = vec![
                        vec!["qdbus6".into(), "org.kde.ScreenSaver".into(), "/ScreenSaver".into(), "Lock".into()],
                        vec!["qdbus".into(), "org.kde.ScreenSaver".into(), "/ScreenSaver".into(), "Lock".into()],
                        vec!["dbus-send".into(), "--session".into(), "--dest=org.kde.ScreenSaver".into(), "/ScreenSaver".into(), "org.freedesktop.ScreenSaver.Lock".into()],
                    ];
                    kde.extend(lock_cmds);
                    lock_cmds = kde;
                }
                let _ = run_first_available(&state.cfg, &lock_cmds, 8.0, None, false, false);
                let _ = run_cmd(&["loginctl", "lock-sessions"], 4.0);
                json_ok(json!({"ok": true, "message": "Screen locked!"}))
            }
            "suspend" => {
                let cmds = if IS_WINDOWS {
                    vec![vec!["rundll32.exe", "powrprof.dll,SetSuspendState", "0,1,0"]]
                } else {
                    vec![
                        vec!["systemctl", "suspend"],
                        vec!["loginctl", "suspend"],
                        vec!["zzz"],
                    ]
                };
                delayed_power(Arc::clone(&state.cfg), cmds);
                json_ok(json!({"ok": true, "message": "Suspending system..."}))
            }
            _ => json_err(StatusCode::BAD_REQUEST, "Unknown power target"),
        }
    })
    .await
}

async fn handle_action(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let (_, sess) = match require_auth(&state, addr.ip(), &headers, "/api/action") {
        Ok(x) => x,
        Err(r) => return r,
    };
    if let Err(r) = require_csrf(&sess, &headers) {
        return r;
    }
    let data = match read_json_object(body, state.cfg.settings.max_json_bytes).await {
        Ok(m) => m,
        Err(r) => return r,
    };

    let tp = data
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let val = data.get("value").cloned().unwrap_or(Value::Null);
    let auto_enter = data
        .get("auto_enter")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    run_blocking(move || {
        match tp.as_str() {
            "notify" => {
                let msg = value_as_str(&val).trim().to_string();
                if msg.is_empty() || msg.chars().count() > 500 {
                    return json_err(StatusCode::BAD_REQUEST, "Notification must be 1-500 characters");
                }
                if IS_WINDOWS {
                    let cfg_c = Arc::clone(&state.cfg);
                    std::thread::spawn(move || {
                        let ps = "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; $n = New-Object System.Windows.Forms.NotifyIcon; $n.Icon = [System.Drawing.SystemIcons]::Information; $n.Visible = $true; $n.ShowBalloonTip(5000, 'Mobile-RC Message', $env:MRC_NOTIFY_MSG, [System.Windows.Forms.ToolTipIcon]::Info); Start-Sleep -Milliseconds 600; $n.Dispose()";
                        let _ = crate::telemetry::win_run_ps(&cfg_c, ps, 8.0, &[("MRC_NOTIFY_MSG", &msg)]);
                    });
                } else {
                    let cmds = vec![
                        vec!["notify-send".into(), "-u".into(), "critical".into(), "Mobile-RC Message".into(), msg.clone()],
                        vec!["hyprctl".into(), "notify".into(), "1".into(), "3000".into(), "rgb(38bdf8)".into(), msg],
                    ];
                    let _ = run_first_available(&state.cfg, &cmds, 8.0, None, false, false);
                }
                json_ok(json!({"ok": true, "message": "Notification sent to PC screen!"}))
            }
            "clipboard" => {
                let text = value_as_str(&val);
                if text.is_empty() || text.chars().count() > 20000 {
                    return json_err(StatusCode::BAD_REQUEST, "Clipboard text must be 1-20000 characters");
                }
                let (rc, _, err) = if IS_WINDOWS {
                    crate::telemetry::win_run_ps(
                        &state.cfg,
                        "Set-Clipboard -Value $env:MRC_CLIP_TEXT",
                        6.0,
                        &[("MRC_CLIP_TEXT", &text)],
                    )
                } else {
                    let cmds = vec![
                        vec!["wl-copy".into()],
                        vec!["xclip".into(), "-selection".into(), "clipboard".into()],
                        vec!["xsel".into(), "--clipboard".into(), "--input".into()],
                    ];
                    run_first_available(&state.cfg, &cmds, 4.0, Some(&text), false, true)
                };
                if rc != 0 {
                    return json_err(StatusCode::INTERNAL_SERVER_ERROR, format!("Clipboard error: {err}"));
                }
                json_ok(json!({"ok": true, "message": "Copied to PC clipboard!"}))
            }
            "open_url" => {
                let raw = value_as_str(&val);
                let url = match validate_open_url(&raw) {
                    Ok(u) => u,
                    Err(msg) => return json_err(StatusCode::BAD_REQUEST, msg),
                };
                if IS_WINDOWS {
                    if !win_open_url(&url) {
                        return json_err(StatusCode::INTERNAL_SERVER_ERROR, "Failed to open URL");
                    }
                } else {
                    let _ = run_as_user(&state.cfg, &["xdg-open", &url], 8.0, None, None, true, true);
                }
                json_ok(json!({"ok": true, "message": format!("Opening {url} on PC browser!")}))
            }
            "launch" => {
                let preset = value_as_str(&val).trim().to_string();
                let Some(linux_cmds) = launch_preset_cmds(&preset) else {
                    return json_err(StatusCode::BAD_REQUEST, "Invalid application preset");
                };
                if IS_WINDOWS {
                    if preset == "youtube" {
                        if win_open_url("https://youtube.com") {
                            return json_ok(json!({"ok": true, "message": "Launching preset: youtube"}));
                        }
                        return json_err(StatusCode::INTERNAL_SERVER_ERROR, "Launch failed");
                    }
                    let win_cmds: &[&[&str]] = match preset.as_str() {
                        "terminal" => &[&["wt"], &["powershell"], &["cmd"]],
                        "files" => &[&["explorer.exe"]],
                        "btop" => &[&["btop"], &["btop4win"], &["taskmgr.exe"]],
                        _ => &[],
                    };
                    for cmd in win_cmds {
                        if let Some(exe) = find_bin(&state.cfg, cmd[0], None) {
                            if spawn_windows_launch(&exe, &cmd[1..], preset == "terminal") {
                                return json_ok(json!({"ok": true, "message": format!("Launching preset: {preset}")}));
                            }
                        }
                    }
                    return json_err(
                        StatusCode::NOT_FOUND,
                        format!("No Windows binary found for preset: {preset}"),
                    );
                }

                let env = get_desktop_env(&state.cfg);
                let sp = env.get("PATH").map(String::as_str);
                for cmd in linux_cmds {
                    if find_bin(&state.cfg, cmd[0], sp).is_some() {
                        let _ = run_as_user(&state.cfg, &cmd, 8.0, None, None, true, true);
                        return json_ok(json!({"ok": true, "message": format!("Launching preset: {preset}")}));
                    }
                }
                json_err(
                    StatusCode::NOT_FOUND,
                    format!("No binary found for preset: {preset}"),
                )
            }
            "ws" => {
                let val_num = match val
                    .as_i64()
                    .or_else(|| val.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
                {
                    Some(n) => n,
                    None => return json_err(StatusCode::BAD_REQUEST, "Workspace must be an integer"),
                };
                if !(1..=99).contains(&val_num) {
                    return json_err(
                        StatusCode::BAD_REQUEST,
                        "Workspace must be between 1 and 99",
                    );
                }
                if IS_WINDOWS {
                    return json_err(
                        StatusCode::NOT_IMPLEMENTED,
                        "Virtual desktop switching via API is not supported on Windows",
                    );
                }
                match switch_workspace(&state.cfg, &state.tel, val_num) {
                    Ok(()) => json_ok(json!({"ok": true, "message": format!("Switched to Workspace {val_num}")})),
                    Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e),
                }
            }
            "hypr" => {
                let act = value_as_str(&val).trim().to_string();
                if !is_valid_hypr_preset(&act) {
                    return json_err(StatusCode::BAD_REQUEST, "Invalid window action");
                }
                if IS_WINDOWS {
                    let ok = match act.as_str() {
                        "fullscreen" => win_send_vk(0x7A, false),
                        "killactive" => win_send_vk(0x73, true),
                        "dpms_toggle" => win_dpms_off(),
                        _ => {
                            return json_err(
                                StatusCode::NOT_IMPLEMENTED,
                                format!("Window action '{act}' is Linux compositor-only"),
                            )
                        }
                    };
                    if !ok {
                        return json_err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Window action failed: {act}"),
                        );
                    }
                    state.cfg.invalidate_cache(&["workspaces_info"]);
                    return json_ok(json!({"ok": true, "message": format!("Window action: {act}")}));
                }
                let env = get_desktop_env(&state.cfg);
                let cmds = get_window_action_cmds(&act, &env);
                let (rc, _, err) = run_first_available(&state.cfg, &cmds, 8.0, None, false, false);
                if rc != 0 {
                    let msg = if err.is_empty() {
                        format!("Window action failed: {act}")
                    } else {
                        err
                    };
                    return json_err(StatusCode::INTERNAL_SERVER_ERROR, msg);
                }
                state.cfg.invalidate_cache(&["workspaces_info"]);
                json_ok(json!({"ok": true, "message": format!("Window action: {act}")}))
            }
            "shell" | "shell_gui" | "shell_type" => {
                if state.cfg.settings.disable_shell {
                    return json_err(StatusCode::FORBIDDEN, "Quick Web Terminal is disabled");
                }
                let cmd_str = value_as_str(&val).trim().to_string();
                if cmd_str.is_empty() || cmd_str.chars().count() > 2000 {
                    return json_err(StatusCode::BAD_REQUEST, "Command must be 1-2000 characters");
                }
                if tp == "shell_gui" {
                    let (ok, detail) = spawn_terminal_with_command(&state.cfg, &cmd_str);
                    return json_ok(json!({
                        "ok": ok,
                        "output": if ok { format!("Opened on-screen terminal ({detail}) with: {cmd_str}") } else { detail.clone() },
                        "message": detail,
                    }));
                }
                if tp == "shell_type" {
                    let (ok, detail) = type_prompt_to_active_window(&state.cfg, &cmd_str, auto_enter);
                    return json_ok(json!({
                        "ok": ok,
                        "output": if ok { format!("Typed prompt into active window ({detail}, auto_enter={auto_enter})") } else { detail.clone() },
                        "message": detail,
                    }));
                }
                let (rc, out, err) =
                    run_as_user(&state.cfg, &[], 15.0, Some(&cmd_str), None, false, false);
                let combined = if err.is_empty() {
                    out
                } else if out.is_empty() {
                    err
                } else {
                    format!("{out}\n{err}")
                };
                let final_out = if combined.trim().is_empty() {
                    format!("(Exit code {rc})")
                } else {
                    combined.trim().to_string()
                };
                json_ok(json!({"ok": rc == 0, "output": final_out}))
            }
            _ => json_err(StatusCode::BAD_REQUEST, "Invalid action type"),
        }
    })
    .await
}

async fn handle_tunnel(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let (_, sess) = match require_auth(&state, addr.ip(), &headers, "/api/tunnel") {
        Ok(x) => x,
        Err(r) => return r,
    };
    if let Err(r) = require_csrf(&sess, &headers) {
        return r;
    }
    let data = match read_json_object(body, state.cfg.settings.max_json_bytes).await {
        Ok(m) => m,
        Err(r) => return r,
    };
    let act = data
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("start")
        .trim()
        .to_ascii_lowercase();
    run_blocking(move || match act.as_str() {
        "start" => {
            state.cfg.set_auto_tunnel_override(true);
            json_ok(state.tunnel.start_tunnel(Arc::clone(&state.cfg)))
        }
        "stop" => {
            state.cfg.set_auto_tunnel_override(false);
            json_ok(state.tunnel.stop_tunnel(&state.cfg))
        }
        _ => json_err(StatusCode::BAD_REQUEST, "Invalid tunnel action"),
    })
    .await
}

async fn handle_mobile_revoke(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let (_, sess) = match require_auth(&state, addr.ip(), &headers, "/api/mobile/revoke") {
        Ok(x) => x,
        Err(r) => return r,
    };
    if let Err(r) = require_csrf(&sess, &headers) {
        return r;
    }
    let data = match read_json_object(body, state.cfg.settings.max_json_bytes).await {
        Ok(m) => m,
        Err(r) => return r,
    };
    let dev_id = data
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if dev_id.is_empty() {
        return json_err(StatusCode::BAD_REQUEST, "Missing device id");
    }
    let ok = run_blocking(move || revoke_mobile_device(&state.cfg, &dev_id)).await;
    json_ok(json!({
        "ok": ok,
        "message": if ok { "Device revoked" } else { "Device id not found" },
    }))
}

async fn handle_feedback(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let (_, sess) = match require_auth(&state, addr.ip(), &headers, "/api/feedback") {
        Ok(x) => x,
        Err(r) => return r,
    };
    if let Err(r) = require_csrf(&sess, &headers) {
        return r;
    }
    let data = match read_json_object(body, state.cfg.settings.max_json_bytes).await {
        Ok(m) => m,
        Err(r) => return r,
    };
    let ip = client_ip(addr.ip(), &headers);
    if !state.auth.check_feedback_rate_limit(&ip) {
        return json_err(
            StatusCode::TOO_MANY_REQUESTS,
            "Feedback rate limit reached. Try again later.",
        );
    }

    let raw_cat = data
        .get("category")
        .and_then(|v| v.as_str())
        .unwrap_or("other")
        .trim()
        .to_ascii_lowercase();
    let category = match raw_cat.as_str() {
        "suggestion" | "bug" | "other" => raw_cat,
        _ => "other".into(),
    };
    let subject: String = data
        .get("subject")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .chars()
        .map(|c| if matches!(c, '\r' | '\n') { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_string();
    let message = data
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let reply_to: String = data
        .get("reply_to")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .chars()
        .filter(|&c| c != '\r' && c != '\n')
        .collect::<String>()
        .trim()
        .chars()
        .take(120)
        .collect();

    if !(1..=120).contains(&subject.chars().count()) {
        return json_err(StatusCode::BAD_REQUEST, "Subject must be 1-120 characters");
    }
    if !(3..=4000).contains(&message.chars().count()) {
        return json_err(StatusCode::BAD_REQUEST, "Message must be 3-4000 characters");
    }
    if !reply_to.is_empty()
        && (!reply_to.contains('@') || reply_to.chars().any(char::is_whitespace))
    {
        return json_err(StatusCode::BAD_REQUEST, "Invalid reply email address");
    }
    if !state.auth.record_feedback_submission(&ip) {
        return json_err(
            StatusCode::TOO_MANY_REQUESTS,
            "Feedback rate limit reached. Try again later.",
        );
    }

    let include_sysinfo = data
        .get("include_sysinfo")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let res = run_blocking(move || {
        send_feedback_report(
            &state.cfg,
            &state.tel,
            &category,
            &subject,
            &message,
            &reply_to,
            include_sysinfo,
        )
    })
    .await;
    json_ok(res)
}

async fn handle_services_post(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let (_, sess) = match require_auth(&state, addr.ip(), &headers, "/api/services") {
        Ok(x) => x,
        Err(r) => return r,
    };
    if let Err(r) = require_csrf(&sess, &headers) {
        return r;
    }
    let data = match read_json_object(body, state.cfg.settings.max_json_bytes).await {
        Ok(m) => m,
        Err(r) => return r,
    };
    let name = data
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let action = data
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let (ok, msg) =
        run_blocking(move || control_service(&state.cfg, &state.tel, &name, &action)).await;
    let status = if !ok && msg.starts_with("Invalid") {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    json_response(status, json!({"ok": ok, "message": msg}), &[])
}

async fn handle_process_kill(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let (_, sess) = match require_auth(&state, addr.ip(), &headers, "/api/process/kill") {
        Ok(x) => x,
        Err(r) => return r,
    };
    if let Err(r) = require_csrf(&sess, &headers) {
        return r;
    }
    let data = match read_json_object(body, state.cfg.settings.max_json_bytes).await {
        Ok(m) => m,
        Err(r) => return r,
    };
    let pid_opt = data.get("pid").and_then(|v| {
        v.as_i64()
            .or_else(|| v.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
    });
    let Some(pid_val) = pid_opt else {
        return json_ok(json!({"ok": false, "message": "Invalid PID"}));
    };
    let sig = data
        .get("signal")
        .and_then(|v| v.as_str())
        .unwrap_or("TERM")
        .to_string();
    let (ok, msg) = run_blocking(move || kill_process(&state.cfg, pid_val, &sig)).await;
    json_ok(json!({"ok": ok, "message": msg}))
}

async fn handle_input(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let (_, sess) = match require_auth(&state, addr.ip(), &headers, "/api/input") {
        Ok(x) => x,
        Err(r) => return r,
    };
    if let Err(r) = require_csrf(&sess, &headers) {
        return r;
    }
    let data = match read_json_object(body, state.cfg.settings.max_json_bytes).await {
        Ok(m) => m,
        Err(r) => return r,
    };
    let kind = data
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let val_obj = Value::Object(data);
    let (ok, msg) = run_blocking(move || send_remote_input(&state.cfg, &kind, &val_obj)).await;
    json_ok(json!({"ok": ok, "message": msg}))
}

fn value_as_str(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => if *b { "True" } else { "False" }.into(),
        other => other.to_string(),
    }
}

/// Spawn LAN UDP discovery listener on `0.0.0.0:discovery_port`.
fn spawn_discovery_worker(state: AppState) {
    if !state.cfg.settings.discovery_enabled {
        return;
    }
    let port = state.cfg.settings.discovery_port;
    tokio::spawn(async move {
        let sock = match UdpSocket::bind(("0.0.0.0", port)).await {
            Ok(s) => s,
            Err(e) => {
                state.cfg.record_audit_event(
                    "WARN",
                    format!("LAN discovery UDP listener unavailable on port {port}: {e}"),
                );
                return;
            }
        };
        let _ = sock.set_broadcast(true);
        state.cfg.record_audit_event(
            "INFO",
            format!("LAN discovery UDP listener active on port {port}"),
        );
        let mut buf = [0u8; 1024];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((len, peer)) => {
                    let msg = String::from_utf8_lossy(&buf[..len]).trim().to_string();
                    if msg == "MOBILE_RC_DISCOVER" || msg.to_ascii_lowercase().contains("\"discover\"") {
                        let st = state.clone();
                        let reply = run_blocking(move || {
                            let os_info = st.tel.get_os_info(&st.cfg);
                            serde_json::to_vec(&json!({
                                "service": "mobile-rc",
                                "version": 2,
                                "hostname": os_info.get("hostname").and_then(|v| v.as_str()).map(str::to_string).unwrap_or_else(get_hostname),
                                "os": os_info.get("name").and_then(|v| v.as_str()).unwrap_or("Linux"),
                                "port": st.cfg.settings.port,
                                "ips": st.tel.get_local_ips(&st.cfg),
                                "macs": st.tel.get_mac_addresses(&st.cfg),
                            }))
                            .unwrap_or_default()
                        })
                        .await;
                        let _ = sock.send_to(&reply, peer).await;
                    }
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(200)).await,
            }
        }
    });
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[tokio::main]
async fn main() {
    let settings = Settings::from_env();
    let cfg = Arc::new(ConfigStore::new(settings));
    let _ = cfg.ensure_config_dir();
    if cfg.get_pin_mode() == "static" {
        cfg.get_pin();
    }
    cfg.get_termux_token();
    cfg.get_ntfy_topic();

    let auth = Arc::new(AuthState::new());
    let tel = Arc::new(TelemetryState::new());
    tel.get_cpu_percent();
    let tunnel = Arc::new(TunnelManager::new());

    let port = cfg.settings.port;
    cfg.record_audit_event("INFO", format!("Mobile-RC server listening on 0.0.0.0:{port}"));

    spawn_tunnel_watchdog(Arc::clone(&cfg), Arc::clone(&tunnel));
    let state = AppState {
        cfg: Arc::clone(&cfg),
        auth,
        tel,
        tunnel: Arc::clone(&tunnel),
    };
    spawn_discovery_worker(state.clone());

    let app = Router::new()
        .route("/", get(handle_index))
        .route("/index.html", get(handle_index))
        .route("/assets/control-access", get(handle_control_access_asset))
        .route("/api/auth/status", get(handle_auth_status))
        .route("/api/status", get(handle_status))
        .route("/api/telemetry", get(handle_telemetry))
        .route("/api/logs", get(handle_logs))
        .route("/api/distros", get(handle_distros))
        .route("/api/services", get(handle_services).post(handle_services_post))
        .route("/api/processes", get(handle_processes))
        .route("/api/mobile/devices", get(handle_mobile_devices))
        .route("/api/screenshot", get(handle_screenshot))
        .route("/api/files", get(handle_files))
        .route("/api/download", get(handle_download))
        .route("/api/mobile/pair", post(handle_mobile_pair))
        .route("/api/pairing/code", post(handle_pairing_code))
        .route("/api/pairing/email-code", post(handle_pairing_email_code))
        .route("/api/login", post(handle_login))
        .route("/api/logout", post(handle_logout))
        .route(
            "/api/upload",
            post(handle_upload).layer(DefaultBodyLimit::disable()),
        )
        .route("/api/media", post(handle_media))
        .route("/api/power", post(handle_power))
        .route("/api/action", post(handle_action))
        .route("/api/tunnel", post(handle_tunnel))
        .route("/api/mobile/revoke", post(handle_mobile_revoke))
        .route("/api/feedback", post(handle_feedback))
        .route("/api/process/kill", post(handle_process_kill))
        .route("/api/input", post(handle_input))
        .with_state(state);

    let bind_addr: SocketAddr = format!("0.0.0.0:{port}").parse().expect("valid bind addr");
    let listener = TcpListener::bind(bind_addr)
        .await
        .expect("failed to bind TCP listener");
    println!("[Mobile-RC] Rust daemon running at http://0.0.0.0:{port}");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .expect("HTTP server error");

    tunnel.stop_tunnel(&cfg);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guess_mime_type() {
        assert_eq!(guess_mime_type(Path::new("shot.jpg")), "image/jpeg");
        assert_eq!(guess_mime_type(Path::new("archive.tar.gz")), "application/gzip");
        assert_eq!(guess_mime_type(Path::new("unknown.xyz")), "application/octet-stream");
    }

    #[test]
    fn test_embedded_assets_non_empty() {
        assert!(INDEX_HTML.contains("<!DOCTYPE html>"));
        assert!(INDEX_HTML.contains("Mobile-RC"));
    }
}

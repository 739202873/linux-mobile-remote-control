//! Host control actions, input injection, screenshot capture, and SSH tunnel lifecycle.

use crate::config::{random_hex, write_secure_file, ConfigStore};
use crate::telemetry::{
    exec_cmd_blocking, find_bin, get_active_compositor, get_desktop_env, get_hostname,
    get_system_path, has_internal_backlight, run_as_user, run_cmd, run_first_available,
    run_first_system_cmd, url_encode, TelemetryState, IS_WINDOWS,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt as WinCommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

struct TunnelInner {
    proc_id: u64,
    child: Option<Child>,
    url: String,
    status: String,
}

pub struct TunnelManager {
    inner: Mutex<TunnelInner>,
    next_id: Mutex<u64>,
}

impl Default for TunnelManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TunnelManager {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(TunnelInner {
                proc_id: 0,
                child: None,
                url: String::new(),
                status: "stopped".to_string(),
            }),
            next_id: Mutex::new(1),
        }
    }

    pub fn get_tunnel_info(&self, cfg: &ConfigStore) -> Value {
        let (active, status, url) = {
            let mut guard = self.inner.lock().unwrap();
            let active = match guard.child.as_mut() {
                Some(ch) => match ch.try_wait() {
                    Ok(None) => true,
                    _ => {
                        guard.child = None;
                        false
                    }
                },
                None => false,
            };
            if !active && guard.status != "unavailable (ssh not installed)" {
                guard.status = "stopped".into();
                guard.url.clear();
            }
            (active, guard.status.clone(), guard.url.clone())
        };
        json!({
            "active": active,
            "status": status,
            "url": url,
            "auto": cfg.is_auto_tunnel_enabled(),
            "topic": cfg.get_ntfy_topic(),
        })
    }

    pub fn start_tunnel(self: &Arc<Self>, cfg: Arc<ConfigStore>) -> Value {
        let Some(ssh_bin) = find_bin(&cfg, "ssh", None) else {
            self.inner.lock().unwrap().status = "unavailable (ssh not installed)".into();
            return self.get_tunnel_info(&cfg);
        };

        {
            let mut guard = self.inner.lock().unwrap();
            if let Some(ch) = guard.child.as_mut() {
                if matches!(ch.try_wait(), Ok(None)) {
                    drop(guard);
                    return self.get_tunnel_info(&cfg);
                }
            }
            ensure_ssh_keypair(&cfg);
            guard.url.clear();
            guard.status = "starting".into();

            let known_hosts_arg = format!("UserKnownHostsFile={}", cfg.settings.ssh_known_hosts.display());
            let forward_arg = format!("80:localhost:{}", cfg.settings.port);
            let mut cmd = Command::new(&ssh_bin);
            cmd.args([
                "-T",
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
                &known_hosts_arg,
                "-o",
                "ExitOnForwardFailure=yes",
                "-o",
                "ServerAliveInterval=30",
                "-o",
                "ServerAliveCountMax=3",
                "-R",
                &forward_arg,
            ]);
            if cfg.settings.ssh_key_file.exists() {
                cmd.arg("-i").arg(&cfg.settings.ssh_key_file);
            }
            cmd.arg("nokey@localhost.run");
            cmd.env("PATH", get_system_path());
            cmd.stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            #[cfg(windows)]
            cmd.creationflags(CREATE_NO_WINDOW);

            match cmd.spawn() {
                Ok(mut child) => {
                    let stdout = child.stdout.take();
                    let stderr = child.stderr.take();
                    let id = {
                        let mut id_g = self.next_id.lock().unwrap();
                        let cur = *id_g;
                        *id_g += 1;
                        cur
                    };
                    guard.proc_id = id;
                    guard.child = Some(child);

                    let mgr_out = Arc::clone(self);
                    let cfg_out = Arc::clone(&cfg);
                    if let Some(out_pipe) = stdout {
                        thread::spawn(move || {
                            read_tunnel_stream(out_pipe, id, mgr_out, cfg_out, true);
                        });
                    }
                    let mgr_err = Arc::clone(self);
                    let cfg_err = Arc::clone(&cfg);
                    if let Some(err_pipe) = stderr {
                        thread::spawn(move || {
                            read_tunnel_stream(err_pipe, id, mgr_err, cfg_err, false);
                        });
                    }
                }
                Err(_) => {
                    guard.status = "stopped".into();
                    drop(guard);
                    return self.get_tunnel_info(&cfg);
                }
            }
        }

        for _ in 0..25 {
            thread::sleep(Duration::from_millis(200));
            let info = self.get_tunnel_info(&cfg);
            let has_url = info
                .get("url")
                .and_then(|v| v.as_str())
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            let stopped = info.get("status").and_then(|v| v.as_str()) == Some("stopped");
            if has_url || stopped {
                return info;
            }
        }
        self.get_tunnel_info(&cfg)
    }

    pub fn stop_tunnel(&self, cfg: &ConfigStore) -> Value {
        let mut child_opt = {
            let mut guard = self.inner.lock().unwrap();
            guard.proc_id = 0;
            guard.url.clear();
            guard.status = "stopped".into();
            guard.child.take()
        };
        if let Some(ref mut ch) = child_opt {
            if matches!(ch.try_wait(), Ok(None)) {
                let _ = ch.kill();
                let _ = ch.wait();
            }
        }
        self.get_tunnel_info(cfg)
    }
}

fn read_tunnel_stream<R: std::io::Read>(
    pipe: R,
    proc_id: u64,
    mgr: Arc<TunnelManager>,
    cfg: Arc<ConfigStore>,
    reset_on_eof: bool,
) {
    let reader = BufReader::new(pipe);
    for line in reader.lines().map_while(Result::ok) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(url) = extract_tunnel_url(trimmed) {
            let mut changed = false;
            {
                let mut guard = mgr.inner.lock().unwrap();
                if guard.proc_id != proc_id {
                    return;
                }
                if guard.url != url {
                    guard.url = url.clone();
                    changed = true;
                }
                guard.status = "online".into();
            }
            if changed {
                let _ = cfg.ensure_config_dir();
                let _ = write_secure_file(
                    &cfg.settings.config_dir.join("tunnel_url.txt"),
                    format!("{url}\n").as_bytes(),
                    0o600,
                );
                let cfg_n = Arc::clone(&cfg);
                let u_n = url.clone();
                thread::spawn(move || publish_ntfy(&cfg_n, &u_n));
            }
        }
    }
    if reset_on_eof {
        let mut guard = mgr.inner.lock().unwrap();
        if guard.proc_id == proc_id {
            guard.url.clear();
            guard.status = "stopped".into();
            guard.child = None;
        }
    }
}

/// Extract generated tunnel URL while filtering `localhost.run` banner/docs/admin links.
pub fn extract_tunnel_url(line: &str) -> Option<String> {
    let mut search_from = 0;
    while let Some(rel) = line[search_from..].find("https://") {
        let start = search_from + rel;
        let after = &line[start + 8..];
        let host_len = after
            .find(|c: char| !(c.is_ascii_alphanumeric() || "._-".contains(c)))
            .unwrap_or(after.len());
        let host = after[..host_len].trim_end_matches('.');
        let low = host.to_ascii_lowercase();
        let valid_suffix = low.ends_with(".lhr.life") || low.ends_with(".localhost.run");
        let is_banner = low.starts_with("admin.") || low.starts_with("www.") || low.starts_with("docs.");
        if valid_suffix && !is_banner && host.len() > 8 {
            return Some(format!("https://{host}"));
        }
        search_from = start + 8;
    }
    None
}

fn ensure_ssh_keypair(cfg: &ConfigStore) {
    let _ = cfg.ensure_config_dir();
    if !cfg.settings.ssh_key_file.exists() {
        if let Some(keygen) = find_bin(cfg, "ssh-keygen", None) {
            let key_str = cfg.settings.ssh_key_file.to_string_lossy().into_owned();
            let mut env: HashMap<String, String> = std::env::vars().collect();
            env.insert("PATH".into(), get_system_path());
            let _ = exec_cmd_blocking(
                &keygen,
                &["-t", "ed25519", "-N", "", "-f", &key_str],
                &env,
                None,
                8.0,
                None,
                None,
                false,
                true,
            );
        }
    }
    #[cfg(unix)]
    if cfg.settings.ssh_key_file.exists() {
        let _ = fs::set_permissions(&cfg.settings.ssh_key_file, fs::Permissions::from_mode(0o600));
    }
}

fn publish_ntfy(cfg: &ConfigStore, url: &str) {
    let topic = cfg.get_ntfy_topic();
    if topic.is_empty() {
        return;
    }
    let Some(curl_bin) = find_bin(cfg, "curl", None) else {
        return;
    };
    let endpoint = format!("https://ntfy.sh/{}", url_encode(&topic, ""));
    let title = format!("{} - Mobile-RC Online", get_hostname());
    let body = format!(
        "Remote dashboard is reachable at:\n{url}\n\nSign in using the PIN stored on your PC."
    );
    let mut env: HashMap<String, String> = std::env::vars().collect();
    env.insert("PATH".into(), get_system_path());
    let _ = exec_cmd_blocking(
        &curl_bin,
        &[
            "-fsS",
            "--max-time",
            "10",
            "-X",
            "POST",
            "-H",
            &format!("Title: {title}"),
            "-H",
            "Tags: computer,globe_with_meridians",
            "-H",
            &format!("Click: {url}"),
            "-H",
            "Content-Type: text/plain; charset=utf-8",
            "--data-binary",
            "@-",
            &endpoint,
        ],
        &env,
        None,
        11.0,
        Some(body.as_bytes()),
        None,
        false,
        true,
    );
}

pub fn spawn_tunnel_watchdog(cfg: Arc<ConfigStore>, tunnel: Arc<TunnelManager>) {
    thread::spawn(move || loop {
        if cfg.is_auto_tunnel_enabled() {
            let alive = {
                let mut guard = tunnel.inner.lock().unwrap();
                matches!(
                    guard.child.as_mut().map(|c| c.try_wait()),
                    Some(Ok(None))
                )
            };
            if !alive {
                tunnel.start_tunnel(Arc::clone(&cfg));
            }
        }
        thread::sleep(Duration::from_secs(10));
    });
}

/// Start, stop, restart, or reload a host system service after strict validation.
pub fn control_service(
    cfg: &ConfigStore,
    tel: &TelemetryState,
    name: &str,
    action: &str,
) -> (bool, String) {
    let svc = name.trim();
    let act = action.trim().to_ascii_lowercase();
    let valid_len = (1..=96).contains(&svc.len());
    let valid_chars = svc.chars().all(|c| {
        c.is_ascii_alphanumeric() || "_.@:-".contains(c) || (IS_WINDOWS && c == '$')
    });
    if !valid_len || !valid_chars {
        return (false, "Invalid service name".into());
    }
    if !matches!(act.as_str(), "start" | "stop" | "restart" | "reload") {
        return (false, "Invalid service action".into());
    }

    let init_sys = tel.detect_init_system(cfg);
    let (rc, out, err) = if IS_WINDOWS {
        let verb = match act.as_str() {
            "start" => "Start-Service",
            "stop" => "Stop-Service -Force",
            "restart" => "Restart-Service -Force",
            _ => return (false, "Reload is not supported on Windows services (use restart)".into()),
        };
        let ps = format!("{verb} -Name $env:MRC_SVC_NAME -ErrorAction Stop");
        crate::telemetry::win_run_ps(cfg, &ps, 20.0, &[("MRC_SVC_NAME", svc)])
    } else if init_sys == "openrc" && find_bin(cfg, "rc-service", None).is_some() {
        run_cmd(&["rc-service", svc, &act], 20.0)
    } else if init_sys == "systemd" && find_bin(cfg, "systemctl", None).is_some() {
        run_cmd(&["systemctl", &act, svc], 20.0)
    } else if init_sys == "runit" && find_bin(cfg, "sv", None).is_some() {
        let sv_act = if act == "reload" { "hup" } else { act.as_str() };
        run_cmd(&["sv", sv_act, svc], 15.0)
    } else {
        return (false, format!("Service control not supported on init system '{init_sys}'"));
    };

    cfg.invalidate_cache(&["services_info"]);
    let msg = if !out.is_empty() {
        out
    } else if !err.is_empty() {
        err
    } else {
        format!("{svc} {act}: exit {rc}")
    };
    if rc == 0 {
        cfg.record_audit_event("INFO", format!("Service action: {svc} -> {act}"));
    } else {
        cfg.record_audit_event("WARN", format!("Service action failed: {svc} -> {act} ({msg})"));
    }
    (rc == 0, msg)
}

/// Signal a non-init, non-self PID cleanly (`TERM`, `KILL`, or `HUP`).
pub fn kill_process(cfg: &ConfigStore, pid_val: i64, sig_name: &str) -> (bool, String) {
    let min_protected: i64 = if IS_WINDOWS { 4 } else { 1 };
    let self_pid = std::process::id() as i64;
    if pid_val <= min_protected || pid_val == self_pid {
        return (
            false,
            "Refusing to signal init/system or Mobile-RC server process".into(),
        );
    }
    let sig_key = sig_name.trim().to_ascii_uppercase();
    let sig_key = if sig_key.is_empty() {
        "TERM"
    } else {
        sig_key.as_str()
    };
    if !matches!(sig_key, "TERM" | "KILL" | "HUP") {
        return (false, "Unsupported signal (use TERM, KILL, or HUP)".into());
    }

    if IS_WINDOWS {
        let pid_str = pid_val.to_string();
        let mut args = vec!["taskkill", "/PID", &pid_str];
        if sig_key == "KILL" {
            args.push("/F");
        }
        let (rc, out, err) = run_cmd(&args, 8.0);
        let msg = if !out.is_empty() {
            out
        } else if !err.is_empty() {
            err
        } else {
            format!("taskkill PID {pid_val}: exit {rc}")
        };
        if rc == 0 {
            cfg.record_audit_event("WARN", format!("Terminated Windows PID {pid_val} ({sig_key})"));
        }
        return (rc == 0, msg);
    }

    #[cfg(unix)]
    unsafe {
        let signum = match sig_key {
            "TERM" => libc::SIGTERM,
            "KILL" => libc::SIGKILL,
            "HUP" => libc::SIGHUP,
            _ => libc::SIGTERM,
        };
        if libc::kill(pid_val as libc::pid_t, signum) == 0 {
            cfg.record_audit_event("WARN", format!("Sent SIG{sig_key} to PID {pid_val}"));
            return (true, format!("Sent SIG{sig_key} to PID {pid_val}"));
        }
        let os_err = std::io::Error::last_os_error();
        return match os_err.raw_os_error() {
            Some(e) if e == libc::ESRCH => (false, format!("Process {pid_val} not found")),
            Some(e) if e == libc::EPERM => (false, format!("Permission denied signaling PID {pid_val}")),
            _ => (false, os_err.to_string()),
        };
    }

    #[allow(unreachable_code)]
    (false, "Unsupported platform".into())
}

#[cfg(windows)]
mod win_input_ffi {
    #[repr(C)]
    pub struct Point {
        pub x: i32,
        pub y: i32,
    }
    #[link(name = "user32")]
    extern "system" {
        pub fn keybd_event(b_vk: u8, b_scan: u8, dw_flags: u32, dw_extra_info: usize);
        pub fn GetCursorPos(lp_point: *mut Point) -> i32;
        pub fn SetCursorPos(x: i32, y: i32) -> i32;
        pub fn mouse_event(dw_flags: u32, dx: i32, dy: i32, dw_data: u32, dw_extra_info: usize);
        pub fn LockWorkStation() -> i32;
        pub fn SendMessageW(hwnd: usize, msg: u32, wparam: usize, lparam: isize) -> isize;
    }
}

pub fn win_send_vk(vk_code: u8, hold_alt: bool) -> bool {
    #[cfg(windows)]
    unsafe {
        if hold_alt {
            win_input_ffi::keybd_event(0x12, 0, 0, 0);
        }
        win_input_ffi::keybd_event(vk_code, 0, 0, 0);
        win_input_ffi::keybd_event(vk_code, 0, 2, 0);
        if hold_alt {
            win_input_ffi::keybd_event(0x12, 0, 2, 0);
        }
        return true;
    }
    #[cfg(not(windows))]
    {
        let _ = (vk_code, hold_alt);
        false
    }
}

pub fn win_lock_workstation() -> bool {
    #[cfg(windows)]
    unsafe {
        if win_input_ffi::LockWorkStation() != 0 {
            return true;
        }
    }
    false
}

pub fn win_dpms_off() -> bool {
    #[cfg(windows)]
    unsafe {
        win_input_ffi::SendMessageW(0xFFFF, 0x0112, 0xF170, 2);
        return true;
    }
    #[cfg(not(windows))]
    false
}

const ALLOWED_REMOTE_KEYS: &[&str] = &[
    "Return",
    "BackSpace",
    "Escape",
    "Tab",
    "space",
    "Left",
    "Right",
    "Up",
    "Down",
    "Prior",
    "Next",
    "Home",
    "End",
    "XF86AudioPlay",
    "XF86AudioRaiseVolume",
    "XF86AudioLowerVolume",
];

#[cfg(windows)]
fn win_vk_for_key(key: &str) -> Option<u8> {
    Some(match key {
        "Return" => 0x0D,
        "BackSpace" => 0x08,
        "Escape" => 0x1B,
        "Tab" => 0x09,
        "space" => 0x20,
        "Prior" => 0x21,
        "Next" => 0x22,
        "End" => 0x23,
        "Home" => 0x24,
        "Left" => 0x25,
        "Up" => 0x26,
        "Right" => 0x27,
        "Down" => 0x28,
        "XF86AudioPlay" => 0xB3,
        "XF86AudioRaiseVolume" => 0xAF,
        "XF86AudioLowerVolume" => 0xAE,
        _ => return None,
    })
}

pub fn send_remote_input(cfg: &ConfigStore, kind: &str, payload: &Value) -> (bool, String) {
    let k = kind.trim().to_ascii_lowercase();
    #[cfg(windows)]
    {
        return send_windows_remote_input(cfg, &k, payload);
    }

    #[cfg(not(windows))]
    {
        let env = get_desktop_env(cfg);
        let sp = env.get("PATH").map(String::as_str);
        let has_ydo = find_bin(cfg, "ydotool", sp).is_some();
        let has_xdo = find_bin(cfg, "xdotool", sp).is_some();
        let has_wtype = find_bin(cfg, "wtype", sp).is_some();

        match k.as_str() {
            "move" => {
                let Some(dx_f) = payload.get("dx").and_then(val_as_f64).or(Some(0.0)) else {
                    return (false, "Invalid mouse delta".into());
                };
                let Some(dy_f) = payload.get("dy").and_then(val_as_f64).or(Some(0.0)) else {
                    return (false, "Invalid mouse delta".into());
                };
                let dx = (dx_f.round() as i32).clamp(-800, 800).to_string();
                let dy = (dy_f.round() as i32).clamp(-800, 800).to_string();
                if has_ydo {
                    let (rc, _, err) = run_as_user(
                        cfg,
                        &["ydotool", "mousemove", "--", &dx, &dy],
                        3.0,
                        None,
                        None,
                        false,
                        false,
                    );
                    return (rc == 0, if rc == 0 { "ydotool".into() } else { err });
                }
                if has_xdo {
                    let (rc, _, err) = run_as_user(
                        cfg,
                        &["xdotool", "mousemove_relative", "--", &dx, &dy],
                        3.0,
                        None,
                        None,
                        false,
                        false,
                    );
                    return (rc == 0, if rc == 0 { "xdotool".into() } else { err });
                }
                (
                    false,
                    "Install ydotool (Wayland) or xdotool (X11) for remote cursor movement".into(),
                )
            }
            "click" => {
                let btn = payload
                    .get("button")
                    .and_then(|v| v.as_str())
                    .unwrap_or("left")
                    .trim()
                    .to_ascii_lowercase();
                let (xdo_b, ydo_b) = match btn.as_str() {
                    "left" => ("1", "0xC0"),
                    "middle" => ("2", "0xC2"),
                    "right" => ("3", "0xC1"),
                    _ => return (false, "Unsupported mouse button".into()),
                };
                if has_ydo {
                    let (rc, _, err) =
                        run_as_user(cfg, &["ydotool", "click", ydo_b], 3.0, None, None, false, false);
                    return (rc == 0, if rc == 0 { "ydotool".into() } else { err });
                }
                if has_xdo {
                    let (rc, _, err) =
                        run_as_user(cfg, &["xdotool", "click", xdo_b], 3.0, None, None, false, false);
                    return (rc == 0, if rc == 0 { "xdotool".into() } else { err });
                }
                (
                    false,
                    "Install ydotool (Wayland) or xdotool (X11) for mouse click".into(),
                )
            }
            "scroll" => {
                let dy = (payload.get("dy").and_then(val_as_f64).unwrap_or(0.0).round() as i32)
                    .clamp(-20, 20);
                if dy == 0 {
                    return (true, "noop".into());
                }
                if has_ydo {
                    let neg_dy = (-dy).to_string();
                    let (rc, _, err) = run_as_user(
                        cfg,
                        &["ydotool", "mousemove", "-w", "--", "0", &neg_dy],
                        3.0,
                        None,
                        None,
                        false,
                        false,
                    );
                    return (rc == 0, if rc == 0 { "ydotool".into() } else { err });
                }
                if has_xdo {
                    let btn = if dy < 0 { "4" } else { "5" };
                    let rep = dy.abs().to_string();
                    let (rc, _, err) = run_as_user(
                        cfg,
                        &["xdotool", "click", "--repeat", &rep, btn],
                        3.0,
                        None,
                        None,
                        false,
                        false,
                    );
                    return (rc == 0, if rc == 0 { "xdotool".into() } else { err });
                }
                (false, "Install ydotool or xdotool for remote scroll".into())
            }
            "key" => {
                let key = payload
                    .get("key")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim();
                if !ALLOWED_REMOTE_KEYS.contains(&key) {
                    return (false, "Unsupported key".into());
                }
                if has_wtype {
                    let (rc, _, _err) =
                        run_as_user(cfg, &["wtype", "-k", key], 3.0, None, None, false, false);
                    if rc == 0 {
                        return (true, "wtype".into());
                    }
                }
                if has_xdo {
                    let (rc, _, err) =
                        run_as_user(cfg, &["xdotool", "key", key], 3.0, None, None, false, false);
                    return (rc == 0, if rc == 0 { "xdotool".into() } else { err });
                }
                if has_ydo && key == "Return" {
                    let (rc, _, err) = run_as_user(
                        cfg,
                        &["ydotool", "key", "28:1", "28:0"],
                        3.0,
                        None,
                        None,
                        false,
                        false,
                    );
                    return (rc == 0, if rc == 0 { "ydotool".into() } else { err });
                }
                (
                    false,
                    "Install wtype, ydotool, or xdotool for remote key input".into(),
                )
            }
            "text" => {
                let text = payload.get("text").and_then(|v| v.as_str()).unwrap_or("");
                if text.is_empty() || text.chars().count() > 1000 {
                    return (false, "Text must be 1-1000 characters".into());
                }
                let auto_enter = payload
                    .get("auto_enter")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                type_prompt_to_active_window(cfg, text, auto_enter)
            }
            _ => (false, "Unsupported remote input kind".into()),
        }
    }
}

#[cfg(windows)]
fn send_windows_remote_input(cfg: &ConfigStore, kind: &str, payload: &Value) -> (bool, String) {
    match kind {
        "move" => unsafe {
            let dx = (payload.get("dx").and_then(val_as_f64).unwrap_or(0.0).round() as i32)
                .clamp(-800, 800);
            let dy = (payload.get("dy").and_then(val_as_f64).unwrap_or(0.0).round() as i32)
                .clamp(-800, 800);
            let mut pt = win_input_ffi::Point { x: 0, y: 0 };
            win_input_ffi::GetCursorPos(&mut pt);
            win_input_ffi::SetCursorPos(pt.x + dx, pt.y + dy);
            (true, "win32".into())
        },
        "click" => unsafe {
            let btn = payload
                .get("button")
                .and_then(|v| v.as_str())
                .unwrap_or("left")
                .trim()
                .to_ascii_lowercase();
            let (down, up) = match btn.as_str() {
                "left" => (0x0002u32, 0x0004u32),
                "right" => (0x0008, 0x0010),
                "middle" => (0x0020, 0x0040),
                _ => return (false, "Unsupported mouse button".into()),
            };
            win_input_ffi::mouse_event(down, 0, 0, 0, 0);
            win_input_ffi::mouse_event(up, 0, 0, 0, 0);
            (true, "win32".into())
        },
        "scroll" => unsafe {
            let dy = (payload.get("dy").and_then(val_as_f64).unwrap_or(0.0).round() as i32)
                .clamp(-20, 20);
            if dy == 0 {
                return (true, "noop".into());
            }
            let wheel_delta = (-dy * 120) as i32 as u32;
            win_input_ffi::mouse_event(0x0800, 0, 0, wheel_delta, 0);
            (true, "win32".into())
        },
        "key" => {
            let key = payload
                .get("key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if !ALLOWED_REMOTE_KEYS.contains(&key) {
                return (false, "Unsupported key".into());
            }
            let Some(vk) = win_vk_for_key(key) else {
                return (false, "Unsupported key".into());
            };
            win_send_vk(vk, false);
            (true, "win32".into())
        }
        "text" => {
            let text = payload.get("text").and_then(|v| v.as_str()).unwrap_or("");
            if text.is_empty() || text.chars().count() > 1000 {
                return (false, "Text must be 1-1000 characters".into());
            }
            let auto_enter = payload
                .get("auto_enter")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            type_prompt_to_active_window(cfg, text, auto_enter)
        }
        _ => (false, "Unsupported remote input kind".into()),
    }
}

pub fn val_as_f64(v: &Value) -> Option<f64> {
    v.as_f64()
        .or_else(|| v.as_i64().map(|n| n as f64))
        .or_else(|| v.as_str().and_then(|s| s.trim().parse::<f64>().ok()))
}

pub fn adjust_brightness(cfg: &ConfigStore, mode: &str, value: Option<i64>) -> bool {
    if IS_WINDOWS {
        let ps = "$b = Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorBrightness -ErrorAction Stop | Select-Object -First 1; $m = Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorBrightnessMethods -ErrorAction Stop | Select-Object -First 1; $cur = [int]$b.CurrentBrightness; $mode = $env:MRC_BRIGHT_MODE; $val = [int]$env:MRC_BRIGHT_VAL; if ($mode -eq 'up') { $target = [Math]::Min(100, $cur + 10) } elseif ($mode -eq 'down') { $target = [Math]::Max(5, $cur - 10) } else { $target = [Math]::Max(5, [Math]::Min(100, $val)) }; $m.WmiSetBrightness(1, $target) | Out-Null; Write-Output $target";
        let val_str = value.unwrap_or(50).to_string();
        let (rc, _, _) = crate::telemetry::win_run_ps(
            cfg,
            ps,
            4.0,
            &[("MRC_BRIGHT_MODE", mode), ("MRC_BRIGHT_VAL", &val_str)],
        );
        if rc == 0 {
            cfg.invalidate_cache(&["media_display"]);
        }
        return rc == 0;
    }

    if has_internal_backlight() {
        let val_s = value.unwrap_or(50).to_string();
        let val_pct = format!("{val_s}%");
        let cmds: Vec<Vec<String>> = match mode {
            "up" => vec![
                vec!["brightnessctl".into(), "set".into(), "+10%".into()],
                vec!["light".into(), "-A".into(), "10".into()],
            ],
            "down" => vec![
                vec!["brightnessctl".into(), "set".into(), "10%-".into()],
                vec!["light".into(), "-U".into(), "10".into()],
            ],
            _ => vec![
                vec!["brightnessctl".into(), "set".into(), val_pct],
                vec!["light".into(), "-S".into(), val_s],
            ],
        };
        let (rc, _, _) = run_first_available(cfg, &cmds, 8.0, None, false, false);
        if rc == 0 {
            cfg.invalidate_cache(&["media_display"]);
            return true;
        }
        let sys_cmds: Vec<Vec<&str>> = cmds
            .iter()
            .map(|c| c.iter().map(String::as_str).collect())
            .collect();
        let sys_refs: Vec<&[&str]> = sys_cmds.iter().map(Vec::as_slice).collect();
        let (rc2, _, _) = run_first_system_cmd(cfg, &sys_refs, 8.0);
        if rc2 == 0 {
            cfg.invalidate_cache(&["media_display"]);
        }
        return rc2 == 0;
    }

    if find_bin(cfg, "ddcutil", None).is_some() {
        let val_s = value.unwrap_or(50).to_string();
        let cmd: Vec<&str> = match mode {
            "up" => vec!["ddcutil", "--noverify", "setvcp", "10", "+", "10"],
            "down" => vec!["ddcutil", "--noverify", "setvcp", "10", "-", "10"],
            _ => vec!["ddcutil", "--noverify", "setvcp", "10", &val_s],
        };
        let (rc, _, _) = run_first_system_cmd(cfg, &[&cmd], 4.0);
        if rc == 0 {
            cfg.invalidate_cache(&["media_display"]);
            return true;
        }
    }

    if mode == "set" {
        if let Some(val) = value {
            let val_s = val.to_string();
            let cmds = vec![vec![
                "hyprctl".into(),
                "hyprsunset".into(),
                "gamma".into(),
                val_s,
            ]];
            let (rc, _, _) = run_first_available(cfg, &cmds, 3.0, None, false, false);
            if rc == 0 {
                cfg.invalidate_cache(&["media_display"]);
                return true;
            }
        }
    }
    false
}

pub fn escape_sendkeys(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if "+%^~()[]{}".contains(ch) {
            out.push('{');
            out.push(ch);
            out.push('}');
        } else if ch == '\n' {
            out.push_str("{ENTER}");
        } else if ch != '\r' {
            out.push(ch);
        }
    }
    out
}

pub fn type_prompt_to_active_window(
    cfg: &ConfigStore,
    text: &str,
    auto_enter: bool,
) -> (bool, String) {
    let env = get_desktop_env(cfg);
    let sp = env.get("PATH").map(String::as_str);

    if IS_WINDOWS {
        let mut escaped = escape_sendkeys(text);
        if auto_enter {
            escaped.push_str("{ENTER}");
        }
        let ps = "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait($env:MRC_SENDKEYS_PAYLOAD)";
        let (rc, out, err) = crate::telemetry::win_run_ps(
            cfg,
            ps,
            6.0,
            &[("MRC_SENDKEYS_PAYLOAD", &escaped)],
        );
        if rc == 0 {
            return (true, "SendKeys".into());
        }
        return (
            false,
            if !err.is_empty() {
                err
            } else if !out.is_empty() {
                out
            } else {
                "SendKeys failed".into()
            },
        );
    }

    if find_bin(cfg, "wtype", sp).is_some() {
        let (rc, _, err) = run_as_user(cfg, &["wtype", "--", text], 5.0, None, None, false, false);
        if rc == 0 {
            if auto_enter {
                let _ = run_as_user(cfg, &["wtype", "-k", "Return"], 3.0, None, None, false, false);
            }
            return (true, "wtype".into());
        }
        return (false, err);
    }
    if find_bin(cfg, "ydotool", sp).is_some() {
        let (rc, _, err) =
            run_as_user(cfg, &["ydotool", "type", "--", text], 5.0, None, None, false, false);
        if rc == 0 {
            if auto_enter {
                let _ = run_as_user(
                    cfg,
                    &["ydotool", "key", "28:1", "28:0"],
                    3.0,
                    None,
                    None,
                    false,
                    false,
                );
            }
            return (true, "ydotool".into());
        }
        return (false, err);
    }
    if find_bin(cfg, "xdotool", sp).is_some() {
        let (rc, _, err) = run_as_user(
            cfg,
            &["xdotool", "type", "--clearmodifiers", "--", text],
            5.0,
            None,
            None,
            false,
            false,
        );
        if rc == 0 {
            if auto_enter {
                let _ = run_as_user(
                    cfg,
                    &["xdotool", "key", "Return"],
                    3.0,
                    None,
                    None,
                    false,
                    false,
                );
            }
            return (true, "xdotool".into());
        }
        return (false, err);
    }
    (
        false,
        "Install wtype (Wayland), ydotool, or xdotool (X11) for active-window typing".into(),
    )
}

pub fn spawn_terminal_with_command(cfg: &ConfigStore, cmd_str: &str) -> (bool, String) {
    let env = get_desktop_env(cfg);
    let sp = env.get("PATH").map(String::as_str);

    if IS_WINDOWS {
        let candidates: Vec<(&str, Vec<&str>)> = vec![
            ("wt", vec!["powershell.exe", "-NoExit", "-Command", cmd_str]),
            ("powershell", vec!["-NoExit", "-Command", cmd_str]),
            ("cmd", vec!["/k", cmd_str]),
        ];
        for (bin, args) in candidates {
            if let Some(resolved) = find_bin(cfg, bin, sp) {
                let mut full = vec![resolved.as_str()];
                full.extend(args);
                run_as_user(cfg, &full, 8.0, None, None, true, true);
                cfg.record_audit_event("INFO", format!("Opened Windows terminal ({bin}) with command"));
                return (true, bin.into());
            }
        }
        return (false, "No Windows terminal emulator found".into());
    }

    let runner = r#"printf "\033[1;36m$ %s\033[0m\n" "$1"; eval "$1"; echo ""; exec "${SHELL:-/bin/sh}""#;
    let candidates: Vec<(&str, Vec<&str>)> = vec![
        ("kitty", vec!["-e", "sh", "-c", runner, "_", cmd_str]),
        ("konsole", vec!["-e", "sh", "-c", runner, "_", cmd_str]),
        ("alacritty", vec!["-e", "sh", "-c", runner, "_", cmd_str]),
        ("foot", vec!["sh", "-c", runner, "_", cmd_str]),
        ("wezterm", vec!["start", "--", "sh", "-c", runner, "_", cmd_str]),
        ("ghostty", vec!["-e", "sh", "-c", runner, "_", cmd_str]),
        ("gnome-terminal", vec!["--", "sh", "-c", runner, "_", cmd_str]),
        ("xfce4-terminal", vec!["-x", "sh", "-c", runner, "_", cmd_str]),
        ("xterm", vec!["-e", "sh", "-c", runner, "_", cmd_str]),
    ];
    for (bin, args) in candidates {
        if let Some(resolved) = find_bin(cfg, bin, sp) {
            let mut full = vec![resolved.as_str()];
            full.extend(args);
            run_as_user(cfg, &full, 8.0, None, None, true, true);
            cfg.record_audit_event(
                "INFO",
                format!("Opened on-screen terminal ({bin}) with command"),
            );
            return (true, bin.into());
        }
    }
    (false, "No supported desktop terminal emulator found".into())
}

pub fn capture_desktop_screenshot(cfg: &ConfigStore) -> Option<(Vec<u8>, &'static str)> {
    let user = cfg.get_target_user_info();
    let tmpdir = std::env::temp_dir().join(format!("mrc_shot_{}", random_hex(6)));
    fs::create_dir_all(&tmpdir).ok()?;
    #[cfg(unix)]
    {
        if crate::config::is_root_or_admin() && user.uid != 0 {
            crate::config::chown_path(&tmpdir, user.uid, user.gid);
        }
        let _ = fs::set_permissions(&tmpdir, fs::Permissions::from_mode(0o700));
    }

    let raw_path = tmpdir.join("raw.png");
    let shot_path = tmpdir.join("shot.jpg");
    let raw_str = raw_path.to_string_lossy().into_owned();
    let shot_str = shot_path.to_string_lossy().into_owned();

    let result = if IS_WINDOWS {
        let ps_script = "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; $vs = [System.Windows.Forms.SystemInformation]::VirtualScreen; $bmp = New-Object System.Drawing.Bitmap($vs.Width, $vs.Height); $g = [System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($vs.Left, $vs.Top, 0, 0, $bmp.Size); $scale = [Math]::Min(1.0, [Math]::Min(1280.0 / [Math]::Max(1, $bmp.Width), 800.0 / [Math]::Max(1, $bmp.Height))); $tw = [Math]::Max(1, [int][Math]::Round($bmp.Width * $scale)); $th = [Math]::Max(1, [int][Math]::Round($bmp.Height * $scale)); $outBmp = New-Object System.Drawing.Bitmap($tw, $th); $g2 = [System.Drawing.Graphics]::FromImage($outBmp); $g2.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic; $g2.DrawImage($bmp, 0, 0, $tw, $th); $enc = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' } | Select-Object -First 1; $ep = New-Object System.Drawing.Imaging.EncoderParameters(1); $ep.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality, 75L); $outBmp.Save($env:MRC_SHOT_PATH, $enc, $ep); $g2.Dispose(); $outBmp.Dispose(); $g.Dispose(); $bmp.Dispose()";
        let (rc, _, _) =
            crate::telemetry::win_run_ps(cfg, ps_script, 8.0, &[("MRC_SHOT_PATH", &shot_str)]);
        if rc == 0 && fs::metadata(&shot_path).map(|m| m.len()).unwrap_or(0) > 500 {
            fs::read(&shot_path).ok().map(|b| (b, "image/jpeg"))
        } else {
            None
        }
    } else {
        let env = get_desktop_env(cfg);
        let sp = env.get("PATH").map(String::as_str);
        let comp = get_active_compositor(&env);
        let mut cmds = vec![
            vec!["grim", &raw_str],
            vec!["wayshot", "-f", &raw_str],
            vec!["spectacle", "-b", "-n", "-o", &raw_str],
            vec!["gnome-screenshot", "-f", &raw_str],
            vec!["maim", &raw_str],
            vec!["scrot", &raw_str],
            vec!["import", "-window", "root", &raw_str],
        ];
        if comp == "kde" {
            let spec = cmds.remove(2);
            cmds.insert(0, spec);
        } else if comp == "gnome" {
            let gnm = cmds.remove(3);
            cmds.insert(0, gnm);
        }
        for cmd in cmds {
            if find_bin(cfg, cmd[0], sp).is_none() {
                continue;
            }
            let (rc, _, _) = run_as_user(cfg, &cmd, 8.0, None, None, false, false);
            if rc == 0 && fs::metadata(&raw_path).map(|m| m.len()).unwrap_or(0) > 1000 {
                break;
            }
        }
        if fs::metadata(&raw_path).map(|m| m.len()).unwrap_or(0) > 1000 {
            let resize_cmds = vec![
                vec![
                    "magick".into(),
                    raw_str.clone(),
                    "-resize".into(),
                    "1280x800".into(),
                    "-quality".into(),
                    "75".into(),
                    shot_str.clone(),
                ],
                vec![
                    "convert".into(),
                    raw_str.clone(),
                    "-resize".into(),
                    "1280x800".into(),
                    "-quality".into(),
                    "75".into(),
                    shot_str.clone(),
                ],
            ];
            let _ = run_first_available(cfg, &resize_cmds, 8.0, None, false, false);
            if fs::metadata(&shot_path).map(|m| m.len()).unwrap_or(0) > 1000 {
                fs::read(&shot_path).ok().map(|b| (b, "image/jpeg"))
            } else {
                fs::read(&raw_path).ok().map(|b| (b, "image/png"))
            }
        } else {
            None
        }
    };

    let _ = fs::remove_dir_all(&tmpdir);
    result
}

pub fn launch_preset_cmds(preset: &str) -> Option<Vec<Vec<&'static str>>> {
    Some(match preset {
        "terminal" => vec![
            vec!["kitty"],
            vec!["konsole"],
            vec!["alacritty"],
            vec!["foot"],
            vec!["wezterm"],
            vec!["ghostty"],
            vec!["gnome-terminal"],
            vec!["xfce4-terminal"],
            vec!["xterm"],
        ],
        "youtube" => vec![vec!["xdg-open", "https://youtube.com"]],
        "files" => vec![
            vec!["dolphin"],
            vec!["thunar"],
            vec!["nautilus"],
            vec!["nemo"],
            vec!["pcmanfm"],
        ],
        "btop" => vec![
            vec!["kitty", "-e", "btop"],
            vec!["konsole", "-e", "btop"],
            vec!["alacritty", "-e", "btop"],
            vec!["foot", "btop"],
            vec!["xterm", "-e", "top"],
        ],
        _ => return None,
    })
}

pub fn is_valid_hypr_preset(act: &str) -> bool {
    matches!(act, "fullscreen" | "killactive" | "dpms_toggle")
}

fn hypr_preset_generic(act: &str) -> Vec<Vec<String>> {
    let raw: &[&[&str]] = match act {
        "fullscreen" => &[
            &["hyprctl", "dispatch", "hl.dsp.window.fullscreen({ mode = 0 })"],
            &["hyprctl", "dispatch", "fullscreen", "0"],
            &["niri", "msg", "action", "fullscreen-window"],
            &["swaymsg", "fullscreen", "toggle"],
            &["riverctl", "toggle-fullscreen"],
            &["qdbus6", "org.kde.kglobalaccel", "/component/kwin", "invokeShortcut", "Window Fullscreen"],
            &["qdbus", "org.kde.kglobalaccel", "/component/kwin", "invokeShortcut", "Window Fullscreen"],
            &["wmctrl", "-r", ":ACTIVE:", "-b", "toggle,fullscreen"],
            &["xdotool", "key", "F11"],
        ],
        "killactive" => &[
            &["hyprctl", "dispatch", "hl.dsp.window.close()"],
            &["hyprctl", "dispatch", "killactive"],
            &["niri", "msg", "action", "close-window"],
            &["swaymsg", "kill"],
            &["riverctl", "close"],
            &["qdbus6", "org.kde.kglobalaccel", "/component/kwin", "invokeShortcut", "Window Close"],
            &["qdbus", "org.kde.kglobalaccel", "/component/kwin", "invokeShortcut", "Window Close"],
            &["kdotool", "getactivewindow", "windowclose"],
            &["wmctrl", "-c", ":ACTIVE:"],
            &["xdotool", "getactivewindow", "windowclose"],
        ],
        "dpms_toggle" => &[
            &["hyprctl", "dispatch", r#"hl.dsp.dpms({ action = "toggle" })"#],
            &["hyprctl", "dispatch", "dpms", "toggle"],
            &["niri", "msg", "action", "power-off-monitors"],
            &["swaymsg", "output", "*", "dpms", "toggle"],
            &["wlopm", "--toggle", "*"],
            &["qdbus6", "org.kde.kglobalaccel", "/component/org_kde_powerdevil", "invokeShortcut", "Turn Off Screen"],
            &["qdbus", "org.kde.kglobalaccel", "/component/org_kde_powerdevil", "invokeShortcut", "Turn Off Screen"],
            &["kscreen-doctor", "--dpms", "off"],
            &["xset", "dpms", "force", "off"],
        ],
        _ => &[],
    };
    raw.iter()
        .map(|row| row.iter().map(|s| (*s).to_string()).collect())
        .collect()
}

pub fn get_window_action_cmds(act: &str, env: &HashMap<String, String>) -> Vec<Vec<String>> {
    let comp = get_active_compositor(env);
    let to_vecs = |slices: &[&[&str]]| -> Vec<Vec<String>> {
        slices
            .iter()
            .map(|r| r.iter().map(|s| (*s).to_string()).collect())
            .collect()
    };

    let x11_fallback = match act {
        "fullscreen" => to_vecs(&[
            &["wmctrl", "-r", ":ACTIVE:", "-b", "toggle,fullscreen"],
            &["xdotool", "key", "F11"],
        ]),
        "killactive" => to_vecs(&[
            &["wmctrl", "-c", ":ACTIVE:"],
            &["xdotool", "getactivewindow", "windowclose"],
        ]),
        "dpms_toggle" => to_vecs(&[&["wlopm", "--toggle", "*"], &["xset", "dpms", "force", "off"]]),
        _ => Vec::new(),
    };

    let mut comp_cmds = match (comp, act) {
        ("hyprland", "fullscreen") => to_vecs(&[
            &["hyprctl", "dispatch", "hl.dsp.window.fullscreen({ mode = 0 })"],
            &["hyprctl", "dispatch", "fullscreen", "0"],
        ]),
        ("hyprland", "killactive") => to_vecs(&[
            &["hyprctl", "dispatch", "hl.dsp.window.close()"],
            &["hyprctl", "dispatch", "killactive"],
        ]),
        ("hyprland", "dpms_toggle") => to_vecs(&[
            &["hyprctl", "dispatch", r#"hl.dsp.dpms({ action = "toggle" })"#],
            &["hyprctl", "dispatch", "dpms", "toggle"],
            &["wlopm", "--toggle", "*"],
        ]),
        ("niri", "fullscreen") => to_vecs(&[&["niri", "msg", "action", "fullscreen-window"]]),
        ("niri", "killactive") => to_vecs(&[&["niri", "msg", "action", "close-window"]]),
        ("niri", "dpms_toggle") => to_vecs(&[
            &["niri", "msg", "action", "power-off-monitors"],
            &["wlopm", "--toggle", "*"],
        ]),
        ("sway", "fullscreen") => to_vecs(&[&["swaymsg", "fullscreen", "toggle"]]),
        ("sway", "killactive") => to_vecs(&[&["swaymsg", "kill"]]),
        ("sway", "dpms_toggle") => {
            to_vecs(&[&["swaymsg", "output", "*", "dpms", "toggle"], &["wlopm", "--toggle", "*"]])
        }
        ("river", "fullscreen") => to_vecs(&[&["riverctl", "toggle-fullscreen"]]),
        ("river", "killactive") => to_vecs(&[&["riverctl", "close"]]),
        ("river", "dpms_toggle") => to_vecs(&[&["wlopm", "--toggle", "*"]]),
        ("kde", "fullscreen") => to_vecs(&[
            &["qdbus6", "org.kde.kglobalaccel", "/component/kwin", "invokeShortcut", "Window Fullscreen"],
            &["qdbus", "org.kde.kglobalaccel", "/component/kwin", "invokeShortcut", "Window Fullscreen"],
            &["dbus-send", "--session", "--dest=org.kde.kglobalaccel", "/component/kwin", "org.kde.kglobalaccel.Component.invokeShortcut", "string:Window Fullscreen"],
        ]),
        ("kde", "killactive") => to_vecs(&[
            &["qdbus6", "org.kde.kglobalaccel", "/component/kwin", "invokeShortcut", "Window Close"],
            &["qdbus", "org.kde.kglobalaccel", "/component/kwin", "invokeShortcut", "Window Close"],
            &["dbus-send", "--session", "--dest=org.kde.kglobalaccel", "/component/kwin", "org.kde.kglobalaccel.Component.invokeShortcut", "string:Window Close"],
            &["kdotool", "getactivewindow", "windowclose"],
        ]),
        ("kde", "dpms_toggle") => to_vecs(&[
            &["dbus-send", "--session", "--dest=org.kde.kglobalaccel", "/component/org_kde_powerdevil", "org.kde.kglobalaccel.Component.invokeShortcut", "string:Turn Off Screen"],
            &["qdbus6", "org.kde.kglobalaccel", "/component/org_kde_powerdevil", "invokeShortcut", "Turn Off Screen"],
            &["qdbus", "org.kde.kglobalaccel", "/component/org_kde_powerdevil", "invokeShortcut", "Turn Off Screen"],
            &["kscreen-doctor", "--dpms", "off"],
        ]),
        ("gnome", _) => return x11_fallback,
        _ => return hypr_preset_generic(act),
    };
    comp_cmds.extend(x11_fallback);
    comp_cmds
}

pub fn switch_workspace(cfg: &ConfigStore, tel: &TelemetryState, val_num: i64) -> Result<(), String> {
    if !(1..=99).contains(&val_num) {
        return Err("Workspace must be between 1 and 99".into());
    }
    let env = get_desktop_env(cfg);
    let comp = get_active_compositor(&env);
    let s = val_num.to_string();
    let hl_arg = format!("hl.dsp.focus({{ workspace = {val_num} }})");
    let dbus_int = format!("int32:{val_num}");
    let x11_num = (val_num - 1).to_string();

    let hypr_cmds = vec![
        vec!["hyprctl".into(), "dispatch".into(), hl_arg],
        vec!["hyprctl".into(), "dispatch".into(), "workspace".into(), s.clone()],
    ];
    let niri_cmds = vec![vec!["niri".into(), "msg".into(), "action".into(), "focus-workspace".into(), s.clone()]];
    let sway_cmds = vec![vec!["swaymsg".into(), "workspace".into(), s.clone()]];
    let kde_cmds = vec![
        vec!["qdbus6".into(), "org.kde.KWin".into(), "/KWin".into(), "org.kde.KWin.setCurrentDesktop".into(), s.clone()],
        vec!["qdbus".into(), "org.kde.KWin".into(), "/KWin".into(), "org.kde.KWin.setCurrentDesktop".into(), s.clone()],
        vec!["dbus-send".into(), "--session".into(), "--dest=org.kde.KWin".into(), "/KWin".into(), "org.kde.KWin.setCurrentDesktop".into(), dbus_int],
        vec!["kdotool".into(), "set_desktop".into(), s.clone()],
    ];
    let x11_ws = vec![
        vec!["wmctrl".into(), "-s".into(), x11_num.clone()],
        vec!["xdotool".into(), "set_desktop".into(), x11_num],
    ];

    let ws_cmds: Vec<Vec<String>> = match comp {
        "hyprland" => {
            let mut v = hypr_cmds;
            v.extend(x11_ws);
            v
        }
        "niri" => {
            let mut v = niri_cmds;
            v.extend(x11_ws);
            v
        }
        "sway" => {
            let mut v = sway_cmds;
            v.extend(x11_ws);
            v
        }
        "kde" => {
            let mut v = kde_cmds;
            v.extend(x11_ws);
            v
        }
        "river" if val_num <= 32 => {
            let mask = (1u64 << (val_num - 1) as u32).to_string();
            let mut v = vec![vec!["riverctl".into(), "set-focused-tags".into(), mask]];
            v.extend(x11_ws);
            v
        }
        _ => {
            let mut v = hypr_cmds;
            v.extend(niri_cmds);
            v.extend(sway_cmds);
            v.extend(kde_cmds);
            v.extend(x11_ws);
            v
        }
    };
    let (rc, _, err) = run_first_available(cfg, &ws_cmds, 8.0, None, false, false);
    if rc != 0 {
        return Err(if err.is_empty() {
            format!("Failed to switch to Workspace {val_num}")
        } else {
            err
        });
    }
    if comp == "river" {
        tel.last_river_tag.store(val_num, Ordering::Relaxed);
    }
    cfg.invalidate_cache(&["workspaces_info"]);
    Ok(())
}

/// Validate and sanitize an external HTTP/HTTPS URL before opening it in the desktop browser.
pub fn validate_open_url(raw: &str) -> Result<String, &'static str> {
    let mut url = raw.trim().to_string();
    if url.is_empty()
        || url
            .chars()
            .any(|ch| ch.is_whitespace() || (ch as u32) < 32)
    {
        return Err("Invalid HTTP/HTTPS URL");
    }
    let head = url.split('/').next().unwrap_or("");
    if !url.contains("://") {
        let can_prepend = match head.split_once(':') {
            None => true,
            Some((_, after_colon)) => after_colon.chars().all(|c| c.is_ascii_digit()) && !after_colon.is_empty(),
        };
        if can_prepend {
            url = format!("https://{url}");
        }
    }
    let Some((scheme, after_scheme)) = url.split_once("://") else {
        return Err("Invalid HTTP/HTTPS URL");
    };
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        return Err("Invalid HTTP/HTTPS URL");
    }
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err("Invalid HTTP/HTTPS URL");
    }
    // Check optional port validity
    let host_part = if let Some(rest) = authority.strip_prefix('[') {
        let Some((h, tail)) = rest.split_once(']') else {
            return Err("Invalid HTTP/HTTPS URL");
        };
        if !tail.is_empty() {
            let Some(port_s) = tail.strip_prefix(':') else {
                return Err("Invalid HTTP/HTTPS URL");
            };
            if port_s.parse::<u16>().is_err() {
                return Err("Invalid HTTP/HTTPS URL");
            }
        }
        h
    } else if let Some((h, port_s)) = authority.split_once(':') {
        if port_s.parse::<u16>().is_err() {
            return Err("Invalid HTTP/HTTPS URL");
        }
        h
    } else {
        authority
    };
    if host_part.is_empty() {
        return Err("Invalid HTTP/HTTPS URL");
    }
    Ok(url)
}

pub fn delayed_power(cfg: Arc<ConfigStore>, cmds: Vec<Vec<&'static str>>) {
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(800));
        run_first_system_cmd(&cfg, &cmds.iter().map(Vec::as_slice).collect::<Vec<_>>(), 8.0);
    });
}

pub fn spawn_windows_launch(exe: &str, args: &[&str], new_console: bool) -> bool {
    let mut cmd = Command::new(exe);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    if new_console {
        cmd.creationflags(0x0000_0010); // CREATE_NEW_CONSOLE
    } else {
        cmd.creationflags(CREATE_NO_WINDOW);
    }
    let _ = new_console;
    match cmd.spawn() {
        Ok(mut ch) => {
            thread::spawn(move || {
                let _ = ch.wait();
            });
            true
        }
        Err(_) => false,
    }
}

#[cfg(windows)]
pub fn win_open_url(url: &str) -> bool {
    spawn_windows_launch("rundll32.exe", &["url.dll,FileProtocolHandler", url], false)
}

#[cfg(not(windows))]
pub fn win_open_url(url: &str) -> bool {
    let _ = Path::new(url);
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_tunnel_url_ignores_banner_links() {
        assert_eq!(extract_tunnel_url("visit https://admin.localhost.run/login"), None);
        assert_eq!(extract_tunnel_url("docs at https://www.localhost.run/docs"), None);
        assert_eq!(extract_tunnel_url("https://docs.localhost.run"), None);
        assert_eq!(
            extract_tunnel_url("abc.lhr.life tunneled with tls termination, https://abc123def.lhr.life"),
            Some("https://abc123def.lhr.life".into())
        );
        assert_eq!(
            extract_tunnel_url("connected https://myhost.localhost.run."),
            Some("https://myhost.localhost.run".into())
        );
    }

    #[test]
    fn test_validate_open_url() {
        assert_eq!(validate_open_url("example.com/foo").unwrap(), "https://example.com/foo");
        assert_eq!(
            validate_open_url("http://192.168.1.5:8080/ui").unwrap(),
            "http://192.168.1.5:8080/ui"
        );
        assert!(validate_open_url("javascript:alert(1)").is_err());
        assert!(validate_open_url("https://user:pass@evil.com").is_err());
        assert!(validate_open_url("https://bad host.com").is_err());
    }

    #[test]
    fn test_control_service_and_kill_pid_validation() {
        let dir = std::env::temp_dir().join(format!("mrc-act-{}", random_hex(5)));
        let mut s = crate::config::Settings::from_env();
        s.config_dir = dir.clone();
        s.config_file = dir.join("config.json");
        let cfg = ConfigStore::new(s);
        let tel = TelemetryState::new();

        assert_eq!(
            control_service(&cfg, &tel, "bad;rm -rf /", "restart"),
            (false, "Invalid service name".into())
        );
        assert_eq!(
            control_service(&cfg, &tel, "nginx", "destroy"),
            (false, "Invalid service action".into())
        );
        assert!(!kill_process(&cfg, 1, "TERM").0);
        assert!(!kill_process(&cfg, std::process::id() as i64, "TERM").0);
        assert!(!kill_process(&cfg, 999999, "SIGFAKE").0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_escape_sendkeys() {
        assert_eq!(escape_sendkeys("a+b%(c)\nd"), "a{+}b{%}{(}c{)}{ENTER}d");
    }
}

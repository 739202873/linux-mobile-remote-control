//! Cross-platform host control actions, input injection, screenshot capture, and SSH tunnel lifecycle.

#[cfg(not(windows))]
mod linux;
#[cfg(not(windows))]
use linux as platform;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as platform;

use crate::config::{random_hex, write_secure_file, ConfigStore};
use crate::telemetry::{
    exec_cmd_blocking, find_bin, get_active_compositor, get_hostname, get_system_path,
    run_first_system_cmd, url_encode, TelemetryState, IS_WINDOWS,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub(crate) const ALLOWED_REMOTE_KEYS: &[&str] = &[
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
            platform::configure_tunnel_command(&mut cmd);

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
    if cfg.settings.ssh_key_file.exists() {
        platform::set_private_file_permissions(&cfg.settings.ssh_key_file);
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

    let (rc, out, err) = match platform::run_service_action(cfg, tel, svc, &act) {
        Ok(res) => res,
        Err(msg) => return (false, msg),
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
    platform::signal_process(cfg, pid_val, sig_key)
}

pub fn win_send_vk(vk_code: u8, hold_alt: bool) -> bool {
    platform::win_send_vk(vk_code, hold_alt)
}

pub fn win_lock_workstation() -> bool {
    platform::win_lock_workstation()
}

pub fn win_dpms_off() -> bool {
    platform::win_dpms_off()
}

pub fn send_remote_input(cfg: &ConfigStore, kind: &str, payload: &Value) -> (bool, String) {
    let k = kind.trim().to_ascii_lowercase();
    if k == "text" {
        let text = payload.get("text").and_then(|v| v.as_str()).unwrap_or("");
        if text.is_empty() || text.chars().count() > 1000 {
            return (false, "Text must be 1-1000 characters".into());
        }
        let auto_enter = payload
            .get("auto_enter")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        return type_prompt_to_active_window(cfg, text, auto_enter);
    }
    platform::send_remote_input(cfg, &k, payload)
}

pub fn val_as_f64(v: &Value) -> Option<f64> {
    v.as_f64()
        .or_else(|| v.as_i64().map(|n| n as f64))
        .or_else(|| v.as_str().and_then(|s| s.trim().parse::<f64>().ok()))
}

pub fn adjust_brightness(cfg: &ConfigStore, mode: &str, value: Option<i64>) -> bool {
    if platform::adjust_brightness(cfg, mode, value) {
        cfg.invalidate_cache(&["media_display"]);
        return true;
    }
    false
}

#[cfg(any(windows, test))]
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
    platform::type_prompt_to_active_window(cfg, text, auto_enter)
}

pub fn spawn_terminal_with_command(cfg: &ConfigStore, cmd_str: &str) -> (bool, String) {
    platform::spawn_terminal_with_command(cfg, cmd_str)
}

pub fn capture_desktop_screenshot(cfg: &ConfigStore) -> Option<(Vec<u8>, &'static str)> {
    let tmpdir = std::env::temp_dir().join(format!("mrc_shot_{}", random_hex(6)));
    fs::create_dir_all(&tmpdir).ok()?;
    let result = platform::capture_desktop_screenshot(cfg, &tmpdir);
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
    platform::switch_workspace(cfg, tel, val_num)?;
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
    platform::spawn_windows_launch(exe, args, new_console)
}

pub fn win_open_url(url: &str) -> bool {
    platform::win_open_url(url)
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

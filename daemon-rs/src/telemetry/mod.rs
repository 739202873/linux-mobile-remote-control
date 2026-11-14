//! Cross-platform system telemetry, command execution helpers, logs, services, and OS inventory.

#[cfg(not(windows))]
mod linux;
#[cfg(not(windows))]
use linux as platform;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as platform;

use crate::config::ConfigStore;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicI64;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

#[cfg(windows)]
use std::os::windows::process::CommandExt as WinCommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub const IS_WINDOWS: bool = cfg!(windows);

#[derive(Default)]
pub(crate) struct DistroCacheSlot {
    pub(crate) ts: f64,
    pub(crate) payload: Value,
}

pub struct TelemetryState {
    pub(crate) last_cpu: Mutex<Option<(u64, u64)>>,
    pub(crate) net_last: Mutex<Option<(Instant, u64, u64)>>,
    pub(crate) proc_last: Mutex<Option<(u64, HashMap<i32, u64>)>>,
    pub(crate) distro_scan_lock: Mutex<()>,
    pub(crate) distro_cache: Mutex<HashMap<&'static str, DistroCacheSlot>>,
    pub last_river_tag: AtomicI64,
}

impl Default for TelemetryState {
    fn default() -> Self {
        Self::new()
    }
}

impl TelemetryState {
    pub fn new() -> Self {
        Self {
            last_cpu: Mutex::new(None),
            net_last: Mutex::new(None),
            proc_last: Mutex::new(None),
            distro_scan_lock: Mutex::new(()),
            distro_cache: Mutex::new(HashMap::new()),
            last_river_tag: AtomicI64::new(1),
        }
    }

    pub fn get_cpu_percent(&self) -> f64 {
        platform::get_cpu_percent(self)
    }

    pub fn get_cpu_temp(&self, cfg: &ConfigStore) -> f64 {
        platform::get_cpu_temp(cfg)
    }

    pub fn get_gpu_info(&self, cfg: &ConfigStore) -> Value {
        cfg.cached("gpu_info", 5.0, false, || compute_gpu_info(cfg))
    }

    pub fn get_memory_info(&self) -> Value {
        platform::get_memory_info()
    }

    pub fn get_swap_info(&self) -> Value {
        platform::get_swap_info()
    }

    pub fn get_battery_info(&self) -> Value {
        platform::get_battery_info()
    }

    pub fn get_mac_addresses(&self, cfg: &ConfigStore) -> Vec<Value> {
        let v = cfg.cached("mac_addresses", 30.0, false, || {
            Value::Array(platform::compute_mac_addresses(cfg))
        });
        v.as_array().cloned().unwrap_or_default()
    }

    pub fn get_network_telemetry(&self, cfg: &ConfigStore) -> Value {
        let (rx_total, tx_total) = platform::compute_net_bytes(cfg);
        let now = Instant::now();
        let (rx_kbps, tx_kbps) = {
            let mut guard = self.net_last.lock().unwrap();
            let res = if let Some((prev_ts, prev_rx, prev_tx)) = *guard {
                let dt = now.duration_since(prev_ts).as_secs_f64().max(0.2);
                (
                    round1(rx_total.saturating_sub(prev_rx) as f64 / 1024.0 / dt),
                    round1(tx_total.saturating_sub(prev_tx) as f64 / 1024.0 / dt),
                )
            } else {
                (0.0, 0.0)
            };
            *guard = Some((now, rx_total, tx_total));
            res
        };

        json!({
            "rx_kbps": rx_kbps,
            "tx_kbps": tx_kbps,
            "macs": self.get_mac_addresses(cfg),
        })
    }

    pub fn get_os_info(&self, cfg: &ConfigStore) -> Value {
        let mut base = cfg.cached("os_static", 3600.0, false, platform::compute_os_static);
        let uptime_str = platform::uptime_secs()
            .map(|secs| {
                let h = secs / 3600;
                let m = (secs % 3600) / 60;
                if h > 0 { format!("{h}h {m}m") } else { format!("{m}m") }
            })
            .unwrap_or_else(|| "-".to_string());
        if let Some(obj) = base.as_object_mut() {
            obj.insert("uptime".into(), Value::String(uptime_str));
        }
        base
    }

    pub fn detect_init_system(&self, cfg: &ConfigStore) -> String {
        let v = cfg.cached("init_system", 3600.0, false, || {
            Value::String(platform::compute_init_system(cfg))
        });
        v.as_str().unwrap_or("unknown").to_string()
    }

    pub fn get_media_and_display(&self, cfg: &ConfigStore) -> Value {
        cfg.cached("media_display", 3.0, false, || platform::compute_media_and_display(cfg))
    }

    pub fn get_workspaces_info(&self, cfg: &ConfigStore) -> Value {
        let river_tag = self
            .last_river_tag
            .load(std::sync::atomic::Ordering::Relaxed);
        cfg.cached("workspaces_info", 2.5, false, || {
            Value::Array(platform::compute_workspaces_info(cfg, river_tag))
        })
    }

    pub fn get_disks_info(&self, cfg: &ConfigStore, refresh: bool) -> Value {
        cfg.cached("disks_info", 20.0, refresh, || {
            Value::Array(platform::compute_disks_info())
        })
    }

    pub fn get_boot_entries(&self, cfg: &ConfigStore, refresh: bool) -> Value {
        cfg.cached("boot_entries", 300.0, refresh, || {
            Value::Array(platform::compute_boot_entries(cfg))
        })
    }

    pub fn get_local_ips(&self, cfg: &ConfigStore) -> Vec<String> {
        let v = cfg.cached("local_ips", 15.0, false, || {
            let mut ips = platform::compute_local_ips(cfg);
            if ips.is_empty() {
                if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
                    if sock.connect("8.8.8.8:80").is_ok() {
                        if let Ok(addr) = sock.local_addr() {
                            let s = addr.ip().to_string();
                            if !s.starts_with("127.") {
                                ips.push(s);
                            }
                        }
                    }
                }
            }
            Value::Array(ips.into_iter().map(Value::String).collect())
        });
        v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn get_services_info(&self, cfg: &ConfigStore) -> Value {
        let init_sys = self.detect_init_system(cfg);
        cfg.cached("services_info", 4.0, false, || {
            platform::compute_services_info(cfg, &init_sys)
        })
    }

    pub fn get_processes_info(&self, limit: usize) -> Value {
        let cap = limit.clamp(5, 60);
        platform::get_processes_info(self, cap)
    }

    pub fn get_system_logs(
        &self,
        cfg: &ConfigStore,
        source: &str,
        level: &str,
        query: &str,
        lines: &str,
    ) -> Value {
        let src = source.trim().to_ascii_lowercase();
        let src = if src.is_empty() { "all" } else { src.as_str() };
        let lvl = level.trim().to_ascii_lowercase();
        let lvl = if lvl.is_empty() { "all" } else { lvl.as_str() };
        let q_low: String = query.trim().to_ascii_lowercase().chars().take(120).collect();
        let limit = lines
            .trim()
            .parse::<usize>()
            .unwrap_or(120)
            .clamp(20, 400);
        let per_src = if src != "all" {
            limit
        } else {
            limit.clamp(30, 80)
        };

        let (available_sources, entries) = platform::collect_logs(cfg, src, lvl, per_src);

        let mut filtered: Vec<Value> = Vec::new();
        for item in entries {
            let item_lvl = item.get("level").and_then(|v| v.as_str()).unwrap_or("INFO");
            if !level_matches_filter(item_lvl, lvl) {
                continue;
            }
            if !q_low.is_empty() {
                let hay = format!(
                    "{} {} {} {}",
                    item.get("ts").and_then(|v| v.as_str()).unwrap_or(""),
                    item.get("source").and_then(|v| v.as_str()).unwrap_or(""),
                    item_lvl,
                    item.get("message").and_then(|v| v.as_str()).unwrap_or(""),
                )
                .to_ascii_lowercase();
                if !hay.contains(&q_low) {
                    continue;
                }
            }
            filtered.push(item);
        }

        if filtered.len() > limit {
            filtered.drain(0..filtered.len() - limit);
        }

        json!({
            "init_system": self.detect_init_system(cfg),
            "available_sources": available_sources,
            "entries": filtered,
            "total": filtered.len(),
        })
    }

    pub fn get_installed_distros_info(
        &self,
        cfg: &ConfigStore,
        deep: bool,
        refresh: bool,
    ) -> Value {
        let cache_key = if deep { "deep" } else { "safe" };
        let now = crate::config::unix_secs_f64();
        let ttl = if deep { 300.0 } else { 45.0 };
        if !refresh {
            let guard = self.distro_cache.lock().unwrap();
            if let Some(slot) = guard.get(cache_key) {
                if (now - slot.ts) < ttl {
                    let mut res = slot.payload.clone();
                    if let Some(obj) = res.as_object_mut() {
                        obj.insert("cached".into(), Value::Bool(true));
                    }
                    return res;
                }
            }
        }

        let os_info = self.get_os_info(cfg);
        let payload = platform::compute_installed_distros(self, cfg, &os_info, deep, refresh);
        self.distro_cache.lock().unwrap().insert(
            cache_key,
            DistroCacheSlot {
                ts: now,
                payload: payload.clone(),
            },
        );
        payload
    }
}

pub(crate) fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

pub(crate) fn compute_gpu_info(cfg: &ConfigStore) -> Value {
    if find_bin(cfg, "nvidia-smi", None).is_some() {
        let (rc, out, _) = run_cmd(
            &[
                "nvidia-smi",
                "--query-gpu=name,utilization.gpu,temperature.gpu",
                "--format=csv,noheader,nounits",
            ],
            3.0,
        );
        if rc == 0 {
            if let Some(first) = out.lines().next() {
                let parts: Vec<&str> = first.split(',').map(str::trim).collect();
                if parts.len() >= 3 {
                    if let (Ok(busy), Ok(temp)) =
                        (parts[1].parse::<f64>(), parts[2].parse::<f64>())
                    {
                        return json!({
                            "available": true,
                            "name": parts[0],
                            "busy_pct": busy.round() as i64,
                            "temp_c": round1(temp),
                        });
                    }
                }
            }
        }
    }
    platform::compute_gpu_fallback(cfg)
}

pub fn merge_path_dirs(groups: &[&str]) -> String {
    let sep = if IS_WINDOWS { ';' } else { ':' };
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for group in groups {
        for part in group.split(sep) {
            let p = part.trim();
            if !p.is_empty() && seen.insert(p.to_string()) {
                out.push(p.to_string());
            }
        }
    }
    let sep_str = if IS_WINDOWS { ";" } else { ":" };
    out.join(sep_str)
}

pub fn get_system_path() -> String {
    let cur = std::env::var("PATH").unwrap_or_default();
    if IS_WINDOWS {
        let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let win_dirs = format!(
            r"{sys_root}\System32;{sys_root};{sys_root}\System32\Wbem;{sys_root}\System32\WindowsPowerShell\v1.0"
        );
        return merge_path_dirs(&[&cur, &win_dirs]);
    }
    merge_path_dirs(&[
        &cur,
        "/run/wrappers/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    ])
}

pub fn find_bin(cfg: &ConfigStore, name: &str, search_path: Option<&str>) -> Option<String> {
    let sp = search_path
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(get_system_path);
    let cache_key = format!("bin:{name}:{sp}");
    let cached = cfg.cached(&cache_key, 30.0, false, || {
        match locate_binary_uncached(name, &sp) {
            Some(p) => Value::String(p),
            None => Value::String(String::new()),
        }
    });
    cached
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn locate_binary_uncached(name: &str, search_path: &str) -> Option<String> {
    let sep = if IS_WINDOWS { ';' } else { ':' };
    let path_obj = Path::new(name);
    if path_obj.is_absolute() || name.contains('/') || name.contains('\\') {
        return is_executable_file(path_obj).then(|| name.to_string());
    }
    let exts: Vec<String> = if IS_WINDOWS {
        let pe = std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD;.PS1".into());
        let mut list = vec![String::new()];
        for ext in pe.split(';') {
            let e = ext.trim();
            if !e.is_empty() {
                list.push(e.to_ascii_lowercase());
            }
        }
        list
    } else {
        vec![String::new()]
    };
    for dir in search_path.split(sep) {
        let d = dir.trim();
        if d.is_empty() {
            continue;
        }
        for ext in &exts {
            let cand_name = if IS_WINDOWS && !ext.is_empty() && !name.to_ascii_lowercase().ends_with(ext) {
                format!("{name}{ext}")
            } else {
                name.to_string()
            };
            let full = Path::new(d).join(&cand_name);
            if is_executable_file(&full) {
                return Some(full.to_string_lossy().into_owned());
            }
        }
    }
    None
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        (meta.permissions().mode() & 0o111) != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[allow(clippy::too_many_arguments)]
pub fn exec_cmd_blocking(
    prog: &str,
    args: &[&str],
    env: &HashMap<String, String>,
    cwd: Option<&Path>,
    timeout_sec: f64,
    input_bytes: Option<&[u8]>,
    uid_gid: Option<(u32, u32)>,
    background: bool,
    discard_output: bool,
) -> (i32, String, String) {
    let mut cmd = Command::new(prog);
    cmd.args(args);
    cmd.env_clear();
    cmd.envs(env);
    if let Some(dir) = cwd {
        if dir.is_dir() {
            cmd.current_dir(dir);
        }
    }
    cmd.stdin(if input_bytes.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    if background || discard_output {
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());
    } else {
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
    }
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    #[cfg(unix)]
    {
        let drop_to = if crate::config::is_root_or_admin() {
            uid_gid.filter(|(u, _)| *u != 0)
        } else {
            None
        };
        unsafe {
            cmd.pre_exec(move || {
                if background {
                    libc::setsid();
                }
                if let Some((u, g)) = drop_to {
                    let _ = libc::setgid(g);
                    let _ = libc::setuid(u);
                }
                Ok(())
            });
        }
    }
    #[cfg(not(unix))]
    let _ = uid_gid;

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return (1, String::new(), e.to_string()),
    };

    if background {
        return (0, String::new(), String::new());
    }

    if let Some(bytes) = input_bytes {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(bytes);
        }
    }

    let out_reader = child.stdout.take().map(|mut p| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = std::io::Read::read_to_end(&mut p, &mut buf);
            String::from_utf8_lossy(&buf).into_owned()
        })
    });
    let err_reader = child.stderr.take().map(|mut p| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = std::io::Read::read_to_end(&mut p, &mut buf);
            String::from_utf8_lossy(&buf).into_owned()
        })
    });

    let deadline = Instant::now() + Duration::from_secs_f64(timeout_sec.max(0.2));
    let mut exit_code: Option<i32> = None;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_code = Some(status.code().unwrap_or(1));
                break;
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }

    let stdout_s = out_reader
        .and_then(|h| h.join().ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let stderr_s = err_reader
        .and_then(|h| h.join().ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    match exit_code {
        Some(rc) => (rc, stdout_s, stderr_s),
        None => (124, stdout_s, "Command timed out".into()),
    }
}

pub fn run_cmd(cmd: &[&str], timeout_sec: f64) -> (i32, String, String) {
    if cmd.is_empty() {
        return (1, String::new(), "Empty command".into());
    }
    let mut env: HashMap<String, String> = std::env::vars().collect();
    if !IS_WINDOWS {
        env.insert("PATH".into(), get_system_path());
    }
    exec_cmd_blocking(
        cmd[0],
        &cmd[1..],
        &env,
        None,
        timeout_sec,
        None,
        None,
        false,
        false,
    )
}

pub fn run_first_system_cmd(
    cfg: &ConfigStore,
    cmds: &[&[&str]],
    timeout_sec: f64,
) -> (i32, String, String) {
    let mut last_err = String::new();
    for cmd in cmds {
        if cmd.is_empty() || find_bin(cfg, cmd[0], None).is_none() {
            continue;
        }
        let (rc, out, err) = run_cmd(cmd, timeout_sec);
        if rc == 0 {
            return (rc, out, err);
        }
        last_err = if !err.is_empty() { err } else { out };
    }
    (1, String::new(), last_err)
}

pub fn win_run_ps(
    cfg: &ConfigStore,
    ps_script: &str,
    timeout_sec: f64,
    extra_env: &[(&str, &str)],
) -> (i32, String, String) {
    platform::win_run_ps(cfg, ps_script, timeout_sec, extra_env)
}

pub fn win_coreaudio_set(cfg: &ConfigStore, pct: i64) -> bool {
    platform::win_coreaudio_set(cfg, pct)
}

pub fn has_internal_backlight() -> bool {
    platform::has_internal_backlight()
}

pub fn get_desktop_env(cfg: &ConfigStore) -> HashMap<String, String> {
    let user = cfg.get_target_user_info();
    let cache_key = format!("desktop_env:{}:{}", user.uid, IS_WINDOWS);
    let val = cfg.cached(&cache_key, 10.0, false, || {
        let map = platform::compute_desktop_env(&user);
        json!(map)
    });
    serde_json::from_value(val).unwrap_or_else(|_| std::env::vars().collect())
}

pub fn get_active_compositor(env: &HashMap<String, String>) -> &'static str {
    if env
        .get("HYPRLAND_INSTANCE_SIGNATURE")
        .map(|s| !s.is_empty())
        .unwrap_or(false)
    {
        return "hyprland";
    }
    if env
        .get("NIRI_SOCKET")
        .map(|s| !s.is_empty() && Path::new(s).exists())
        .unwrap_or(false)
    {
        return "niri";
    }
    if env
        .get("SWAYSOCK")
        .map(|s| !s.is_empty() && Path::new(s).exists())
        .unwrap_or(false)
    {
        return "sway";
    }
    let desktop = env
        .get("XDG_CURRENT_DESKTOP")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    if desktop.contains("niri") {
        return "niri";
    }
    if desktop.contains("hyprland") {
        return "hyprland";
    }
    if desktop.contains("sway") {
        return "sway";
    }
    if desktop.contains("river") {
        return "river";
    }
    if desktop.contains("kde")
        || desktop.contains("plasma")
        || env.get("KDE_FULL_SESSION").map(|s| !s.is_empty()).unwrap_or(false)
    {
        return "kde";
    }
    if desktop.contains("gnome") {
        return "gnome";
    }
    ""
}

pub fn run_as_user(
    cfg: &ConfigStore,
    cmd: &[&str],
    timeout_sec: f64,
    shell_cmd: Option<&str>,
    input_text: Option<&str>,
    background: bool,
    discard_output: bool,
) -> (i32, String, String) {
    let user = cfg.get_target_user_info();
    let env = get_desktop_env(cfg);
    let default_cwd = if IS_WINDOWS {
        std::env::var("SystemDrive").unwrap_or_else(|_| r"C:\".into())
    } else {
        "/".into()
    };
    let cwd_path = if Path::new(&user.home).is_dir() {
        Path::new(&user.home)
    } else {
        Path::new(&default_cwd)
    };
    let stdin_bytes = input_text.map(|s| s.as_bytes());
    if let Some(scmd) = shell_cmd {
        let (prog, args): (&str, Vec<&str>) = if IS_WINDOWS {
            ("cmd.exe", vec!["/C", scmd])
        } else {
            ("/bin/sh", vec!["-c", scmd])
        };
        return exec_cmd_blocking(
            prog,
            &args,
            &env,
            Some(cwd_path),
            timeout_sec,
            stdin_bytes,
            Some((user.uid, user.gid)),
            background,
            discard_output,
        );
    }
    if cmd.is_empty() {
        return (1, String::new(), "Empty command".into());
    }
    exec_cmd_blocking(
        cmd[0],
        &cmd[1..],
        &env,
        Some(cwd_path),
        timeout_sec,
        stdin_bytes,
        Some((user.uid, user.gid)),
        background,
        discard_output,
    )
}

pub fn run_first_available(
    cfg: &ConfigStore,
    variants: &[Vec<String>],
    timeout_sec: f64,
    input_text: Option<&str>,
    background: bool,
    discard_output: bool,
) -> (i32, String, String) {
    let mut last_err = String::new();
    let env = get_desktop_env(cfg);
    let search_path = env.get("PATH").map(String::as_str).unwrap_or("");
    for cmd in variants {
        if cmd.is_empty() || find_bin(cfg, &cmd[0], Some(search_path)).is_none() {
            continue;
        }
        let refs: Vec<&str> = cmd.iter().map(String::as_str).collect();
        let (rc, out, err) = run_as_user(
            cfg,
            &refs,
            timeout_sec,
            None,
            input_text,
            background,
            discard_output,
        );
        let first_line = out
            .trim_start()
            .lines()
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let bad_out = [
            "error:",
            "invalid dispatcher",
            "no such dispatcher",
            "unknown request",
            "couldn't connect",
            "could not connect",
        ]
        .iter()
        .any(|pfx| first_line.starts_with(pfx));
        if rc == 0 && !bad_out {
            return (rc, out, err);
        }
        last_err = if !err.is_empty() {
            err
        } else if !out.is_empty() {
            out
        } else {
            format!("Exit code {rc}")
        };
    }
    (
        1,
        String::new(),
        if last_err.is_empty() {
            "No supported desktop tool succeeded".into()
        } else {
            last_err
        },
    )
}

pub fn url_encode(input: &str, safe: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.as_bytes() {
        let ch = *b as char;
        let is_unreserved = ch.is_ascii_alphanumeric() || "-._~".contains(ch);
        if is_unreserved || (!safe.is_empty() && safe.contains(ch)) {
            out.push(ch);
        } else {
            use std::fmt::Write;
            let _ = write!(&mut out, "%{b:02X}");
        }
    }
    out
}

pub fn get_hostname() -> String {
    #[cfg(unix)]
    unsafe {
        let mut buf = [0 as libc::c_char; 256];
        if libc::gethostname(buf.as_mut_ptr(), buf.len()) == 0 {
            buf[buf.len() - 1] = 0;
            let cstr = std::ffi::CStr::from_ptr(buf.as_ptr());
            let s = cstr.to_string_lossy().into_owned();
            if !s.is_empty() {
                return s;
            }
        }
    }
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .or_else(|_| fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "localhost".into())
}

pub fn os_cpu_count() -> usize {
    thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub fn fmt_size_bytes(nbytes: u64) -> String {
    let f = nbytes as f64;
    if nbytes >= 1u64 << 40 {
        format!("{:.1}T", f / (1u64 << 40) as f64)
    } else if nbytes >= 1u64 << 30 {
        format!("{:.1}G", f / (1u64 << 30) as f64)
    } else if nbytes >= 1u64 << 20 {
        format!("{:.1}M", f / (1u64 << 20) as f64)
    } else {
        format!("{:.0}K", f / 1024.0)
    }
}

#[cfg(any(windows, test))]
pub(crate) fn is_valid_mac(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

#[cfg(any(windows, test))]
pub(crate) fn parse_csv_row(line: &str) -> Vec<String> {
    let mut cols = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' {
            if in_quotes && chars.peek() == Some(&'"') {
                cur.push('"');
                chars.next();
            } else {
                in_quotes = !in_quotes;
            }
        } else if c == ',' && !in_quotes {
            cols.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    cols.push(cur);
    cols
}

pub fn classify_log_level(text: &str) -> &'static str {
    let low = text.to_ascii_lowercase();
    if [
        "critical",
        "crit",
        "fatal",
        "panic",
        "segfault",
        "oom-killer",
        "error",
        "[err]",
        " fail",
        "failed",
    ]
    .iter()
    .any(|k| low.contains(k))
    {
        return "ERROR";
    }
    if ["warn", "warning", "deprecated", "timeout", "retry"]
        .iter()
        .any(|k| low.contains(k))
    {
        return "WARN";
    }
    "INFO"
}

fn level_matches_filter(entry_level: &str, wanted: &str) -> bool {
    let lvl = entry_level.to_ascii_uppercase();
    match wanted {
        "err" => matches!(lvl.as_str(), "ERROR" | "CRIT" | "FATAL"),
        "warn" => matches!(lvl.as_str(), "ERROR" | "CRIT" | "FATAL" | "WARN"),
        _ => true,
    }
}

pub fn parse_log_line(raw_line: &str, source_name: &str) -> Value {
    let mut ts = String::new();
    let trimmed = raw_line.trim();
    let mut msg = trimmed.to_string();

    if trimmed.len() >= 19
        && trimmed.as_bytes()[4] == b'-'
        && trimmed.as_bytes()[7] == b'-'
        && (trimmed.as_bytes()[10] == b'T' || trimmed.as_bytes()[10] == b' ')
        && trimmed.as_bytes()[13] == b':'
        && trimmed.as_bytes()[16] == b':'
    {
        if let Some((head, tail)) = trimmed.split_once(char::is_whitespace) {
            ts = head.to_string();
            msg = tail.trim_start().to_string();
        }
    } else if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some((inside, tail)) = rest.split_once(']') {
            ts = inside.trim().to_string();
            msg = tail.trim_start().to_string();
        }
    } else if let Some((ts_part, rest)) = split_syslog_ts(trimmed) {
        ts = ts_part;
        msg = rest;
    }

    let msg_trunc: String = msg.chars().take(1200).collect();
    json!({
        "ts": ts,
        "source": source_name,
        "level": classify_log_level(raw_line),
        "message": msg_trunc,
    })
}

fn split_syslog_ts(line: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 4
        && parts[0].len() == 3
        && parts[0].as_bytes()[0].is_ascii_uppercase()
        && parts[1].chars().all(|c| c.is_ascii_digit())
        && parts[2].len() == 8
        && parts[2].as_bytes().get(2) == Some(&b':')
        && parts[2].as_bytes().get(5) == Some(&b':')
    {
        let ts = format!("{} {} {}", parts[0], parts[1], parts[2]);
        let msg = parts[3..].join(" ");
        return Some((ts, msg));
    }
    None
}

#[allow(dead_code)]
pub fn tcp_probe(addr: &str, timeout_ms: u64) -> bool {
    addr.to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
        .map(|sa| TcpStream::connect_timeout(&sa, Duration::from_millis(timeout_ms)).is_ok())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_classification_and_parsing() {
        assert_eq!(classify_log_level("kernel panic occurred"), "ERROR");
        assert_eq!(classify_log_level("retrying connection timeout"), "WARN");
        assert_eq!(classify_log_level("daemon started normally"), "INFO");

        let parsed_dmesg = parse_log_line("[   12.3456] usbcore: registered interface", "dmesg");
        assert_eq!(parsed_dmesg["ts"], "12.3456");
        assert_eq!(parsed_dmesg["source"], "dmesg");

        let parsed_iso = parse_log_line(
            "2026-11-15T01:00:00+0700 host systemd[1]: Failed to start foo",
            "journal",
        );
        assert_eq!(parsed_iso["level"], "ERROR");
        assert!(parsed_iso["ts"].as_str().unwrap().starts_with("2026-11-15"));
    }

    #[test]
    fn test_fmt_size_bytes() {
        assert_eq!(fmt_size_bytes(512 * 1024), "512K");
        assert_eq!(fmt_size_bytes(2 * 1024 * 1024 * 1024), "2.0G");
    }

    #[test]
    fn test_merge_path_dirs_dedup() {
        let sep = if IS_WINDOWS { ";" } else { ":" };
        let g1 = format!("/a{sep}/b");
        let g2 = format!("/b{sep}/c{sep}/a");
        let merged = merge_path_dirs(&[&g1, &g2]);
        assert_eq!(merged, format!("/a{sep}/b{sep}/c"));
    }

    #[test]
    fn test_windows_parsing_helpers() {
        assert!(is_valid_mac("00:11:22:aa:BB:cc"));
        assert!(!is_valid_mac("00:11:22:aa:BB"));
        assert_eq!(
            parse_csv_row(r#""Node ""1""",aa:bb:cc:dd:ee:ff,Up"#),
            vec!["Node \"1\"", "aa:bb:cc:dd:ee:ff", "Up"]
        );
    }
}

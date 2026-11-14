//! Cross-platform system telemetry, command execution helpers, logs, services, and OS inventory.

#[cfg(unix)]
use crate::config::is_root_or_admin;
use crate::config::{local_datetime_string, ConfigStore, TargetUserInfo};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

#[cfg(windows)]
use std::os::windows::process::CommandExt as WinCommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub const IS_WINDOWS: bool = cfg!(windows);

#[derive(Default)]
struct DistroCacheSlot {
    ts: f64,
    payload: Value,
}

pub struct TelemetryState {
    last_cpu: Mutex<Option<(u64, u64)>>,
    net_last: Mutex<Option<(Instant, u64, u64)>>,
    proc_last: Mutex<Option<(u64, HashMap<i32, u64>)>>,
    distro_scan_lock: Mutex<()>,
    distro_cache: Mutex<HashMap<&'static str, DistroCacheSlot>>,
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
}

/// Merge PATH components while preserving priority order and deduplicating entries.
pub fn merge_path_dirs(groups: &[&str]) -> String {
    let sep = if IS_WINDOWS { ';' } else { ':' };
    let mut parts: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for group in groups {
        for raw in group.split(sep) {
            let entry = raw.trim();
            if !entry.is_empty() && seen.insert(entry.to_string()) {
                parts.push(entry.to_string());
            }
        }
    }
    let sep_str = if IS_WINDOWS { ";" } else { ":" };
    parts.join(sep_str)
}

/// Return expanded system PATH covering Windows System32/OpenSSH or FHS/NixOS wrappers.
pub fn get_system_path() -> String {
    let cur = std::env::var("PATH").unwrap_or_default();
    if IS_WINDOWS {
        let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let win_dirs = format!(
            "{sys_root}\\System32;{sys_root};{sys_root}\\System32\\Wbem;{sys_root}\\System32\\WindowsPowerShell\\v1.0;{sys_root}\\System32\\OpenSSH"
        );
        return merge_path_dirs(&[&cur, &win_dirs]);
    }
    merge_path_dirs(&[
        &cur,
        "/run/wrappers/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    ])
}

/// Locate an executable inside an explicit or default system PATH (cached 30s).
pub fn find_bin(cfg: &ConfigStore, name: &str, search_path: Option<&str>) -> Option<String> {
    let fallback = get_system_path();
    let eff = search_path.unwrap_or(&fallback);
    let key = format!("find_bin:{name}:{eff}");
    let name_owned = name.to_string();
    let eff_owned = eff.to_string();
    let v = cfg.cached(&key, 30.0, false, || {
        match locate_binary_uncached(&name_owned, &eff_owned) {
            Some(p) => Value::String(p),
            None => Value::Null,
        }
    });
    v.as_str().map(str::to_string)
}

fn locate_binary_uncached(name: &str, search_path: &str) -> Option<String> {
    let sep = if IS_WINDOWS { ';' } else { ':' };
    let direct = Path::new(name);
    if direct.components().count() > 1 || direct.is_absolute() {
        return is_executable_file(direct).then(|| direct.to_string_lossy().into_owned());
    }
    let exts: Vec<String> = if IS_WINDOWS {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into())
            .split(';')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        vec![String::new()]
    };
    for dir in search_path.split(sep) {
        let trimmed = dir.trim();
        if trimmed.is_empty() {
            continue;
        }
        let base = Path::new(trimmed).join(name);
        if is_executable_file(&base) {
            return Some(base.to_string_lossy().into_owned());
        }
        if IS_WINDOWS {
            for ext in &exts {
                let with_ext = Path::new(trimmed).join(format!("{name}{ext}"));
                if is_executable_file(&with_ext) {
                    return Some(with_ext.to_string_lossy().into_owned());
                }
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
        use std::os::unix::fs::PermissionsExt;
        (meta.permissions().mode() & 0o111) != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Core blocking subprocess runner supporting timeout, optional stdin, privilege drop, and background mode.
#[allow(clippy::too_many_arguments)]
pub fn exec_cmd_blocking(
    program: &str,
    args: &[&str],
    env_map: &HashMap<String, String>,
    cwd: Option<&Path>,
    timeout_sec: f64,
    stdin_bytes: Option<&[u8]>,
    drop_to_user: Option<(u32, u32)>,
    background: bool,
    discard_output: bool,
) -> (i32, String, String) {
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.env_clear();
    cmd.envs(env_map);
    if let Some(dir) = cwd {
        if dir.is_dir() {
            cmd.current_dir(dir);
        }
    }

    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    #[cfg(unix)]
    {
        let drop_pair = if is_root_or_admin() {
            drop_to_user.filter(|&(u, _)| u != 0)
        } else {
            None
        };
        if drop_pair.is_some() || background {
            unsafe {
                cmd.pre_exec(move || {
                    if background {
                        libc::setsid();
                    }
                    if let Some((uid, gid)) = drop_pair {
                        if libc::setgid(gid as libc::gid_t) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        if libc::setuid(uid as libc::uid_t) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }
                    Ok(())
                });
            }
        }
    }

    if background {
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        return match cmd.spawn() {
            Ok(mut child) => {
                thread::spawn(move || {
                    let _ = child.wait();
                });
                (0, String::new(), String::new())
            }
            Err(e) => (1, String::new(), e.to_string()),
        };
    }

    cmd.stdin(if stdin_bytes.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    if discard_output {
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
    } else {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return (1, String::new(), e.to_string()),
    };

    if let Some(bytes) = stdin_bytes {
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let _ = stdin.write_all(bytes);
        }
    }

    let out_handle = child.stdout.take().map(|mut s| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
            buf
        })
    });
    let err_handle = child.stderr.take().map(|mut s| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
            buf
        })
    });

    let deadline = Instant::now() + Duration::from_secs_f64(timeout_sec.max(0.1));
    let mut exit_code = 1;
    let mut timed_out = false;

    loop {
        match child.try_wait() {
            Ok(Some(st)) => {
                exit_code = st.code().unwrap_or(1);
                break;
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    timed_out = true;
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }

    let stdout = out_handle
        .and_then(|h| h.join().ok())
        .map(|b| String::from_utf8_lossy(&b).trim().to_string())
        .unwrap_or_default();
    let stderr = if timed_out {
        format!("Command timed out after {timeout_sec}s")
    } else {
        err_handle
            .and_then(|h| h.join().ok())
            .map(|b| String::from_utf8_lossy(&b).trim().to_string())
            .unwrap_or_default()
    };

    (exit_code, stdout, stderr)
}

/// Run a system command with expanded system PATH and C locale.
pub fn run_cmd(cmd: &[&str], timeout_sec: f64) -> (i32, String, String) {
    if cmd.is_empty() {
        return (1, String::new(), "Empty command".into());
    }
    let mut env: HashMap<String, String> = std::env::vars().collect();
    env.insert("PATH".into(), get_system_path());
    if !IS_WINDOWS {
        env.insert("LC_ALL".into(), "C".into());
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
    variants: &[&[&str]],
    timeout_sec: f64,
) -> (i32, String, String) {
    let sys_path = get_system_path();
    for cmd in variants {
        if cmd.is_empty() || find_bin(cfg, cmd[0], Some(&sys_path)).is_none() {
            continue;
        }
        let (rc, out, err) = run_cmd(cmd, timeout_sec);
        if rc == 0 {
            return (rc, out, err);
        }
    }
    (1, String::new(), "No supported system utility found".into())
}

#[cfg(windows)]
pub fn win_run_ps(
    cfg: &ConfigStore,
    ps_script: &str,
    timeout_sec: f64,
    extra_env: &[(&str, &str)],
) -> (i32, String, String) {
    let ps_bin = find_bin(cfg, "powershell", None).unwrap_or_else(|| "powershell".into());
    let mut env: HashMap<String, String> = std::env::vars().collect();
    env.insert("PATH".into(), get_system_path());
    for (k, v) in extra_env {
        env.insert((*k).to_string(), (*v).to_string());
    }
    exec_cmd_blocking(
        &ps_bin,
        &[
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            ps_script,
        ],
        &env,
        None,
        timeout_sec,
        None,
        None,
        false,
        false,
    )
}

#[cfg(not(windows))]
pub fn win_run_ps(
    _cfg: &ConfigStore,
    _ps_script: &str,
    _timeout_sec: f64,
    _extra_env: &[(&str, &str)],
) -> (i32, String, String) {
    (1, String::new(), "Windows-only".into())
}

/// Inspect active processes strictly owned by the target user to reconstruct GUI session env (cached 12s).
pub fn get_desktop_env(cfg: &ConfigStore) -> HashMap<String, String> {
    let user = cfg.get_target_user_info();
    let cache_key = format!("desktop_env:{}:{}", user.uid, IS_WINDOWS);
    let cached = cfg.cached(&cache_key, 12.0, false, || {
        let map = compute_desktop_env(&user);
        serde_json::to_value(map).unwrap_or(Value::Object(Map::new()))
    });
    serde_json::from_value(cached).unwrap_or_default()
}

fn compute_desktop_env(user: &TargetUserInfo) -> HashMap<String, String> {
    if IS_WINDOWS {
        let mut env: HashMap<String, String> = std::env::vars().collect();
        env.entry("USERPROFILE".into()).or_insert_with(|| user.home.clone());
        env.entry("HOME".into()).or_insert_with(|| user.home.clone());
        env.entry("USERNAME".into())
            .or_insert_with(|| user.username.clone());
        env.insert("PATH".into(), get_system_path());
        return env;
    }

    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut session_path = String::new();
    let mut env = HashMap::new();
    env.insert("HOME".into(), user.home.clone());
    env.insert("USER".into(), user.username.clone());
    env.insert("LOGNAME".into(), user.username.clone());
    env.insert("LC_ALL".into(), "C".into());

    const GRAB_KEYS: &[&str] = &[
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "HYPRLAND_INSTANCE_SIGNATURE",
        "NIRI_SOCKET",
        "SWAYSOCK",
        "XDG_CURRENT_DESKTOP",
        "XDG_SESSION_TYPE",
        "KDE_FULL_SESSION",
        "QT_QPA_PLATFORM",
        "PATH",
    ];

    #[cfg(unix)]
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            if !name.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let proc_dir = entry.path();
            let Ok(meta) = fs::metadata(&proc_dir) else {
                continue;
            };
            if meta.uid() != user.uid {
                continue;
            }
            let Ok(raw) = fs::read(proc_dir.join("environ")) else {
                continue;
            };
            for item in raw.split(|&b| b == 0) {
                let s = String::from_utf8_lossy(item);
                let Some((k, v)) = s.split_once('=') else {
                    continue;
                };
                if v.is_empty() || !GRAB_KEYS.contains(&k) {
                    continue;
                }
                if k == "PATH" {
                    session_path = merge_path_dirs(&[&session_path, v]);
                } else {
                    env.entry(k.to_string()).or_insert_with(|| v.to_string());
                }
            }
        }
    }

    let nix_paths = format!(
        "/run/wrappers/bin:/etc/profiles/per-user/{}/bin:{}/.nix-profile/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin",
        user.username, user.home
    );
    let proc_path = std::env::var("PATH").unwrap_or_default();
    let fallback_paths = format!(
        "{}/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        user.home
    );
    env.insert(
        "PATH".into(),
        merge_path_dirs(&[&session_path, &nix_paths, &proc_path, &fallback_paths]),
    );

    let runtime_dir = env
        .get("XDG_RUNTIME_DIR")
        .cloned()
        .unwrap_or_else(|| format!("/run/user/{}", user.uid));
    if Path::new(&runtime_dir).is_dir() {
        env.entry("XDG_RUNTIME_DIR".into())
            .or_insert_with(|| runtime_dir.clone());
        let bus_sock = Path::new(&runtime_dir).join("bus");
        if bus_sock.exists() {
            env.entry("DBUS_SESSION_BUS_ADDRESS".into())
                .or_insert_with(|| format!("unix:path={}", bus_sock.display()));
        }
        let mut runtime_entries: Vec<String> = fs::read_dir(&runtime_dir)
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        runtime_entries.sort();

        if !env.contains_key("WAYLAND_DISPLAY") {
            if let Some(wl) = runtime_entries
                .iter()
                .find(|n| n.starts_with("wayland-") && !n.ends_with(".lock"))
            {
                env.insert("WAYLAND_DISPLAY".into(), wl.clone());
            }
        }
        let niri_valid = env
            .get("NIRI_SOCKET")
            .map(|p| Path::new(p).exists())
            .unwrap_or(false);
        if !niri_valid {
            if let Some(niri) = runtime_entries
                .iter()
                .rev()
                .find(|n| n.starts_with("niri.") && n.ends_with(".sock"))
            {
                let cand = Path::new(&runtime_dir).join(niri);
                if cand.exists() {
                    env.insert("NIRI_SOCKET".into(), cand.to_string_lossy().into_owned());
                }
            }
        }
        let sway_valid = env
            .get("SWAYSOCK")
            .map(|p| Path::new(p).exists())
            .unwrap_or(false);
        if !sway_valid {
            if let Some(sway) = runtime_entries
                .iter()
                .rev()
                .find(|n| n.starts_with("sway-ipc.") && n.ends_with(".sock"))
            {
                let cand = Path::new(&runtime_dir).join(sway);
                if cand.exists() {
                    env.insert("SWAYSOCK".into(), cand.to_string_lossy().into_owned());
                }
            }
        }
        let hypr_dir = Path::new(&runtime_dir).join("hypr");
        let cur_his = env
            .get("HYPRLAND_INSTANCE_SIGNATURE")
            .cloned()
            .unwrap_or_default();
        let his_valid =
            !cur_his.is_empty() && hypr_dir.join(&cur_his).join(".socket.sock").exists();
        if hypr_dir.is_dir() && !his_valid {
            if let Ok(rd) = fs::read_dir(&hypr_dir) {
                let mut sigs: Vec<String> = rd
                    .flatten()
                    .filter_map(|e| e.file_name().into_string().ok())
                    .collect();
                sigs.sort_by(|a, b| b.cmp(a));
                for sig in sigs {
                    if hypr_dir.join(&sig).join(".socket.sock").exists() {
                        env.insert("HYPRLAND_INSTANCE_SIGNATURE".into(), sig);
                        break;
                    }
                }
            }
        }
    }
    env.entry("DISPLAY".into()).or_insert_with(|| ":0".into());
    env
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

/// Execute a command as the target desktop user with reconstructed GUI session environment.
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

/// Run the first available desktop command variant whose binary exists in session PATH.
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

/// Percent-encode a string for URLs / query parameters.
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

#[cfg(windows)]
mod win_ffi {
    #[repr(C)]
    pub struct FileTime {
        pub dw_low_date_time: u32,
        pub dw_high_date_time: u32,
    }
    impl FileTime {
        pub fn to_u64(&self) -> u64 {
            ((self.dw_high_date_time as u64) << 32) | (self.dw_low_date_time as u64)
        }
    }
    #[repr(C)]
    pub struct MemoryStatusEx {
        pub dw_length: u32,
        pub dw_memory_load: u32,
        pub ull_total_phys: u64,
        pub ull_avail_phys: u64,
        pub ull_total_page_file: u64,
        pub ull_avail_page_file: u64,
        pub ull_total_virtual: u64,
        pub ull_avail_virtual: u64,
        pub ull_avail_ext_virtual: u64,
    }
    #[repr(C)]
    pub struct SystemPowerStatus {
        pub ac_line_status: u8,
        pub battery_flag: u8,
        pub battery_life_percent: u8,
        pub system_status_flag: u8,
        pub battery_life_time: u32,
        pub battery_full_life_time: u32,
    }
    #[link(name = "kernel32")]
    extern "system" {
        pub fn GetSystemTimes(
            idle: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
        pub fn GlobalMemoryStatusEx(lp: *mut MemoryStatusEx) -> i32;
        pub fn GetSystemPowerStatus(lp: *mut SystemPowerStatus) -> i32;
        pub fn GetTickCount64() -> u64;
        pub fn GetLogicalDrives() -> u32;
        pub fn GetDriveTypeW(lp_root_path_name: *const u16) -> u32;
        pub fn GetDiskFreeSpaceExW(
            lp_directory_name: *const u16,
            lp_free_bytes_available: *mut u64,
            lp_total_number_of_bytes: *mut u64,
            lp_total_number_of_free_bytes: *mut u64,
        ) -> i32;
    }
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

impl TelemetryState {
    pub fn get_cpu_percent(&self) -> f64 {
        #[cfg(windows)]
        {
            unsafe {
                let mut idle: win_ffi::FileTime = std::mem::zeroed();
                let mut kern: win_ffi::FileTime = std::mem::zeroed();
                let mut usr: win_ffi::FileTime = std::mem::zeroed();
                if win_ffi::GetSystemTimes(&mut idle, &mut kern, &mut usr) == 0 {
                    return 0.0;
                }
                let idle_v = idle.to_u64();
                let total_v = kern.to_u64() + usr.to_u64();
                let mut guard = self.last_cpu.lock().unwrap();
                let Some((pi, pt)) = *guard else {
                    *guard = Some((idle_v, total_v));
                    return 0.0;
                };
                *guard = Some((idle_v, total_v));
                let dt = total_v.saturating_sub(pt);
                let di = idle_v.saturating_sub(pi);
                if dt == 0 {
                    return 0.0;
                }
                return round1((100.0 * (1.0 - (di as f64 / dt as f64))).clamp(0.0, 100.0));
            }
        }
        #[cfg(not(windows))]
        {
            let Ok(raw) = fs::read_to_string("/proc/stat") else {
                return 0.0;
            };
            let Some(first) = raw.lines().next() else {
                return 0.0;
            };
            let vals: Vec<u64> = first
                .split_whitespace()
                .skip(1)
                .take(7)
                .filter_map(|x| x.parse::<u64>().ok())
                .collect();
            if vals.len() < 5 {
                return 0.0;
            }
            let idle = vals[3] + vals[4];
            let total: u64 = vals.iter().sum();
            let mut guard = self.last_cpu.lock().unwrap();
            let Some((pi, pt)) = *guard else {
                *guard = Some((idle, total));
                return 0.0;
            };
            *guard = Some((idle, total));
            let dt = total.saturating_sub(pt);
            let di = idle.saturating_sub(pi);
            if dt == 0 {
                return 0.0;
            }
            round1(100.0 * (1.0 - (di as f64 / dt as f64)))
        }
    }

    pub fn get_cpu_temp(&self, cfg: &ConfigStore) -> f64 {
        if IS_WINDOWS {
            let v = cfg.cached("win_cpu_temp", 8.0, false, || {
                let (rc, out, _) = win_run_ps(
                    cfg,
                    "try { $t = Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop | Measure-Object -Property CurrentTemperature -Maximum; if ($t.Maximum -gt 2000) { [math]::Round(($t.Maximum / 10.0) - 273.15, 1) } else { 0 } } catch { 0 }",
                    4.0,
                    &[],
                );
                if rc == 0 {
                    if let Ok(val) = out.lines().last().unwrap_or("").trim().parse::<f64>() {
                        if (5.0..130.0).contains(&val) {
                            return json!(round1(val));
                        }
                    }
                }
                json!(0.0)
            });
            return v.as_f64().unwrap_or(0.0);
        }

        let mut temps = collect_hwmon_temps(&["k10temp", "coretemp", "zenpower", "cpu", "acpitz", "thinkpad"]);
        if temps.is_empty() {
            temps = collect_hwmon_temps(&["asus-ec-sensors", "nct67", "it87", "gigabyte", "msi-ec"]);
        }
        if temps.is_empty() {
            if let Ok(entries) = fs::read_dir("/sys/class/thermal") {
                for entry in entries.flatten() {
                    if let Some(name) = entry.file_name().to_str() {
                        if name.starts_with("thermal_zone") {
                            if let Ok(s) = fs::read_to_string(entry.path().join("temp")) {
                                if let Ok(v) = s.trim().parse::<i64>() {
                                    if (5000..130000).contains(&v) {
                                        temps.push(v as f64 / 1000.0);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        temps
            .into_iter()
            .fold(None, |acc: Option<f64>, t| Some(acc.map_or(t, |m| m.max(t))))
            .map(round1)
            .unwrap_or(0.0)
    }

    pub fn get_gpu_info(&self, cfg: &ConfigStore) -> Value {
        cfg.cached("gpu_info", 5.0, false, || compute_gpu_info(cfg))
    }

    pub fn get_memory_info(&self) -> Value {
        #[cfg(windows)]
        unsafe {
            let mut st: win_ffi::MemoryStatusEx = std::mem::zeroed();
            st.dw_length = std::mem::size_of::<win_ffi::MemoryStatusEx>() as u32;
            if win_ffi::GlobalMemoryStatusEx(&mut st) == 0 {
                return json!({"total_gb": 0.0, "used_gb": 0.0, "percent": 0.0});
            }
            let total = st.ull_total_phys;
            let used = total.saturating_sub(st.ull_avail_phys);
            let pct = if total > 0 {
                round1((used as f64 / total as f64) * 100.0)
            } else {
                0.0
            };
            let gib = 1024.0 * 1024.0 * 1024.0;
            return json!({
                "total_gb": round1(total as f64 / gib),
                "used_gb": round1(used as f64 / gib),
                "percent": pct,
            });
        }
        #[cfg(not(windows))]
        {
            let Ok(raw) = fs::read_to_string("/proc/meminfo") else {
                return json!({"total_gb": 0.0, "used_gb": 0.0, "percent": 0.0});
            };
            let mut total = 0u64;
            let mut avail = None;
            let mut free = 0u64;
            for line in raw.lines() {
                let Some((k, v)) = line.split_once(':') else {
                    continue;
                };
                let kb = v
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                match k.trim() {
                    "MemTotal" => total = kb * 1024,
                    "MemAvailable" => avail = Some(kb * 1024),
                    "MemFree" => free = kb * 1024,
                    _ => {}
                }
            }
            let avail_bytes = avail.unwrap_or(free);
            let used = total.saturating_sub(avail_bytes);
            let pct = if total > 0 {
                round1((used as f64 / total as f64) * 100.0)
            } else {
                0.0
            };
            let gib = 1024.0 * 1024.0 * 1024.0;
            json!({
                "total_gb": round1(total as f64 / gib),
                "used_gb": round1(used as f64 / gib),
                "percent": pct,
            })
        }
    }

    pub fn get_swap_info(&self) -> Value {
        #[cfg(windows)]
        unsafe {
            let mut st: win_ffi::MemoryStatusEx = std::mem::zeroed();
            st.dw_length = std::mem::size_of::<win_ffi::MemoryStatusEx>() as u32;
            if win_ffi::GlobalMemoryStatusEx(&mut st) == 0 {
                return json!({"total_gb": 0.0, "used_gb": 0.0, "percent": 0.0});
            }
            let page_total = st.ull_total_page_file.saturating_sub(st.ull_total_phys);
            if page_total == 0 {
                return json!({"total_gb": 0.0, "used_gb": 0.0, "percent": 0.0});
            }
            let ram_used = st.ull_total_phys.saturating_sub(st.ull_avail_phys);
            let commit_used = st.ull_total_page_file.saturating_sub(st.ull_avail_page_file);
            let page_used = commit_used.saturating_sub(ram_used).min(page_total);
            let pct = round1((page_used as f64 / page_total as f64) * 100.0);
            let gib = 1024.0 * 1024.0 * 1024.0;
            return json!({
                "total_gb": round1(page_total as f64 / gib),
                "used_gb": round1(page_used as f64 / gib),
                "percent": pct,
            });
        }
        #[cfg(not(windows))]
        {
            let Ok(raw) = fs::read_to_string("/proc/meminfo") else {
                return json!({"total_gb": 0.0, "used_gb": 0.0, "percent": 0.0});
            };
            let mut total = 0u64;
            let mut free = 0u64;
            for line in raw.lines() {
                if let Some((k, v)) = line.split_once(':') {
                    let kb = v
                        .split_whitespace()
                        .next()
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(0);
                    match k.trim() {
                        "SwapTotal" => total = kb * 1024,
                        "SwapFree" => free = kb * 1024,
                        _ => {}
                    }
                }
            }
            let used = total.saturating_sub(free);
            let pct = if total > 0 {
                round1((used as f64 / total as f64) * 100.0)
            } else {
                0.0
            };
            let gib = 1024.0 * 1024.0 * 1024.0;
            json!({
                "total_gb": round1(total as f64 / gib),
                "used_gb": round1(used as f64 / gib),
                "percent": pct,
            })
        }
    }

    pub fn get_battery_info(&self) -> Value {
        #[cfg(windows)]
        unsafe {
            let mut sps: win_ffi::SystemPowerStatus = std::mem::zeroed();
            if win_ffi::GetSystemPowerStatus(&mut sps) != 0 {
                if (sps.battery_flag & 128) != 0 || sps.battery_life_percent == 255 {
                    return json!({"has_battery": false, "has_ups": false, "percent": Value::Null, "status": "AC Desktop", "plugged": true});
                }
                let pct = (sps.battery_life_percent as i64).clamp(0, 100);
                let plugged = sps.ac_line_status == 1;
                return json!({
                    "has_battery": true,
                    "has_ups": false,
                    "percent": pct,
                    "status": if plugged { "Charging" } else { "Discharging" },
                    "plugged": plugged,
                });
            }
            return json!({"has_battery": false, "has_ups": false, "percent": Value::Null, "status": "AC Desktop", "plugged": true});
        }
        #[cfg(not(windows))]
        {
            let ps_dir = Path::new("/sys/class/power_supply");
            if let Ok(rd) = fs::read_dir(ps_dir) {
                let mut devs: Vec<String> = rd
                    .flatten()
                    .filter_map(|e| e.file_name().into_string().ok())
                    .collect();
                devs.sort();
                for dev in &devs {
                    if dev.starts_with("BAT") {
                        let base = ps_dir.join(dev);
                        if let Ok(cap_s) = fs::read_to_string(base.join("capacity")) {
                            if let Ok(cap) = cap_s.trim().parse::<i64>() {
                                let status = fs::read_to_string(base.join("status"))
                                    .map(|s| s.trim().to_string())
                                    .unwrap_or_else(|_| "Unknown".into());
                                let plugged = matches!(
                                    status.to_ascii_lowercase().as_str(),
                                    "charging" | "full" | "not charging"
                                );
                                return json!({
                                    "has_battery": true,
                                    "has_ups": false,
                                    "percent": cap,
                                    "status": status,
                                    "plugged": plugged,
                                });
                            }
                        }
                    }
                }
                for dev in &devs {
                    let base = ps_dir.join(dev);
                    if let (Ok(tp), Ok(cap_s)) = (
                        fs::read_to_string(base.join("type")),
                        fs::read_to_string(base.join("capacity")),
                    ) {
                        if tp.trim().eq_ignore_ascii_case("ups") {
                            if let Ok(cap) = cap_s.trim().parse::<i64>() {
                                return json!({
                                    "has_battery": false,
                                    "has_ups": true,
                                    "percent": cap,
                                    "status": "UPS Backup",
                                    "plugged": true,
                                });
                            }
                        }
                    }
                }
            }
            json!({"has_battery": false, "has_ups": false, "percent": Value::Null, "status": "AC Desktop", "plugged": true})
        }
    }

    pub fn get_mac_addresses(&self, cfg: &ConfigStore) -> Vec<Value> {
        let v = cfg.cached("mac_addresses", 30.0, false, || {
            Value::Array(compute_mac_addresses(cfg))
        });
        v.as_array().cloned().unwrap_or_default()
    }

    pub fn get_network_telemetry(&self, cfg: &ConfigStore) -> Value {
        let (rx_total, tx_total) = if IS_WINDOWS {
            let v = cfg.cached("win_net_bytes", 2.5, false, || {
                let (rc, out, _) = win_run_ps(
                    cfg,
                    "$rx=0L; $tx=0L; [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object { $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback' } | ForEach-Object { try { $s=$_.GetIPStatistics(); $rx+=$s.BytesReceived; $tx+=$s.BytesSent } catch {} }; \"$rx $tx\"",
                    4.0,
                    &[],
                );
                if rc == 0 {
                    if let Some(last) = out.lines().last() {
                        let p: Vec<&str> = last.split_whitespace().collect();
                        if p.len() == 2 {
                            if let (Ok(rx), Ok(tx)) = (p[0].parse::<u64>(), p[1].parse::<u64>()) {
                                return json!([rx, tx]);
                            }
                        }
                    }
                }
                json!([0, 0])
            });
            let rx = v.get(0).and_then(|x| x.as_u64()).unwrap_or(0);
            let tx = v.get(1).and_then(|x| x.as_u64()).unwrap_or(0);
            (rx, tx)
        } else {
            let mut rx = 0u64;
            let mut tx = 0u64;
            if let Ok(raw) = fs::read_to_string("/proc/net/dev") {
                for line in raw.lines().skip(2) {
                    let Some((iface, rest)) = line.split_once(':') else {
                        continue;
                    };
                    if iface.trim() == "lo" {
                        continue;
                    }
                    let cols: Vec<&str> = rest.split_whitespace().collect();
                    if cols.len() >= 9 {
                        rx += cols[0].parse::<u64>().unwrap_or(0);
                        tx += cols[8].parse::<u64>().unwrap_or(0);
                    }
                }
            }
            (rx, tx)
        };

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
        let mut base = cfg.cached("os_static", 3600.0, false, compute_os_static);
        #[cfg(windows)]
        let uptime_str = unsafe {
            let sec = win_ffi::GetTickCount64() / 1000;
            let (h, m) = (sec / 3600, (sec % 3600) / 60);
            if h > 0 { format!("{h}h {m}m") } else { format!("{m}m") }
        };
        #[cfg(not(windows))]
        let uptime_str = fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|raw| {
                raw.split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<f64>().ok())
            })
            .map(|sec_f| {
                let sec = sec_f as u64;
                let (h, m) = (sec / 3600, (sec % 3600) / 60);
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
            Value::String(compute_init_system(cfg))
        });
        v.as_str().unwrap_or("unknown").to_string()
    }

    pub fn get_media_and_display(&self, cfg: &ConfigStore) -> Value {
        cfg.cached("media_display", 3.0, false, || compute_media_and_display(cfg))
    }

    pub fn get_workspaces_info(&self, cfg: &ConfigStore) -> Value {
        let river_tag = self.last_river_tag.load(Ordering::Relaxed);
        cfg.cached("workspaces_info", 2.5, false, || {
            Value::Array(compute_workspaces_info(cfg, river_tag))
        })
    }

    pub fn get_disks_info(&self, cfg: &ConfigStore, refresh: bool) -> Value {
        cfg.cached("disks_info", 20.0, refresh, || {
            Value::Array(compute_disks_info())
        })
    }

    pub fn get_boot_entries(&self, cfg: &ConfigStore, refresh: bool) -> Value {
        cfg.cached("boot_entries", 300.0, refresh, || {
            Value::Array(compute_boot_entries(cfg))
        })
    }

    pub fn get_local_ips(&self, cfg: &ConfigStore) -> Vec<String> {
        let v = cfg.cached("local_ips", 15.0, false, || {
            Value::Array(
                compute_local_ips(cfg)
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            )
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
        cfg.cached("services_info", 4.0, false, || compute_services_info(cfg, self))
    }

    pub fn get_processes_info(&self, limit: usize) -> Value {
        let cap = limit.clamp(5, 60);
        if IS_WINDOWS {
            let mut items: Vec<(f64, Value)> = Vec::new();
            let (rc, out, _) = run_cmd(&["tasklist", "/FO", "CSV", "/NH"], 6.0);
            if rc == 0 {
                for line in out.lines() {
                    let cols = parse_csv_row(line);
                    if cols.len() < 5 {
                        continue;
                    }
                    let name = cols[0].trim();
                    let Ok(pid) = cols[1].trim().parse::<i32>() else {
                        continue;
                    };
                    let mem_digits: String =
                        cols[4].chars().filter(|c| c.is_ascii_digit()).collect();
                    let rss_mb = mem_digits
                        .parse::<f64>()
                        .map(|kb| round1(kb / 1024.0))
                        .unwrap_or(0.0);
                    let short_name: String = name.chars().take(32).collect();
                    let short_cmd: String = name.chars().take(96).collect();
                    items.push((
                        rss_mb,
                        json!({
                            "pid": pid,
                            "name": short_name,
                            "cmd": short_cmd,
                            "state": "R",
                            "cpu_pct": 0.0,
                            "rss_mb": rss_mb,
                        }),
                    ));
                }
            }
            items.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
            let total = items.len();
            let processes: Vec<Value> = items.into_iter().take(cap).map(|x| x.1).collect();
            return json!({"processes": processes, "total": total});
        }

        let total_ticks: u64 = fs::read_to_string("/proc/stat")
            .ok()
            .and_then(|s| {
                s.lines().next().map(|l| {
                    l.split_whitespace()
                        .skip(1)
                        .take(7)
                        .filter_map(|x| x.parse::<u64>().ok())
                        .sum()
                })
            })
            .unwrap_or(0);

        let (prev_total, prev_procs) = {
            let guard = self.proc_last.lock().unwrap();
            guard.clone().unwrap_or((0, HashMap::new()))
        };
        let dt_ticks = if prev_total > 0 && total_ticks > prev_total {
            total_ticks - prev_total
        } else {
            0
        };
        let ncpus = os_cpu_count() as f64;
        let page_size = unix_page_size();
        let mut cur_procs = HashMap::new();
        let mut items: Vec<(f64, f64, Value)> = Vec::new();

        if let Ok(rd) = fs::read_dir("/proc") {
            for entry in rd.flatten() {
                let Ok(pid_str) = entry.file_name().into_string() else {
                    continue;
                };
                if !pid_str.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                let Ok(pid) = pid_str.parse::<i32>() else {
                    continue;
                };
                let Ok(stat_raw) = fs::read_to_string(entry.path().join("stat")) else {
                    continue;
                };
                let (Some(lp), Some(rp)) = (stat_raw.find('('), stat_raw.rfind(')')) else {
                    continue;
                };
                if rp <= lp {
                    continue;
                }
                let comm = &stat_raw[lp + 1..rp];
                let rest: Vec<&str> = stat_raw[rp + 2..].split_whitespace().collect();
                if rest.len() < 22 {
                    continue;
                }
                let state = rest[0];
                let proc_ticks = rest[11].parse::<u64>().unwrap_or(0)
                    + rest[12].parse::<u64>().unwrap_or(0);
                let rss_pages = rest[21].parse::<u64>().unwrap_or(0);
                let rss_mb = round1((rss_pages * page_size) as f64 / (1024.0 * 1024.0));
                cur_procs.insert(pid, proc_ticks);

                let cpu_pct = if dt_ticks > 0 {
                    if let Some(&prev) = prev_procs.get(&pid) {
                        round1(
                            (proc_ticks.saturating_sub(prev) as f64 / dt_ticks as f64)
                                * 100.0
                                * ncpus,
                        )
                    } else {
                        0.0
                    }
                } else {
                    0.0
                };

                let cmd = fs::read(entry.path().join("cmdline"))
                    .ok()
                    .map(|raw| {
                        let replaced: Vec<u8> = raw
                            .into_iter()
                            .take(256)
                            .map(|b| if b == 0 { b' ' } else { b })
                            .collect();
                        String::from_utf8_lossy(&replaced).trim().to_string()
                    })
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| comm.to_string());

                let name_trunc: String = comm.chars().take(32).collect();
                let cmd_trunc: String = cmd.chars().take(96).collect();
                items.push((
                    cpu_pct,
                    rss_mb,
                    json!({
                        "pid": pid,
                        "name": name_trunc,
                        "cmd": cmd_trunc,
                        "state": state,
                        "cpu_pct": cpu_pct,
                        "rss_mb": rss_mb,
                    }),
                ));
            }
        }
        *self.proc_last.lock().unwrap() = Some((total_ticks, cur_procs));
        items.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal))
        });
        let total = items.len();
        let processes: Vec<Value> = items.into_iter().take(cap).map(|x| x.2).collect();
        json!({"processes": processes, "total": total})
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

        let mut available_sources: Vec<String> = Vec::new();
        let mut entries: Vec<Value> = Vec::new();

        if IS_WINDOWS {
            available_sources.extend(["mobile-rc".into(), "system".into(), "application".into()]);
            if src == "all" || src == "mobile-rc" {
                for item in cfg.audit_log_tail(per_src) {
                    entries.push(json!(item));
                }
            }
            if src == "all" || src == "system" {
                entries.extend(read_windows_event_logs(cfg, "System", "system", per_src));
            }
            if src == "all" || src == "application" {
                entries.extend(read_windows_event_logs(
                    cfg,
                    "Application",
                    "application",
                    per_src,
                ));
            }
        } else {
            let has_journal = find_bin(cfg, "journalctl", None).is_some();
            let has_dmesg = find_bin(cfg, "dmesg", None).is_some();
            let syslog_files: Vec<&str> = [
                "/var/log/messages",
                "/var/log/syslog",
                "/var/log/socklog/everything/current",
                "/var/log/everything/current",
            ]
            .into_iter()
            .filter(|p| Path::new(p).is_file())
            .collect();
            let openrc_files: Vec<&str> = ["/var/log/rc.log"]
                .into_iter()
                .filter(|p| Path::new(p).is_file())
                .collect();

            available_sources.push("mobile-rc".into());
            if has_journal {
                available_sources.push("journal".into());
            }
            if !openrc_files.is_empty() {
                available_sources.push("openrc".into());
            }
            if !syslog_files.is_empty() {
                available_sources.push("syslog".into());
            }
            if has_dmesg {
                available_sources.push("dmesg".into());
            }

            if src == "all" || src == "mobile-rc" {
                for item in cfg.audit_log_tail(per_src) {
                    entries.push(json!(item));
                }
                if Path::new("/var/log/mobile-rc.log").is_file() {
                    for raw in read_tail_lines("/var/log/mobile-rc.log", per_src, 524_288) {
                        entries.push(parse_log_line(&raw, "mobile-rc"));
                    }
                }
            }

            if (src == "all" || src == "journal") && has_journal {
                let per_str = per_src.to_string();
                let mut jcmd = vec!["journalctl", "-n", &per_str, "--no-pager", "-o", "short-iso"];
                if lvl == "err" {
                    jcmd.extend(["-p", "3"]);
                } else if lvl == "warn" {
                    jcmd.extend(["-p", "4"]);
                }
                let (rc, out, _) = run_cmd(&jcmd, 6.0);
                if rc == 0 {
                    for raw in out.lines() {
                        if !raw.starts_with("-- ") {
                            entries.push(parse_log_line(raw, "journal"));
                        }
                    }
                }
            }

            if (src == "all" || src == "openrc") && !openrc_files.is_empty() {
                for path in openrc_files {
                    for raw in read_tail_lines(path, per_src, 524_288) {
                        entries.push(parse_log_line(&raw, "openrc"));
                    }
                }
            }

            if (src == "all" || src == "syslog") && !syslog_files.is_empty() {
                for path in syslog_files.iter().take(2) {
                    for raw in read_tail_lines(path, per_src, 524_288) {
                        entries.push(parse_log_line(&raw, "syslog"));
                    }
                }
            }

            if (src == "all" || src == "dmesg") && has_dmesg {
                let mut dcmd = vec!["dmesg", "-T"];
                if lvl == "err" {
                    dcmd.push("--level=emerg,alert,crit,err");
                } else if lvl == "warn" {
                    dcmd.push("--level=emerg,alert,crit,err,warn");
                }
                let (mut rc, mut out, _) = run_cmd(&dcmd, 5.0);
                if rc != 0 {
                    (rc, out, _) = run_cmd(&["dmesg"], 5.0);
                }
                if rc == 0 {
                    let lines_vec: Vec<&str> = out.lines().collect();
                    let start = lines_vec.len().saturating_sub(per_src);
                    for raw in &lines_vec[start..] {
                        if !raw.trim().is_empty() {
                            entries.push(parse_log_line(raw, "dmesg"));
                        }
                    }
                }
            }
        }

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
        if IS_WINDOWS {
            let payload = get_windows_distros_info(cfg, self, &os_info, refresh);
            self.distro_cache.lock().unwrap().insert(
                cache_key,
                DistroCacheSlot {
                    ts: now,
                    payload: payload.clone(),
                },
            );
            return payload;
        }

        let mut cpu_model = String::new();
        if let Ok(raw) = fs::read_to_string("/proc/cpuinfo") {
            for line in raw.lines() {
                if line.starts_with("model name") {
                    if let Some((_, rhs)) = line.split_once(':') {
                        cpu_model = rhs.trim().to_string();
                        break;
                    }
                }
            }
        }

        let env = get_desktop_env(cfg);
        let host_name = os_info
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("Linux")
            .to_string();
        let host_hostname = os_info
            .get("hostname")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let host_kernel = os_info
            .get("kernel")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let init_sys = self.detect_init_system(cfg);
        let comp = get_active_compositor(&env);
        let gpu_name = self
            .get_gpu_info(cfg)
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("Integrated / Unknown")
            .to_string();

        let host = json!({
            "name": host_name,
            "hostname": host_hostname,
            "kernel": host_kernel,
            "arch": std::env::consts::ARCH,
            "init_system": init_sys,
            "compositor": if comp.is_empty() { "unknown" } else { comp },
            "cpu_model": if cpu_model.is_empty() { "Unknown CPU" } else { &cpu_model },
            "gpu_name": gpu_name,
        });

        let efi_entries = self.get_boot_entries(cfg, refresh);
        let bootloader_entries = scan_bootloader_configs();
        let filesystems = scan_mounted_filesystems(cfg);

        let mut os_prober: Vec<Value> = Vec::new();
        if find_bin(cfg, "os-prober", None).is_some() {
            let (rc, out, _) = run_cmd(&["os-prober"], 10.0);
            if rc == 0 {
                for line in out.lines() {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() >= 3 {
                        os_prober.push(json!({
                            "device": parts[0].trim(),
                            "name": parts[1].trim(),
                            "short": parts[2].trim(),
                            "boot_type": parts.get(3).map(|s| s.trim()).unwrap_or(""),
                        }));
                    }
                }
            }
        }

        let mut unmounted_distros: Vec<Value> = Vec::new();
        let mut scan_errors: Vec<String> = Vec::new();
        if deep {
            let _scan_guard = self.distro_scan_lock.lock().unwrap();
            let linux_fs = [
                "ext4", "ext3", "ext2", "btrfs", "xfs", "f2fs", "jfs", "reiserfs", "nilfs2",
            ];
            if find_bin(cfg, "lsblk", None).is_some() {
                let (rc, out, err) = run_cmd(
                    &[
                        "lsblk",
                        "-J",
                        "-o",
                        "NAME,PATH,TYPE,FSTYPE,LABEL,PARTLABEL,UUID,SIZE,MOUNTPOINT",
                    ],
                    8.0,
                );
                if rc == 0 && !out.is_empty() {
                    if let Ok(tree) = serde_json::from_str::<Value>(&out) {
                        let mut flat: Vec<Value> = Vec::new();
                        if let Some(arr) = tree.get("blockdevices").and_then(|v| v.as_array()) {
                            walk_lsblk_devices(arr, &mut flat);
                        }
                        for dev in flat {
                            let name = dev.get("name").and_then(|v| v.as_str()).unwrap_or("");
                            if name.starts_with("zram")
                                || name.starts_with("loop")
                                || name.starts_with("ram")
                            {
                                continue;
                            }
                            let fstype = dev
                                .get("fstype")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_ascii_lowercase();
                            let mnt = dev.get("mountpoint").and_then(|v| v.as_str());
                            let dev_path = dev
                                .get("path")
                                .and_then(|v| v.as_str())
                                .map(str::to_string)
                                .unwrap_or_else(|| {
                                    if name.is_empty() {
                                        String::new()
                                    } else {
                                        format!("/dev/{name}")
                                    }
                                });
                            if dev_path.is_empty()
                                || mnt.is_some()
                                || !linux_fs.contains(&fstype.as_str())
                            {
                                continue;
                            }
                            let label = dev
                                .get("label")
                                .or_else(|| dev.get("partlabel"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let uuid = dev.get("uuid").and_then(|v| v.as_str()).unwrap_or("");
                            let tmpdir = std::env::temp_dir()
                                .join(format!("mrc-probe-{}", crate::config::random_hex(6)));
                            if fs::create_dir_all(&tmpdir).is_ok() {
                                let tmp_str = tmpdir.to_string_lossy().into_owned();
                                let mut mounted = false;
                                let opts_list: &[&str] = if matches!(fstype.as_str(), "ext4" | "ext3" | "xfs") {
                                    &["ro,noload", "ro"]
                                } else {
                                    &["ro"]
                                };
                                for mopts in opts_list {
                                    let (mrc, _, _) =
                                        run_cmd(&["mount", "-o", mopts, &dev_path, &tmp_str], 6.0);
                                    if mrc == 0 {
                                        mounted = true;
                                        break;
                                    }
                                }
                                if mounted {
                                    unmounted_distros.extend(inspect_mounted_tree_for_distros(
                                        &tmpdir, &dev_path, &fstype, label, uuid,
                                    ));
                                    let (urc, _, uerr) = run_cmd(&["umount", &tmp_str], 6.0);
                                    if urc != 0 {
                                        scan_errors.push(format!(
                                            "umount {dev_path}: {}",
                                            if uerr.is_empty() {
                                                urc.to_string()
                                            } else {
                                                uerr
                                            }
                                        ));
                                    }
                                }
                                let _ = fs::remove_dir_all(&tmpdir);
                            }
                        }
                    } else {
                        scan_errors.push("lsblk parse failed".into());
                    }
                } else if !err.is_empty() {
                    scan_errors.push(err);
                }
            } else {
                scan_errors.push("lsblk utility not found".into());
            }
        }

        let mut detected_distros = vec![json!({
            "name": host_name,
            "source": "Running Host",
            "detail": format!("{init_sys} / {host_kernel}"),
        })];
        let mut seen_names: HashSet<String> = HashSet::from([host_name.to_ascii_lowercase()]);

        for item in &unmounted_distros {
            let dname = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let dev = item.get("device").and_then(|v| v.as_str()).unwrap_or("");
            let fst = item.get("fstype").and_then(|v| v.as_str()).unwrap_or("");
            let sub = item.get("subvolume").and_then(|v| v.as_str()).unwrap_or("/");
            detected_distros.push(json!({
                "name": dname,
                "source": "Unmounted Partition",
                "detail": format!("{dev} ({fst}, subvol {sub})"),
            }));
            seen_names.insert(dname.to_ascii_lowercase());
        }
        for item in &os_prober {
            let dname = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if !dname.is_empty() && seen_names.insert(dname.to_ascii_lowercase()) {
                let dev = item.get("device").and_then(|v| v.as_str()).unwrap_or("");
                detected_distros.push(json!({
                    "name": dname,
                    "source": "os-prober",
                    "detail": dev,
                }));
            }
        }
        for item in &bootloader_entries {
            let title = item.get("title").and_then(|v| v.as_str()).unwrap_or("");
            if !title.is_empty() && seen_names.insert(title.to_ascii_lowercase()) {
                let loader = item.get("loader").and_then(|v| v.as_str()).unwrap_or("");
                let detail = item
                    .get("kernel")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .or_else(|| item.get("file").and_then(|v| v.as_str()))
                    .unwrap_or("");
                detected_distros.push(json!({
                    "name": title,
                    "source": loader,
                    "detail": detail,
                }));
            }
        }

        let payload = json!({
            "scanned_at": local_datetime_string(),
            "deep_scan": deep,
            "cached": false,
            "host": host,
            "efi_entries": efi_entries,
            "bootloader_entries": bootloader_entries,
            "os_prober": os_prober,
            "filesystems": filesystems,
            "unmounted_distros": unmounted_distros,
            "detected_distros": detected_distros,
            "scan_errors": scan_errors,
        });
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

fn unix_page_size() -> u64 {
    #[cfg(unix)]
    unsafe {
        let p = libc::sysconf(libc::_SC_PAGESIZE);
        if p > 0 {
            return p as u64;
        }
    }
    4096
}

fn collect_hwmon_temps(keywords: &[&str]) -> Vec<f64> {
    let mut temps = Vec::new();
    let Ok(rd) = fs::read_dir("/sys/class/hwmon") else {
        return temps;
    };
    for hw in rd.flatten() {
        let path = hw.path();
        let name = fs::read_to_string(path.join("name"))
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if keywords.iter().any(|k| name.contains(k)) {
            if let Ok(files) = fs::read_dir(&path) {
                for f in files.flatten() {
                    if let Some(fname) = f.file_name().to_str() {
                        if fname.starts_with("temp") && fname.ends_with("_input") {
                            if let Ok(raw) = fs::read_to_string(f.path()) {
                                if let Ok(v) = raw.trim().parse::<i64>() {
                                    if (5000..130000).contains(&v) {
                                        temps.push(v as f64 / 1000.0);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    temps
}

fn compute_gpu_info(cfg: &ConfigStore) -> Value {
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

    if IS_WINDOWS {
        let v = cfg.cached("win_gpu_name", 180.0, false, || {
            let (_, out, _) = win_run_ps(
                cfg,
                "(Get-CimInstance Win32_VideoController | Select-Object -First 1).Name",
                4.0,
                &[],
            );
            Value::String(out)
        });
        let name = v.as_str().unwrap_or("").lines().next().unwrap_or("").trim();
        if !name.is_empty() {
            let short: String = name.chars().take(64).collect();
            return json!({"available": true, "name": short, "busy_pct": Value::Null, "temp_c": Value::Null});
        }
        return json!({"available": false, "name": "Integrated / Unknown", "busy_pct": Value::Null, "temp_c": Value::Null});
    }

    if let Ok(rd) = fs::read_dir("/sys/class/drm") {
        let mut cards: Vec<String> = rd
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| {
                n.starts_with("card") && n.len() > 4 && n[4..].chars().all(|c| c.is_ascii_digit())
            })
            .collect();
        cards.sort();
        for card in cards {
            let dev_dir = Path::new("/sys/class/drm").join(&card).join("device");
            let busy_pct = fs::read_to_string(dev_dir.join("gpu_busy_percent"))
                .ok()
                .and_then(|s| s.trim().parse::<i64>().ok());
            let mut temp_c = None;
            if let Ok(hms) = fs::read_dir(dev_dir.join("hwmon")) {
                for hm in hms.flatten() {
                    if let Ok(s) = fs::read_to_string(hm.path().join("temp1_input")) {
                        if let Ok(v) = s.trim().parse::<i64>() {
                            if (5000..130000).contains(&v) {
                                temp_c = Some(round1(v as f64 / 1000.0));
                                break;
                            }
                        }
                    }
                }
            }
            if busy_pct.is_some() || temp_c.is_some() {
                return json!({
                    "available": true,
                    "name": format!("GPU ({card})"),
                    "busy_pct": busy_pct,
                    "temp_c": temp_c,
                });
            }
        }
    }

    let gpu_temps = collect_hwmon_temps(&["amdgpu", "nouveau", "radeon", "xe", "i915"]);
    if let Some(max_t) = gpu_temps
        .into_iter()
        .fold(None, |acc: Option<f64>, t| Some(acc.map_or(t, |m| m.max(t))))
    {
        return json!({"available": true, "name": "GPU", "busy_pct": Value::Null, "temp_c": round1(max_t)});
    }
    json!({"available": false, "name": "Integrated / Unknown", "busy_pct": Value::Null, "temp_c": Value::Null})
}

fn compute_mac_addresses(cfg: &ConfigStore) -> Vec<Value> {
    let mut macs = Vec::new();
    if IS_WINDOWS {
        if find_bin(cfg, "getmac", None).is_some() {
            let (rc, out, _) = run_cmd(&["getmac", "/FO", "CSV", "/NH"], 4.0);
            if rc == 0 {
                let mut idx = 1usize;
                for line in out.lines() {
                    let row = parse_csv_row(line);
                    if row.is_empty() {
                        continue;
                    }
                    let raw_mac = row[0].trim().replace('-', ":").to_ascii_lowercase();
                    if is_valid_mac(&raw_mac) && raw_mac != "00:00:00:00:00:00" {
                        let iface: String = row
                            .get(1)
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .unwrap_or_else(|| format!("eth{idx}"));
                        macs.push(json!({"iface": iface.chars().take(48).collect::<String>(), "mac": raw_mac}));
                        idx += 1;
                    }
                }
            }
        }
        return macs;
    }

    if let Ok(rd) = fs::read_dir("/sys/class/net") {
        let mut ifaces: Vec<String> = rd
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        ifaces.sort();
        for iface in ifaces {
            if iface == "lo"
                || iface.starts_with("veth")
                || iface.starts_with("docker")
                || iface.starts_with("br-")
                || iface.starts_with("virbr")
            {
                continue;
            }
            if let Ok(mac_raw) =
                fs::read_to_string(Path::new("/sys/class/net").join(&iface).join("address"))
            {
                let mac = mac_raw.trim().to_ascii_lowercase();
                if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                    macs.push(json!({"iface": iface, "mac": mac}));
                }
            }
        }
    }
    macs
}

fn is_valid_mac(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

fn compute_os_static() -> Value {
    let hostname = get_hostname();
    if IS_WINDOWS {
        return json!({
            "name": "Windows 10/11",
            "hostname": hostname,
            "kernel": std::env::consts::OS,
        });
    }
    let mut os_name = "Linux".to_string();
    if let Ok(raw) = fs::read_to_string("/etc/os-release") {
        for line in raw.lines() {
            if let Some(rest) = line.strip_prefix("PRETTY_NAME=") {
                os_name = rest.trim().trim_matches('"').trim_matches('\'').to_string();
                break;
            }
        }
    }
    let mut kernel = String::new();
    #[cfg(unix)]
    unsafe {
        let mut uts: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut uts) == 0 {
            kernel = std::ffi::CStr::from_ptr(uts.release.as_ptr())
                .to_string_lossy()
                .into_owned();
        }
    }
    if kernel.is_empty() {
        kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "-".into());
    }
    json!({
        "name": os_name,
        "hostname": hostname,
        "kernel": kernel,
    })
}

fn compute_init_system(cfg: &ConfigStore) -> String {
    if IS_WINDOWS {
        return "windows-svc".into();
    }
    if Path::new("/run/systemd/system").is_dir() {
        return "systemd".into();
    }
    if Path::new("/run/openrc").is_dir() || Path::new("/sbin/openrc-run").exists() {
        return "openrc".into();
    }
    if Path::new("/run/runit").is_dir() || Path::new("/etc/runit").is_dir() {
        return "runit".into();
    }
    if let Ok(comm) = fs::read_to_string("/proc/1/comm") {
        let low = comm.trim().to_ascii_lowercase();
        for cand in ["systemd", "openrc", "runit", "s6"] {
            if low.contains(cand) {
                return cand.into();
            }
        }
    }
    if find_bin(cfg, "systemctl", None).is_some() {
        return "systemd".into();
    }
    if find_bin(cfg, "rc-service", None).is_some() {
        return "openrc".into();
    }
    if find_bin(cfg, "sv", None).is_some() {
        return "runit".into();
    }
    "unknown".into()
}

pub fn has_internal_backlight() -> bool {
    if IS_WINDOWS {
        return false;
    }
    fs::read_dir("/sys/class/backlight")
        .map(|mut rd| rd.next().is_some())
        .unwrap_or(false)
}

fn compute_media_and_display(cfg: &ConfigStore) -> Value {
    let mut vol: i64 = 50;
    let mut muted = false;
    let mut brightness: i64 = 50;
    let mut brightness_backend = "unavailable".to_string();
    let mut media_status = "Stopped".to_string();
    let mut media_title = "Nothing playing".to_string();

    if IS_WINDOWS {
        if let Some((wv, wm)) = win_coreaudio_get(cfg) {
            vol = wv;
            muted = wm;
        }
        let (rc_b, out_b, _) = win_run_ps(
            cfg,
            "try { (Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorBrightness -ErrorAction Stop | Select-Object -First 1).CurrentBrightness } catch {}",
            3.0,
            &[],
        );
        if rc_b == 0 {
            if let Ok(b) = out_b.trim().parse::<i64>() {
                brightness = b.clamp(5, 100);
                brightness_backend = "wmi".into();
            }
        }
        return json!({
            "volume": vol,
            "muted": muted,
            "brightness": brightness,
            "brightness_backend": brightness_backend,
            "media_status": "Windows Media",
            "media_title": "Use Windows media keys",
        });
    }

    let env = get_desktop_env(cfg);
    let sp = env.get("PATH").map(String::as_str);

    if find_bin(cfg, "wpctl", sp).is_some() {
        let (rc, out, _) = run_as_user(cfg, &["wpctl", "get-volume", "@DEFAULT_AUDIO_SINK@"], 8.0, None, None, false, false);
        if rc == 0 {
            if let Some(idx) = out.find("Volume:") {
                let after = out[idx + 7..].trim_start();
                if let Some(tok) = after.split_whitespace().next() {
                    if let Ok(f) = tok.parse::<f64>() {
                        vol = (f * 100.0).round() as i64;
                    }
                }
            }
            muted = out.contains("[MUTED]");
        }
    } else if find_bin(cfg, "pactl", sp).is_some() {
        let (rc, out, _) = run_as_user(cfg, &["pactl", "get-sink-volume", "@DEFAULT_SINK@"], 8.0, None, None, false, false);
        if rc == 0 {
            if let Some(pct) = extract_first_percent(&out) {
                vol = pct;
            }
        }
        let (rc_m, out_m, _) = run_as_user(cfg, &["pactl", "get-sink-mute", "@DEFAULT_SINK@"], 8.0, None, None, false, false);
        if rc_m == 0 {
            muted = out_m.to_ascii_lowercase().contains("yes");
        }
    }

    if has_internal_backlight() && find_bin(cfg, "brightnessctl", sp).is_some() {
        let (rc_b, out_b, _) = run_cmd(&["brightnessctl", "-m"], 5.0);
        if rc_b == 0 {
            for field in out_b.split(',') {
                if let Some(stripped) = field.strip_suffix('%') {
                    if let Ok(b) = stripped.parse::<i64>() {
                        brightness = b;
                        brightness_backend = "backlight".into();
                        break;
                    }
                }
            }
        }
    } else if find_bin(cfg, "ddcutil", sp).is_some() {
        brightness_backend = "ddcutil".into();
    }

    if find_bin(cfg, "playerctl", sp).is_some() {
        let (rc_s, out_s, _) = run_as_user(cfg, &["playerctl", "status"], 4.0, None, None, false, false);
        if rc_s == 0 && !out_s.is_empty() {
            media_status = out_s;
        }
        let (rc_t, out_t, _) = run_as_user(
            cfg,
            &["playerctl", "metadata", "--format", "{{artist}} - {{title}}"],
            4.0,
            None,
            None,
            false,
            false,
        );
        if rc_t == 0 && !out_t.is_empty() {
            let cleaned = out_t.trim_matches(|c| c == ' ' || c == '-');
            if !cleaned.is_empty() {
                media_title = cleaned.to_string();
            }
        }
    }

    json!({
        "volume": vol,
        "muted": muted,
        "brightness": brightness,
        "brightness_backend": brightness_backend,
        "media_status": media_status,
        "media_title": media_title,
    })
}

fn extract_first_percent(text: &str) -> Option<i64> {
    let mut digits = String::new();
    for ch in text.chars() {
        if ch.is_ascii_digit() {
            digits.push(ch);
        } else if ch == '%' && !digits.is_empty() {
            return digits.parse::<i64>().ok();
        } else {
            digits.clear();
        }
    }
    None
}

const WIN_COREAUDIO_CS: &str = r#"using System; using System.Runtime.InteropServices; public class MrcAudio { [Guid("5CDF2C82-841E-4546-9722-0CF74078229A"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)] interface IAudioEndpointVolume { int f0(); int f1(); int f2(); int f3(); int SetMasterVolumeLevelScalar(float fLevel, Guid pguidEventContext); int f5(); int GetMasterVolumeLevelScalar(out float pfLevel); int f7(); int f8(); int f9(); int f10(); int SetMute([MarshalAs(UnmanagedType.Bool)] bool bMute, Guid pguidEventContext); int GetMute(out bool pbMute); } [Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)] interface IMMDevice { int Activate(ref Guid iid, int dwClsCtx, IntPtr pActivationParams, [MarshalAs(UnmanagedType.IUnknown)] out object ppInterface); } [Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)] interface IMMDeviceEnumerator { int f0(); int GetDefaultAudioEndpoint(int dataFlow, int role, out IMMDevice ppDevice); } [ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")] class MMDeviceEnumerator {} static IAudioEndpointVolume Ep() { var en = (IMMDeviceEnumerator)(new MMDeviceEnumerator()); IMMDevice dev; en.GetDefaultAudioEndpoint(0, 1, out dev); Guid iid = typeof(IAudioEndpointVolume).GUID; object obj; dev.Activate(ref iid, 23, IntPtr.Zero, out obj); return (IAudioEndpointVolume)obj; } public static string Get() { float v; bool m; var e = Ep(); e.GetMasterVolumeLevelScalar(out v); e.GetMute(out m); return ((int)Math.Round(v*100))+"|"+(m?1:0); } public static void Set(int pct) { Ep().SetMasterVolumeLevelScalar(Math.Max(0f, Math.Min(1f, pct/100f)), Guid.Empty); } }"#;

pub fn win_coreaudio_get(cfg: &ConfigStore) -> Option<(i64, bool)> {
    let ps = format!("Add-Type -TypeDefinition @'\n{WIN_COREAUDIO_CS}\n'@; [MrcAudio]::Get()");
    let (rc, out, _) = win_run_ps(cfg, &ps, 4.0, &[]);
    if rc == 0 {
        if let Some((a, b)) = out.lines().last().unwrap_or("").trim().split_once('|') {
            if let Ok(v) = a.parse::<i64>() {
                return Some((v, b == "1"));
            }
        }
    }
    None
}

pub fn win_coreaudio_set(cfg: &ConfigStore, pct: i64) -> bool {
    let ps = format!(
        "Add-Type -TypeDefinition @'\n{WIN_COREAUDIO_CS}\n'@; [MrcAudio]::Set([int]$env:MRC_VOL_PCT)"
    );
    let clamped = pct.clamp(0, 100).to_string();
    let (rc, _, _) = win_run_ps(cfg, &ps, 4.0, &[("MRC_VOL_PCT", &clamped)]);
    if rc == 0 {
        cfg.invalidate_cache(&["media_display"]);
    }
    rc == 0
}

fn compute_workspaces_info(cfg: &ConfigStore, river_tag: i64) -> Vec<Value> {
    if IS_WINDOWS {
        return vec![json!({"id": 1, "name": "Desktop", "active": true, "windows": 0})];
    }
    let env = get_desktop_env(cfg);
    let sp = env.get("PATH").map(String::as_str);
    let comp = get_active_compositor(&env);

    if matches!(comp, "hyprland" | "") && find_bin(cfg, "hyprctl", sp).is_some() {
        if let Some(ws) = get_hyprland_workspaces(cfg) {
            return ws;
        }
    }
    if matches!(comp, "niri" | "") && find_bin(cfg, "niri", sp).is_some() {
        if let Some(ws) = get_niri_workspaces(cfg) {
            return ws;
        }
    }
    if matches!(comp, "sway" | "") && find_bin(cfg, "swaymsg", sp).is_some() {
        if let Some(ws) = get_sway_workspaces(cfg) {
            return ws;
        }
    }
    if matches!(comp, "kde" | "") {
        if let Some(ws) = get_kde_workspaces(cfg, sp) {
            return ws;
        }
    }
    if comp == "river" {
        let cur = if (1..=9).contains(&river_tag) {
            river_tag
        } else {
            1
        };
        return (1..=9)
            .map(|i| json!({"id": i, "name": i.to_string(), "active": i == cur, "windows": 0}))
            .collect();
    }
    if find_bin(cfg, "wmctrl", sp).is_some() {
        let (rc, out, _) = run_as_user(cfg, &["wmctrl", "-d"], 3.0, None, None, false, false);
        if rc == 0 {
            let mut items = Vec::new();
            for line in out.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(Ok(n)) = parts.first().map(|s| s.parse::<i64>()) {
                    let idx = n + 1;
                    let active = parts.get(1) == Some(&"*");
                    items.push(json!({"id": idx, "name": idx.to_string(), "active": active, "windows": 0}));
                }
            }
            if !items.is_empty() {
                return items;
            }
        }
    }
    if find_bin(cfg, "xdotool", sp).is_some() {
        let (rc_n, out_n, _) =
            run_as_user(cfg, &["xdotool", "get_num_desktops"], 3.0, None, None, false, false);
        let (rc_c, out_c, _) =
            run_as_user(cfg, &["xdotool", "get_desktop"], 3.0, None, None, false, false);
        if rc_n == 0 {
            if let Ok(cnt) = out_n.trim().parse::<i64>() {
                let count = cnt.clamp(1, 20);
                let cur = if rc_c == 0 {
                    out_c.trim().parse::<i64>().map(|c| c + 1).unwrap_or(1)
                } else {
                    1
                };
                return (1..=count)
                    .map(|i| json!({"id": i, "name": i.to_string(), "active": i == cur, "windows": 0}))
                    .collect();
            }
        }
    }
    (1..=4)
        .map(|i| json!({"id": i, "name": i.to_string(), "active": i == 1, "windows": 0}))
        .collect()
}

fn get_hyprland_workspaces(cfg: &ConfigStore) -> Option<Vec<Value>> {
    let (rc_ws, out_ws, _) =
        run_as_user(cfg, &["hyprctl", "workspaces", "-j"], 3.0, None, None, false, false);
    if rc_ws != 0 || out_ws.is_empty() {
        return None;
    }
    let raw_ws: Value = serde_json::from_str(&out_ws).ok()?;
    let arr = raw_ws.as_array()?;
    let (rc_aw, out_aw, _) = run_as_user(
        cfg,
        &["hyprctl", "activeworkspace", "-j"],
        3.0,
        None,
        None,
        false,
        false,
    );
    let active_id = if rc_aw == 0 {
        serde_json::from_str::<Value>(&out_aw)
            .ok()
            .and_then(|v| v.get("id").and_then(|x| x.as_i64()))
    } else {
        None
    };

    let mut by_id: HashMap<i64, Value> = HashMap::new();
    for w in arr {
        let Some(wid) = w.get("id").and_then(|v| v.as_i64()) else {
            continue;
        };
        let wtype = w
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if wid <= 0 || wtype == "special" {
            continue;
        }
        let name = w
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| wid.to_string());
        let windows = w.get("windows").and_then(|v| v.as_i64()).unwrap_or(0);
        by_id.insert(
            wid,
            json!({
                "id": wid,
                "name": name,
                "active": Some(wid) == active_id,
                "windows": windows,
            }),
        );
    }
    if let Some(aid) = active_id {
        if aid > 0 && !by_id.contains_key(&aid) {
            by_id.insert(
                aid,
                json!({"id": aid, "name": aid.to_string(), "active": true, "windows": 0}),
            );
        }
    }
    if by_id.is_empty() {
        return None;
    }
    let mut keys: Vec<i64> = by_id.keys().copied().collect();
    keys.sort_unstable();
    Some(keys.into_iter().filter_map(|k| by_id.remove(&k)).collect())
}

fn get_niri_workspaces(cfg: &ConfigStore) -> Option<Vec<Value>> {
    let (rc, out, _) = run_as_user(
        cfg,
        &["niri", "msg", "--json", "workspaces"],
        3.0,
        None,
        None,
        false,
        false,
    );
    if rc != 0 || out.is_empty() {
        return None;
    }
    let raw: Value = serde_json::from_str(&out).ok()?;
    let arr = raw.as_array()?;
    let focused_output = arr
        .iter()
        .find(|w| w.get("is_focused").and_then(|v| v.as_bool()) == Some(true))
        .and_then(|w| w.get("output").and_then(|v| v.as_str()))
        .map(str::to_string);

    let mut by_idx: HashMap<i64, Value> = HashMap::new();
    for w in arr {
        if let Some(ref fout) = focused_output {
            if w.get("output").and_then(|v| v.as_str()) != Some(fout.as_str()) {
                continue;
            }
        }
        let Some(idx) = w.get("idx").and_then(|v| v.as_i64()) else {
            continue;
        };
        if idx <= 0 {
            continue;
        }
        let name = w
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| idx.to_string());
        let active = w.get("is_focused").and_then(|v| v.as_bool()) == Some(true)
            || w.get("is_active").and_then(|v| v.as_bool()) == Some(true);
        let windows = if w.get("active_window_id").map(|v| !v.is_null()).unwrap_or(false) {
            1
        } else {
            0
        };
        by_idx.insert(
            idx,
            json!({"id": idx, "name": name, "active": active, "windows": windows}),
        );
    }
    if by_idx.is_empty() {
        return None;
    }
    let mut keys: Vec<i64> = by_idx.keys().copied().collect();
    keys.sort_unstable();
    Some(keys.into_iter().filter_map(|k| by_idx.remove(&k)).collect())
}

fn get_sway_workspaces(cfg: &ConfigStore) -> Option<Vec<Value>> {
    let (rc, out, _) = run_as_user(
        cfg,
        &["swaymsg", "-t", "get_workspaces", "-r"],
        3.0,
        None,
        None,
        false,
        false,
    );
    if rc != 0 || out.is_empty() {
        return None;
    }
    let arr: Vec<Value> = serde_json::from_str(&out).ok()?;
    let mut items: Vec<(i64, Value)> = Vec::new();
    for w in arr {
        let Some(num) = w.get("num").and_then(|v| v.as_i64()) else {
            continue;
        };
        if num <= 0 {
            continue;
        }
        let name = w
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| num.to_string());
        let focused = w.get("focused").and_then(|v| v.as_bool()).unwrap_or(false);
        items.push((
            num,
            json!({"id": num, "name": name, "active": focused, "windows": 0}),
        ));
    }
    if items.is_empty() {
        return None;
    }
    items.sort_by_key(|x| x.0);
    Some(items.into_iter().map(|x| x.1).collect())
}

fn get_kde_workspaces(cfg: &ConfigStore, sp: Option<&str>) -> Option<Vec<Value>> {
    for qbin in ["qdbus6", "qdbus"] {
        if find_bin(cfg, qbin, sp).is_none() {
            continue;
        }
        let (rc_cnt, out_cnt, _) = run_as_user(
            cfg,
            &[
                qbin,
                "org.kde.KWin",
                "/VirtualDesktopManager",
                "org.kde.KWin.VirtualDesktopManager.count",
            ],
            3.0,
            None,
            None,
            false,
            false,
        );
        let (rc_cur, out_cur, _) = run_as_user(
            cfg,
            &[qbin, "org.kde.KWin", "/KWin", "org.kde.KWin.currentDesktop"],
            3.0,
            None,
            None,
            false,
            false,
        );
        if rc_cnt == 0 {
            if let Ok(cnt) = out_cnt.trim().parse::<i64>() {
                let count = cnt.clamp(1, 20);
                let cur = if rc_cur == 0 {
                    out_cur.trim().parse::<i64>().unwrap_or(1)
                } else {
                    1
                };
                return Some(
                    (1..=count)
                        .map(|i| json!({"id": i, "name": i.to_string(), "active": i == cur, "windows": 0}))
                        .collect(),
                );
            }
        }
    }
    if find_bin(cfg, "kdotool", sp).is_some() {
        let (rc_n, out_n, _) =
            run_as_user(cfg, &["kdotool", "get_num_desktops"], 3.0, None, None, false, false);
        let (rc_c, out_c, _) =
            run_as_user(cfg, &["kdotool", "get_desktop"], 3.0, None, None, false, false);
        if rc_n == 0 {
            if let Ok(cnt) = out_n.trim().parse::<i64>() {
                let count = cnt.clamp(1, 20);
                let cur = if rc_c == 0 {
                    out_c.trim().parse::<i64>().unwrap_or(1)
                } else {
                    1
                };
                return Some(
                    (1..=count)
                        .map(|i| json!({"id": i, "name": i.to_string(), "active": i == cur, "windows": 0}))
                        .collect(),
                );
            }
        }
    }
    None
}

#[cfg_attr(not(test), allow(dead_code))]
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

fn collect_disk_nodes(
    nodes: &[Value],
    out: &mut Vec<Value>,
    seen: &mut HashSet<(String, String, String)>,
) {
    for node in nodes {
        let name = node.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let ntype = node.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let fstype = node.get("fstype").and_then(|v| v.as_str()).unwrap_or("");
        let is_virtual = name.starts_with("zram")
            || name.starts_with("loop")
            || matches!(ntype, "zram" | "loop" | "rom");
        if !is_virtual && !fstype.is_empty() && !fstype.eq_ignore_ascii_case("swap") {
            let mount = node.get("mountpoint").and_then(|v| v.as_str());
            let key = (
                name.to_string(),
                fstype.to_string(),
                mount.unwrap_or("").to_string(),
            );
            if seen.insert(key) {
                let label = node
                    .get("label")
                    .and_then(|v| v.as_str())
                    .or_else(|| node.get("partlabel").and_then(|v| v.as_str()))
                    .or(mount)
                    .unwrap_or(name);
                let size = node.get("size").and_then(|v| v.as_str()).unwrap_or("-");
                let use_pct = node.get("fsuse%").and_then(|v| v.as_str()).unwrap_or("-");
                out.push(json!({
                    "part": name,
                    "label": label,
                    "fstype": fstype,
                    "size": size,
                    "use_pct": use_pct,
                    "mounted": mount.is_some(),
                }));
            }
        }
        if let Some(children) = node.get("children").and_then(|v| v.as_array()) {
            collect_disk_nodes(children, out, seen);
        }
    }
}

fn compute_disks_info() -> Vec<Value> {
    let mut disks = Vec::new();
    #[cfg(windows)]
    unsafe {
        let mask = win_ffi::GetLogicalDrives();
        for i in 0..26u32 {
            if (mask & (1 << i)) == 0 {
                continue;
            }
            let letter = (b'A' + i as u8) as char;
            let root = format!("{letter}:\\");
            let mut wide: Vec<u16> = root.encode_utf16().collect();
            wide.push(0);
            let dtype = win_ffi::GetDriveTypeW(wide.as_ptr());
            let dlabel = match dtype {
                2 => "Removable",
                3 => "Fixed",
                4 => "Network",
                _ => continue,
            };
            let mut avail = 0u64;
            let mut total = 0u64;
            let mut free = 0u64;
            if win_ffi::GetDiskFreeSpaceExW(wide.as_ptr(), &mut avail, &mut total, &mut free) != 0 {
                let used = total.saturating_sub(free);
                let pct = if total > 0 {
                    ((used as f64 / total as f64) * 100.0).round() as i64
                } else {
                    0
                };
                disks.push(json!({
                    "part": format!("{letter}:"),
                    "label": format!("Drive ({letter}:)"),
                    "fstype": dlabel,
                    "size": fmt_size_bytes(total),
                    "use_pct": format!("{pct}%"),
                    "mounted": true,
                }));
            }
        }
        return disks;
    }
    #[cfg(not(windows))]
    {
        let (rc, out, _) = run_cmd(
            &[
                "lsblk",
                "-J",
                "-o",
                "NAME,TYPE,LABEL,PARTLABEL,SIZE,FSTYPE,FSUSED,FSUSE%,MOUNTPOINT",
            ],
            8.0,
        );
        if rc == 0 && !out.is_empty() {
            if let Ok(parsed) = serde_json::from_str::<Value>(&out) {
                if let Some(arr) = parsed.get("blockdevices").and_then(|v| v.as_array()) {
                    let mut seen = HashSet::new();
                    collect_disk_nodes(arr, &mut disks, &mut seen);
                }
            }
        }
        disks
    }
}

fn compute_boot_entries(cfg: &ConfigStore) -> Vec<Value> {
    let mut entries = Vec::new();
    if IS_WINDOWS {
        if find_bin(cfg, "bcdedit", None).is_some() {
            let (rc, out, _) = run_cmd(&["bcdedit", "/enum", "firmware"], 5.0);
            if rc == 0 {
                let mut cur_id = String::new();
                let mut cur_desc = String::new();
                for raw in out.lines().chain(std::iter::once("")) {
                    let line = raw.trim();
                    if line.is_empty() {
                        if !cur_id.is_empty()
                            && !cur_desc.is_empty()
                            && !cur_id.eq_ignore_ascii_case("{fwbootmgr}")
                        {
                            entries.push(json!({"num": cur_id, "name": cur_desc}));
                        }
                        cur_id.clear();
                        cur_desc.clear();
                        continue;
                    }
                    let mut split = line.splitn(2, char::is_whitespace);
                    if let (Some(k), Some(v)) = (split.next(), split.next()) {
                        let k_low = k.to_ascii_lowercase();
                        if k_low == "identifier" {
                            cur_id = v.trim().to_string();
                        } else if k_low == "description" {
                            cur_desc = v.trim().to_string();
                        }
                    }
                }
            }
        }
        return entries;
    }

    if find_bin(cfg, "efibootmgr", None).is_some() {
        let (rc, out, _) = run_cmd(&["efibootmgr"], 5.0);
        if rc == 0 {
            for line in out.lines() {
                if let Some(rest) = line.strip_prefix("Boot") {
                    if rest.len() >= 5 && rest.is_char_boundary(4) {
                        let hex = &rest[..4];
                        if hex.chars().all(|c| c.is_ascii_hexdigit()) {
                            let after_hex = rest[4..].trim_start_matches('*').trim_start();
                            let raw_name = after_hex.split('\t').next().unwrap_or("").trim();
                            if raw_name.is_empty() {
                                continue;
                            }
                            let low = raw_name.to_ascii_lowercase();
                            let skip = ["efi ", "cdrom", "cd/dvd", "removable", "network", "pxe", "usb"]
                                .iter()
                                .any(|t| low.contains(t));
                            if !skip {
                                entries.push(json!({"num": hex.to_ascii_uppercase(), "name": raw_name}));
                            }
                        }
                    }
                }
            }
        }
    }
    entries
}

fn compute_local_ips(cfg: &ConfigStore) -> Vec<String> {
    let mut ips: Vec<String> = Vec::new();
    if IS_WINDOWS {
        let host = get_hostname();
        if let Ok(addrs) = (host.as_str(), 0u16).to_socket_addrs() {
            for addr in addrs {
                if addr.is_ipv4() {
                    let s = addr.ip().to_string();
                    if !s.starts_with("127.") && !ips.contains(&s) {
                        ips.push(s);
                    }
                }
            }
        }
    } else if find_bin(cfg, "ip", None).is_some() {
        let (rc, out, _) = run_cmd(&["ip", "-4", "-o", "addr", "show", "scope", "global"], 4.0);
        if rc == 0 {
            for line in out.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(idx) = parts.iter().position(|&p| p == "inet") {
                    if let Some(cidr) = parts.get(idx + 1) {
                        let ip_addr = cidr.split('/').next().unwrap_or("");
                        if !ip_addr.is_empty()
                            && !ip_addr.starts_with("127.")
                            && !ips.contains(&ip_addr.to_string())
                        {
                            ips.push(ip_addr.to_string());
                        }
                    }
                }
            }
        }
    }

    if !IS_WINDOWS && ips.is_empty() && find_bin(cfg, "hostname", None).is_some() {
        let (rc, out, _) = run_cmd(&["hostname", "-I"], 3.0);
        if rc == 0 {
            for tok in out.split_whitespace() {
                if tok.contains('.') && !tok.starts_with("127.") && !ips.contains(&tok.to_string()) {
                    ips.push(tok.to_string());
                }
            }
        }
    }

    if ips.is_empty() {
        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
            if sock.connect("8.8.8.8:80").is_ok() {
                if let Ok(local) = sock.local_addr() {
                    let s = local.ip().to_string();
                    if !s.starts_with("127.") {
                        ips.push(s);
                    }
                }
            }
        }
    }
    ips
}

fn compute_services_info(cfg: &ConfigStore, tel: &TelemetryState) -> Value {
    let init_sys = tel.detect_init_system(cfg);
    let mut services: Vec<Value> = Vec::new();
    if IS_WINDOWS {
        let ps = "Get-Service | Sort-Object Status -Descending | Select-Object -First 80 Name,@{N='Status';E={$_.Status.ToString()}},@{N='StartType';E={$_.StartType.ToString()}} | ConvertTo-Json -Compress";
        let (rc, out, _) = win_run_ps(cfg, ps, 6.0, &[]);
        if rc == 0 && !out.is_empty() {
            if let Ok(parsed) = serde_json::from_str::<Value>(&out) {
                let arr = match parsed {
                    Value::Array(a) => a,
                    Value::Object(_) => vec![parsed],
                    _ => Vec::new(),
                };
                for item in arr {
                    if let Some(name) = item.get("Name").and_then(|v| v.as_str()) {
                        let status = item
                            .get("Status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown")
                            .to_ascii_lowercase();
                        let start = item
                            .get("StartType")
                            .and_then(|v| v.as_str())
                            .unwrap_or("windows");
                        services.push(json!({
                            "name": name,
                            "status": status,
                            "runlevel": start,
                        }));
                    }
                }
            }
        }
        return json!({"init_system": init_sys, "services": services});
    }

    if init_sys == "openrc" && find_bin(cfg, "rc-status", None).is_some() {
        let (rc, out, _) = run_cmd(&["rc-status", "-a", "-C"], 6.0);
        let mut runlevel = "default".to_string();
        if rc == 0 {
            for line in out.lines() {
                let s = line.trim();
                if s.is_empty() {
                    continue;
                }
                if let Some(rest) = s.strip_prefix("Runlevel:") {
                    runlevel = rest.trim().to_string();
                    continue;
                }
                if let Some((left, right)) = s.rsplit_once('[') {
                    if let Some(status_raw) = right.strip_suffix(']') {
                        let name = left.trim();
                        if !name.is_empty()
                            && name
                                .chars()
                                .all(|c| c.is_ascii_alphanumeric() || "_.@:-".contains(c))
                        {
                            services.push(json!({
                                "name": name,
                                "status": status_raw.trim(),
                                "runlevel": runlevel,
                            }));
                        }
                    }
                }
            }
        }
    } else if init_sys == "systemd" && find_bin(cfg, "systemctl", None).is_some() {
        let (rc, out, _) = run_cmd(
            &[
                "systemctl",
                "list-units",
                "--type=service",
                "--all",
                "--no-pager",
                "--no-legend",
            ],
            6.0,
        );
        if rc == 0 {
            for line in out.lines().take(80) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let unit = parts[0].strip_suffix(".service").unwrap_or(parts[0]);
                    services.push(json!({
                        "name": unit,
                        "status": format!("{} ({})", parts[2], parts[3]),
                        "runlevel": "systemd",
                    }));
                }
            }
        }
    } else if init_sys == "runit" && find_bin(cfg, "sv", None).is_some() {
        for base in ["/run/runit/service", "/var/service"] {
            if !Path::new(base).is_dir() {
                continue;
            }
            if let Ok(rd) = fs::read_dir(base) {
                let mut names: Vec<String> = rd
                    .flatten()
                    .filter_map(|e| e.file_name().into_string().ok())
                    .collect();
                names.sort();
                for name in names.into_iter().take(60) {
                    let p = Path::new(base).join(&name);
                    let p_str = p.to_string_lossy().into_owned();
                    let (rc, out, _) = run_cmd(&["sv", "status", &p_str], 3.0);
                    let st = if !out.is_empty() {
                        out.split(':').next().unwrap_or("ok").trim().to_string()
                    } else if rc == 0 {
                        "ok".into()
                    } else {
                        "down".into()
                    };
                    services.push(json!({"name": name, "status": st, "runlevel": "runit"}));
                }
            }
            break;
        }
    }
    json!({"init_system": init_sys, "services": services})
}

fn read_tail_lines(path: &str, max_lines: usize, max_bytes: u64) -> Vec<String> {
    let Ok(mut f) = File::open(path) else {
        return Vec::new();
    };
    let Ok(size) = f.seek(SeekFrom::End(0)) else {
        return Vec::new();
    };
    let start = size.saturating_sub(max_bytes);
    if f.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let mut raw = Vec::new();
    if f.read_to_end(&mut raw).is_err() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&raw);
    let mut lines: Vec<String> = text
        .lines()
        .map(str::to_string)
        .collect();
    if start > 0 && !lines.is_empty() {
        lines.remove(0);
    }
    let non_empty: Vec<String> = lines.into_iter().filter(|l| !l.trim().is_empty()).collect();
    let skip = non_empty.len().saturating_sub(max_lines);
    non_empty.into_iter().skip(skip).collect()
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

fn read_windows_event_logs(
    cfg: &ConfigStore,
    log_name: &str,
    source_tag: &str,
    max_events: usize,
) -> Vec<Value> {
    let ps = "try { Get-WinEvent -LogName $env:MRC_EVT_LOG -MaxEvents ([int]$env:MRC_EVT_MAX) -ErrorAction Stop | ForEach-Object { $t = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); $l = [string]$_.LevelDisplayName; $p = [string]$_.ProviderName; $m = ([string]$_.Message) -replace '[\\r\\n\\t]+',' '; \"$t|$l|$p|$m\" } } catch {}";
    let max_str = max_events.to_string();
    let (rc, out, _) = win_run_ps(
        cfg,
        ps,
        6.0,
        &[("MRC_EVT_LOG", log_name), ("MRC_EVT_MAX", &max_str)],
    );
    let mut entries = Vec::new();
    if rc == 0 {
        for line in out.lines() {
            let parts: Vec<&str> = line.splitn(4, '|').collect();
            if parts.len() < 4 {
                continue;
            }
            let ts = parts[0].trim();
            let lvl_raw = parts[1].trim();
            let prov = parts[2].trim();
            let msg = parts[3].trim();
            let combined = format!("{lvl_raw} {msg}");
            let body = if prov.is_empty() {
                msg.to_string()
            } else {
                format!("[{prov}] {msg}")
            };
            let truncated: String = body.chars().take(1200).collect();
            entries.push(json!({
                "ts": ts,
                "source": source_tag,
                "level": classify_log_level(&combined),
                "message": truncated,
            }));
        }
        entries.reverse();
    }
    entries
}

fn parse_os_release_file(path: &Path) -> Option<(String, String, String)> {
    if !path.is_file() {
        return None;
    }
    let raw = fs::read_to_string(path).ok()?;
    let mut pretty = String::new();
    let mut name = String::new();
    let mut id = String::new();
    let mut ver = String::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            let val = v.trim().trim_matches('"').trim_matches('\'').to_string();
            match k.trim() {
                "PRETTY_NAME" => pretty = val,
                "NAME" => name = val,
                "ID" => id = val,
                "VERSION_ID" => ver = val,
                _ => {}
            }
        }
    }
    if pretty.is_empty() && name.is_empty() && id.is_empty() {
        return None;
    }
    let final_name = if !pretty.is_empty() {
        pretty
    } else if !name.is_empty() {
        name
    } else {
        "Linux".into()
    };
    let final_id = if id.is_empty() { "linux".into() } else { id };
    Some((final_name, final_id, ver))
}

fn scan_bootloader_configs() -> Vec<Value> {
    let mut entries = Vec::new();
    for base in [
        "/boot/loader/entries",
        "/efi/loader/entries",
        "/boot/efi/loader/entries",
    ] {
        let Ok(rd) = fs::read_dir(base) else {
            continue;
        };
        let mut names: Vec<String> = rd
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.ends_with(".conf"))
            .collect();
        names.sort();
        for fname in names {
            let fpath = Path::new(base).join(&fname);
            let mut title = fname.trim_end_matches(".conf").to_string();
            let mut linux_img = String::new();
            if let Ok(raw) = fs::read_to_string(&fpath) {
                for line in raw.lines() {
                    let s = line.trim();
                    if let Some(t) = s.strip_prefix("title ") {
                        title = t.trim().to_string();
                    } else if let Some(l) = s.strip_prefix("linux ") {
                        linux_img = l.trim().to_string();
                    }
                }
                entries.push(json!({
                    "loader": "systemd-boot",
                    "title": title,
                    "kernel": linux_img,
                    "file": fname,
                }));
            }
        }
    }

    for gpath in [
        "/boot/grub/grub.cfg",
        "/boot/grub2/grub.cfg",
        "/boot/efi/EFI/grub/grub.cfg",
    ] {
        if let Ok(raw) = fs::read_to_string(gpath) {
            for line in raw.lines() {
                let s = line.trim_start();
                if let Some(rest) = s.strip_prefix("menuentry ") {
                    let rest = rest.trim_start();
                    let quote = rest.chars().next();
                    if let Some(q @ ('\'' | '"')) = quote {
                        if let Some(end) = rest[1..].find(q) {
                            let title = rest[1..1 + end].trim();
                            if !title.is_empty() {
                                entries.push(json!({
                                    "loader": "grub",
                                    "title": title,
                                    "kernel": "",
                                    "file": gpath,
                                }));
                            }
                        }
                    }
                }
            }
        }
    }
    entries.truncate(40);
    entries
}

fn scan_mounted_filesystems(cfg: &ConfigStore) -> Vec<Value> {
    let mut mounts = Vec::new();
    let skip_fs = [
        "proc", "sysfs", "tmpfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "pstore", "bpf",
        "tracefs", "securityfs", "efivarfs", "fusectl", "debugfs", "ramfs", "configfs",
        "hugetlbfs", "mqueue", "autofs",
    ];
    if find_bin(cfg, "findmnt", None).is_some() {
        let (rc, out, _) = run_cmd(&["findmnt", "-J", "-l", "-o", "SOURCE,TARGET,FSTYPE,OPTIONS"], 5.0);
        if rc == 0 {
            if let Ok(parsed) = serde_json::from_str::<Value>(&out) {
                if let Some(arr) = parsed.get("filesystems").and_then(|v| v.as_array()) {
                    for node in arr {
                        let fstype = node.get("fstype").and_then(|v| v.as_str()).unwrap_or("");
                        if skip_fs.contains(&fstype) {
                            continue;
                        }
                        mounts.push(json!({
                            "source": node.get("source").and_then(|v| v.as_str()).unwrap_or(""),
                            "target": node.get("target").and_then(|v| v.as_str()).unwrap_or(""),
                            "fstype": fstype,
                            "options": node.get("options").and_then(|v| v.as_str()).unwrap_or(""),
                        }));
                    }
                    mounts.truncate(30);
                    return mounts;
                }
            }
        }
    }
    if let Ok(raw) = fs::read_to_string("/proc/mounts") {
        for line in raw.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 && parts[0].starts_with("/dev/") {
                mounts.push(json!({
                    "source": parts[0],
                    "target": parts[1],
                    "fstype": parts[2],
                    "options": parts[3],
                }));
            }
        }
    }
    mounts.truncate(30);
    mounts
}

fn inspect_mounted_tree_for_distros(
    root_path: &Path,
    dev_path: &str,
    fstype: &str,
    label: &str,
    uuid: &str,
) -> Vec<Value> {
    let mut found = Vec::new();
    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    let mut candidates: Vec<(String, std::path::PathBuf)> =
        vec![(String::new(), root_path.to_path_buf())];
    if fstype == "btrfs" {
        if let Ok(rd) = fs::read_dir(root_path) {
            let mut names: Vec<String> = rd
                .flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n.starts_with('@'))
                .collect();
            names.sort();
            for name in names {
                let sub = root_path.join(&name);
                if sub.is_dir() {
                    candidates.push((name, sub));
                }
            }
        }
    }
    for (subvol, base) in candidates {
        for rel in ["etc/os-release", "usr/lib/os-release"] {
            if let Some((name, id, ver)) = parse_os_release_file(&base.join(rel)) {
                let key = (dev_path.to_string(), subvol.clone(), name.clone());
                if seen.insert(key) {
                    found.push(json!({
                        "name": name,
                        "id": id,
                        "version_id": ver,
                        "device": dev_path,
                        "fstype": fstype,
                        "label": label,
                        "uuid": uuid,
                        "subvolume": if subvol.is_empty() { "/" } else { &subvol },
                    }));
                }
                break;
            }
        }
    }
    found
}

fn walk_lsblk_devices(nodes: &[Value], out: &mut Vec<Value>) {
    for node in nodes {
        out.push(node.clone());
        if let Some(children) = node.get("children").and_then(|v| v.as_array()) {
            walk_lsblk_devices(children, out);
        }
    }
}

fn get_windows_distros_info(
    cfg: &ConfigStore,
    tel: &TelemetryState,
    os_info: &Value,
    refresh: bool,
) -> Value {
    let cpu_model = std::env::var("PROCESSOR_IDENTIFIER")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "x86_64 CPU".into());
    let name = os_info
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("Windows");
    let hostname = os_info
        .get("hostname")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let kernel = os_info.get("kernel").and_then(|v| v.as_str()).unwrap_or("");
    let gpu_name = tel
        .get_gpu_info(cfg)
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("Integrated / Unknown")
        .to_string();

    let host = json!({
        "name": name,
        "hostname": hostname,
        "kernel": kernel,
        "arch": std::env::consts::ARCH,
        "init_system": "windows-svc",
        "compositor": "DWM",
        "cpu_model": cpu_model,
        "gpu_name": gpu_name,
    });
    let mut detected_distros = vec![json!({
        "name": name,
        "source": "Running Host",
        "detail": format!("windows-svc / {kernel}"),
    })];
    if find_bin(cfg, "wsl", None).is_some() {
        let (rc, out, _) = run_cmd(&["wsl", "-l", "-v"], 5.0);
        if rc == 0 {
            for line in out.lines().skip(1) {
                let clean = line.replace('\0', "");
                let clean = clean.trim().trim_start_matches('*').trim();
                if clean.is_empty() {
                    continue;
                }
                let parts: Vec<&str> = clean.split_whitespace().collect();
                if !parts.is_empty() {
                    detected_distros.push(json!({
                        "name": parts[0],
                        "source": "WSL",
                        "detail": if parts.len() > 1 { parts[1..].join(" ") } else { "Installed".into() },
                    }));
                }
            }
        }
    }
    let disks = tel.get_disks_info(cfg, refresh);
    let filesystems: Vec<Value> = disks
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|d| {
                    json!({
                        "target": d.get("part").and_then(|v| v.as_str()).unwrap_or(""),
                        "fstype": d.get("fstype").and_then(|v| v.as_str()).unwrap_or(""),
                        "source": format!(
                            "{} ({} used)",
                            d.get("size").and_then(|v| v.as_str()).unwrap_or("-"),
                            d.get("use_pct").and_then(|v| v.as_str()).unwrap_or("-")
                        ),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    json!({
        "scanned_at": local_datetime_string(),
        "deep_scan": false,
        "cached": false,
        "host": host,
        "efi_entries": tel.get_boot_entries(cfg, refresh),
        "bootloader_entries": [],
        "os_prober": [],
        "filesystems": filesystems,
        "unmounted_distros": [],
        "detected_distros": detected_distros,
        "scan_errors": [],
    })
}

/// Parse one CSV line (handling quoted fields).
fn parse_csv_row(line: &str) -> Vec<String> {
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

/// Probe outbound TCP connectivity cleanly if needed.
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

        let parsed_iso = parse_log_line("2026-11-15T01:00:00+0700 host systemd[1]: Failed to start foo", "journal");
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
}

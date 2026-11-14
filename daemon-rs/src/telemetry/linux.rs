//! Linux / Unix system telemetry, desktop session inspection, logs, and OS inventory.

use super::{
    find_bin, get_active_compositor, get_desktop_env, get_hostname, merge_path_dirs,
    os_cpu_count, parse_log_line, round1, run_as_user, run_cmd, TelemetryState,
};
use crate::config::{local_datetime_string, ConfigStore, TargetUserInfo};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub(super) fn win_run_ps(
    _cfg: &ConfigStore,
    _ps_script: &str,
    _timeout_sec: f64,
    _extra_env: &[(&str, &str)],
) -> (i32, String, String) {
    (1, String::new(), "Windows-only".into())
}

pub(super) fn win_coreaudio_set(_cfg: &ConfigStore, _pct: i64) -> bool {
    false
}

pub(super) fn has_internal_backlight() -> bool {
    fs::read_dir("/sys/class/backlight")
        .map(|mut rd| rd.next().is_some())
        .unwrap_or(false)
}

pub(super) fn compute_desktop_env(user: &TargetUserInfo) -> HashMap<String, String> {
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

pub(super) fn get_cpu_percent(tel: &TelemetryState) -> f64 {
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
    let mut guard = tel.last_cpu.lock().unwrap();
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

pub(super) fn get_cpu_temp(_cfg: &ConfigStore) -> f64 {
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

pub(super) fn compute_gpu_fallback(_cfg: &ConfigStore) -> Value {
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

pub(super) fn get_memory_info() -> Value {
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

pub(super) fn get_swap_info() -> Value {
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

pub(super) fn get_battery_info() -> Value {
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

pub(super) fn compute_mac_addresses(_cfg: &ConfigStore) -> Vec<Value> {
    let mut macs = Vec::new();
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

pub(super) fn compute_net_bytes(_cfg: &ConfigStore) -> (u64, u64) {
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
}

pub(super) fn compute_os_static() -> Value {
    let hostname = get_hostname();
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

pub(super) fn uptime_secs() -> Option<u64> {
    fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|raw| {
            raw.split_whitespace()
                .next()
                .and_then(|s| s.parse::<f64>().ok())
        })
        .map(|sec_f| sec_f as u64)
}

pub(super) fn compute_init_system(cfg: &ConfigStore) -> String {
    if Path::new("/run/systemd/system").is_dir() {
        return "systemd".into();
    }
    if Path::new("/run/openrc").is_dir() || Path::new("/sbin/openrc-run").exists() {
        return "openrc".into();
    }
    if (Path::new("/run/dinit.sock").exists() || Path::new("/etc/dinit.d").is_dir())
        && find_bin(cfg, "dinitctl", None).is_some()
    {
        return "dinit".into();
    }
    if Path::new("/run/runit").is_dir() || Path::new("/etc/runit").is_dir() {
        return "runit".into();
    }
    if let Ok(comm) = fs::read_to_string("/proc/1/comm") {
        let low = comm.trim().to_ascii_lowercase();
        for cand in ["systemd", "openrc", "dinit", "runit", "s6"] {
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
    if find_bin(cfg, "dinitctl", None).is_some() {
        return "dinit".into();
    }
    if find_bin(cfg, "sv", None).is_some() {
        return "runit".into();
    }
    "unknown".into()
}

pub(super) fn compute_media_and_display(cfg: &ConfigStore) -> Value {
    let mut vol: i64 = 50;
    let mut muted = false;
    let mut brightness: i64 = 50;
    let mut brightness_backend = "unavailable".to_string();
    let mut media_status = "Stopped".to_string();
    let mut media_title = "Nothing playing".to_string();

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

pub(super) fn compute_workspaces_info(cfg: &ConfigStore, river_tag: i64) -> Vec<Value> {
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

pub(super) fn compute_disks_info() -> Vec<Value> {
    let mut disks = Vec::new();
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

pub(super) fn compute_boot_entries(cfg: &ConfigStore) -> Vec<Value> {
    let mut entries = Vec::new();
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

pub(super) fn compute_local_ips(cfg: &ConfigStore) -> Vec<String> {
    let mut ips = Vec::new();
    if find_bin(cfg, "ip", None).is_some() {
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
    if ips.is_empty() && find_bin(cfg, "hostname", None).is_some() {
        let (rc, out, _) = run_cmd(&["hostname", "-I"], 3.0);
        if rc == 0 {
            for tok in out.split_whitespace() {
                if tok.contains('.') && !tok.starts_with("127.") && !ips.contains(&tok.to_string()) {
                    ips.push(tok.to_string());
                }
            }
        }
    }
    ips
}

pub(super) fn compute_services_info(cfg: &ConfigStore, init_sys: &str) -> Value {
    let mut services: Vec<Value> = Vec::new();
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

pub(super) fn get_processes_info(tel: &TelemetryState, cap: usize) -> Value {
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
        let guard = tel.proc_last.lock().unwrap();
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
            let proc_ticks =
                rest[11].parse::<u64>().unwrap_or(0) + rest[12].parse::<u64>().unwrap_or(0);
            let rss_pages = rest[21].parse::<u64>().unwrap_or(0);
            let rss_mb = round1((rss_pages * page_size) as f64 / (1024.0 * 1024.0));
            cur_procs.insert(pid, proc_ticks);

            let cpu_pct = if dt_ticks > 0 {
                if let Some(&prev) = prev_procs.get(&pid) {
                    round1((proc_ticks.saturating_sub(prev) as f64 / dt_ticks as f64) * 100.0 * ncpus)
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
    *tel.proc_last.lock().unwrap() = Some((total_ticks, cur_procs));
    items.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal))
    });
    let total = items.len();
    let processes: Vec<Value> = items.into_iter().take(cap).map(|x| x.2).collect();
    json!({"processes": processes, "total": total})
}

pub(super) fn collect_logs(
    cfg: &ConfigStore,
    src: &str,
    lvl: &str,
    per_src: usize,
) -> (Vec<String>, Vec<Value>) {
    let mut available_sources: Vec<String> = Vec::new();
    let mut entries: Vec<Value> = Vec::new();

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

    (available_sources, entries)
}

pub(super) fn compute_installed_distros(
    tel: &TelemetryState,
    cfg: &ConfigStore,
    os_info: &Value,
    deep: bool,
    refresh: bool,
) -> Value {
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
    let init_sys = tel.detect_init_system(cfg);
    let comp = get_active_compositor(&env);
    let gpu_name = tel
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

    let efi_entries = tel.get_boot_entries(cfg, refresh);
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
        let _scan_guard = tel.distro_scan_lock.lock().unwrap();
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
                        if name.starts_with("zram") || name.starts_with("loop") || name.starts_with("ram") {
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
                                if name.is_empty() { String::new() } else { format!("/dev/{name}") }
                            });
                        if dev_path.is_empty() || mnt.is_some() || !linux_fs.contains(&fstype.as_str()) {
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
                                        if uerr.is_empty() { urc.to_string() } else { uerr }
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

    json!({
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
    })
}

fn unix_page_size() -> u64 {
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
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    if start > 0 && !lines.is_empty() {
        lines.remove(0);
    }
    let non_empty: Vec<String> = lines.into_iter().filter(|l| !l.trim().is_empty()).collect();
    let skip = non_empty.len().saturating_sub(max_lines);
    non_empty.into_iter().skip(skip).collect()
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

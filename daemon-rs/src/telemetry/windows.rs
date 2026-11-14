//! Windows system telemetry, Win32 FFI, CoreAudio COM bridge, Event Logs, and WSL inventory.

use super::{
    classify_log_level, exec_cmd_blocking, find_bin, fmt_size_bytes, get_hostname, get_system_path,
    is_valid_mac, parse_csv_row, round1, run_cmd, TelemetryState,
};
use crate::config::{local_datetime_string, ConfigStore, TargetUserInfo};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::ToSocketAddrs;

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

pub(super) fn win_run_ps(
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

const WIN_COREAUDIO_CS: &str = r#"using System; using System.Runtime.InteropServices; public class MrcAudio { [Guid("5CDF2C82-841E-4546-9722-0CF74078229A"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)] interface IAudioEndpointVolume { int f0(); int f1(); int f2(); int f3(); int SetMasterVolumeLevelScalar(float fLevel, Guid pguidEventContext); int f5(); int GetMasterVolumeLevelScalar(out float pfLevel); int f7(); int f8(); int f9(); int f10(); int SetMute([MarshalAs(UnmanagedType.Bool)] bool bMute, Guid pguidEventContext); int GetMute(out bool pbMute); } [Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)] interface IMMDevice { int Activate(ref Guid iid, int dwClsCtx, IntPtr pActivationParams, [MarshalAs(UnmanagedType.IUnknown)] out object ppInterface); } [Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)] interface IMMDeviceEnumerator { int f0(); int GetDefaultAudioEndpoint(int dataFlow, int role, out IMMDevice ppDevice); } [ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")] class MMDeviceEnumerator {} static IAudioEndpointVolume Ep() { var en = (IMMDeviceEnumerator)(new MMDeviceEnumerator()); IMMDevice dev; en.GetDefaultAudioEndpoint(0, 1, out dev); Guid iid = typeof(IAudioEndpointVolume).GUID; object obj; dev.Activate(ref iid, 23, IntPtr.Zero, out obj); return (IAudioEndpointVolume)obj; } public static string Get() { float v; bool m; var e = Ep(); e.GetMasterVolumeLevelScalar(out v); e.GetMute(out m); return ((int)Math.Round(v*100))+"|"+(m?1:0); } public static void Set(int pct) { Ep().SetMasterVolumeLevelScalar(Math.Max(0f, Math.Min(1f, pct/100f)), Guid.Empty); } }"#;

fn win_coreaudio_get(cfg: &ConfigStore) -> Option<(i64, bool)> {
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

pub(super) fn win_coreaudio_set(cfg: &ConfigStore, pct: i64) -> bool {
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

pub(super) fn has_internal_backlight() -> bool {
    false
}

pub(super) fn compute_desktop_env(user: &TargetUserInfo) -> HashMap<String, String> {
    let mut env: HashMap<String, String> = std::env::vars().collect();
    env.entry("USERPROFILE".into()).or_insert_with(|| user.home.clone());
    env.entry("HOME".into()).or_insert_with(|| user.home.clone());
    env.entry("USERNAME".into())
        .or_insert_with(|| user.username.clone());
    env.insert("PATH".into(), get_system_path());
    env
}

pub(super) fn get_cpu_percent(tel: &TelemetryState) -> f64 {
    unsafe {
        let mut idle: win_ffi::FileTime = std::mem::zeroed();
        let mut kern: win_ffi::FileTime = std::mem::zeroed();
        let mut usr: win_ffi::FileTime = std::mem::zeroed();
        if win_ffi::GetSystemTimes(&mut idle, &mut kern, &mut usr) == 0 {
            return 0.0;
        }
        let idle_v = idle.to_u64();
        let total_v = kern.to_u64() + usr.to_u64();
        let mut guard = tel.last_cpu.lock().unwrap();
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
        round1((100.0 * (1.0 - (di as f64 / dt as f64))).clamp(0.0, 100.0))
    }
}

pub(super) fn get_cpu_temp(cfg: &ConfigStore) -> f64 {
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
    v.as_f64().unwrap_or(0.0)
}

pub(super) fn compute_gpu_fallback(cfg: &ConfigStore) -> Value {
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
    json!({"available": false, "name": "Integrated / Unknown", "busy_pct": Value::Null, "temp_c": Value::Null})
}

pub(super) fn get_memory_info() -> Value {
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
        json!({
            "total_gb": round1(total as f64 / gib),
            "used_gb": round1(used as f64 / gib),
            "percent": pct,
        })
    }
}

pub(super) fn get_swap_info() -> Value {
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
        json!({
            "total_gb": round1(page_total as f64 / gib),
            "used_gb": round1(page_used as f64 / gib),
            "percent": pct,
        })
    }
}

pub(super) fn get_battery_info() -> Value {
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
        json!({"has_battery": false, "has_ups": false, "percent": Value::Null, "status": "AC Desktop", "plugged": true})
    }
}

pub(super) fn compute_mac_addresses(cfg: &ConfigStore) -> Vec<Value> {
    let mut macs = Vec::new();
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
    macs
}

pub(super) fn compute_net_bytes(cfg: &ConfigStore) -> (u64, u64) {
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
}

pub(super) fn compute_os_static() -> Value {
    json!({
        "name": "Windows 10/11",
        "hostname": get_hostname(),
        "kernel": std::env::consts::OS,
    })
}

pub(super) fn uptime_secs() -> Option<u64> {
    unsafe { Some(win_ffi::GetTickCount64() / 1000) }
}

pub(super) fn compute_init_system(_cfg: &ConfigStore) -> String {
    "windows-svc".into()
}

pub(super) fn compute_media_and_display(cfg: &ConfigStore) -> Value {
    let mut vol: i64 = 50;
    let mut muted = false;
    let mut brightness: i64 = 50;
    let mut brightness_backend = "unavailable".to_string();

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
    json!({
        "volume": vol,
        "muted": muted,
        "brightness": brightness,
        "brightness_backend": brightness_backend,
        "media_status": "Windows Media",
        "media_title": "Use Windows media keys",
    })
}

pub(super) fn compute_workspaces_info(_cfg: &ConfigStore, _river_tag: i64) -> Vec<Value> {
    vec![json!({"id": 1, "name": "Desktop", "active": true, "windows": 0})]
}

pub(super) fn compute_disks_info() -> Vec<Value> {
    let mut disks = Vec::new();
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
    }
    disks
}

pub(super) fn compute_boot_entries(cfg: &ConfigStore) -> Vec<Value> {
    let mut entries = Vec::new();
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
    entries
}

pub(super) fn compute_local_ips(_cfg: &ConfigStore) -> Vec<String> {
    let mut ips = Vec::new();
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
    ips
}

pub(super) fn compute_services_info(cfg: &ConfigStore, init_sys: &str) -> Value {
    let mut services = Vec::new();
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
    json!({"init_system": init_sys, "services": services})
}

pub(super) fn get_processes_info(_tel: &TelemetryState, cap: usize) -> Value {
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
            let mem_digits: String = cols[4].chars().filter(|c| c.is_ascii_digit()).collect();
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
    json!({"processes": processes, "total": total})
}

pub(super) fn collect_logs(
    cfg: &ConfigStore,
    src: &str,
    _lvl: &str,
    per_src: usize,
) -> (Vec<String>, Vec<Value>) {
    let available_sources = vec!["mobile-rc".into(), "system".into(), "application".into()];
    let mut entries = Vec::new();
    if src == "all" || src == "mobile-rc" {
        for item in cfg.audit_log_tail(per_src) {
            entries.push(json!(item));
        }
    }
    if src == "all" || src == "system" {
        entries.extend(read_windows_event_logs(cfg, "System", "system", per_src));
    }
    if src == "all" || src == "application" {
        entries.extend(read_windows_event_logs(cfg, "Application", "application", per_src));
    }
    (available_sources, entries)
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

pub(super) fn compute_installed_distros(
    tel: &TelemetryState,
    cfg: &ConfigStore,
    os_info: &Value,
    _deep: bool,
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

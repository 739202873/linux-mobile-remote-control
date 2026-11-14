//! Windows host actions: PowerShell services, taskkill, Win32 input injection, GDI+ screenshots, and app launch.

use super::{escape_sendkeys, val_as_f64, ALLOWED_REMOTE_KEYS};
use crate::config::ConfigStore;
use crate::telemetry::{find_bin, get_desktop_env, run_as_user, run_cmd, win_run_ps, TelemetryState};
use serde_json::Value;
use std::fs;
use std::os::windows::process::CommandExt as WinCommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub(super) fn configure_tunnel_command(cmd: &mut Command) {
    cmd.creation_flags(CREATE_NO_WINDOW);
}

pub(super) fn set_private_file_permissions(_path: &Path) {}

pub(super) fn run_service_action(
    cfg: &ConfigStore,
    _tel: &TelemetryState,
    svc: &str,
    act: &str,
) -> Result<(i32, String, String), String> {
    let verb = match act {
        "start" => "Start-Service",
        "stop" => "Stop-Service -Force",
        "restart" => "Restart-Service -Force",
        _ => return Err("Reload is not supported on Windows services (use restart)".into()),
    };
    let ps = format!("{verb} -Name $env:MRC_SVC_NAME -ErrorAction Stop");
    Ok(win_run_ps(cfg, &ps, 20.0, &[("MRC_SVC_NAME", svc)]))
}

pub(super) fn signal_process(cfg: &ConfigStore, pid_val: i64, sig_key: &str) -> (bool, String) {
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
    (rc == 0, msg)
}

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

pub(super) fn win_send_vk(vk_code: u8, hold_alt: bool) -> bool {
    unsafe {
        if hold_alt {
            win_input_ffi::keybd_event(0x12, 0, 0, 0);
        }
        win_input_ffi::keybd_event(vk_code, 0, 0, 0);
        win_input_ffi::keybd_event(vk_code, 0, 2, 0);
        if hold_alt {
            win_input_ffi::keybd_event(0x12, 0, 2, 0);
        }
    }
    true
}

pub(super) fn win_lock_workstation() -> bool {
    unsafe { win_input_ffi::LockWorkStation() != 0 }
}

pub(super) fn win_dpms_off() -> bool {
    unsafe {
        win_input_ffi::SendMessageW(0xFFFF, 0x0112, 0xF170, 2);
    }
    true
}

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

pub(super) fn send_remote_input(_cfg: &ConfigStore, k: &str, payload: &Value) -> (bool, String) {
    match k {
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
        _ => (false, "Unsupported remote input kind".into()),
    }
}

pub(super) fn adjust_brightness(cfg: &ConfigStore, mode: &str, value: Option<i64>) -> bool {
    let ps = "$b = Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorBrightness -ErrorAction Stop | Select-Object -First 1; $m = Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorBrightnessMethods -ErrorAction Stop | Select-Object -First 1; $cur = [int]$b.CurrentBrightness; $mode = $env:MRC_BRIGHT_MODE; $val = [int]$env:MRC_BRIGHT_VAL; if ($mode -eq 'up') { $target = [Math]::Min(100, $cur + 10) } elseif ($mode -eq 'down') { $target = [Math]::Max(5, $cur - 10) } else { $target = [Math]::Max(5, [Math]::Min(100, $val)) }; $m.WmiSetBrightness(1, $target) | Out-Null; Write-Output $target";
    let val_str = value.unwrap_or(50).to_string();
    let (rc, _, _) = win_run_ps(
        cfg,
        ps,
        4.0,
        &[("MRC_BRIGHT_MODE", mode), ("MRC_BRIGHT_VAL", &val_str)],
    );
    rc == 0
}

pub(super) fn type_prompt_to_active_window(
    cfg: &ConfigStore,
    text: &str,
    auto_enter: bool,
) -> (bool, String) {
    let mut escaped = escape_sendkeys(text);
    if auto_enter {
        escaped.push_str("{ENTER}");
    }
    let ps = "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait($env:MRC_SENDKEYS_PAYLOAD)";
    let (rc, out, err) = win_run_ps(cfg, ps, 6.0, &[("MRC_SENDKEYS_PAYLOAD", &escaped)]);
    if rc == 0 {
        return (true, "SendKeys".into());
    }
    (
        false,
        if !err.is_empty() {
            err
        } else if !out.is_empty() {
            out
        } else {
            "SendKeys failed".into()
        },
    )
}

pub(super) fn spawn_terminal_with_command(cfg: &ConfigStore, cmd_str: &str) -> (bool, String) {
    let env = get_desktop_env(cfg);
    let sp = env.get("PATH").map(String::as_str);
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
            cfg.record_audit_event(
                "INFO",
                format!("Opened Windows terminal ({bin}) with command"),
            );
            return (true, bin.into());
        }
    }
    (false, "No Windows terminal emulator found".into())
}

pub(super) fn capture_desktop_screenshot(
    cfg: &ConfigStore,
    tmpdir: &Path,
) -> Option<(Vec<u8>, &'static str)> {
    let shot_path = tmpdir.join("shot.jpg");
    let shot_str = shot_path.to_string_lossy().into_owned();
    let ps_script = "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; $vs = [System.Windows.Forms.SystemInformation]::VirtualScreen; $bmp = New-Object System.Drawing.Bitmap($vs.Width, $vs.Height); $g = [System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($vs.Left, $vs.Top, 0, 0, $bmp.Size); $scale = [Math]::Min(1.0, [Math]::Min(1280.0 / [Math]::Max(1, $bmp.Width), 800.0 / [Math]::Max(1, $bmp.Height))); $tw = [Math]::Max(1, [int][Math]::Round($bmp.Width * $scale)); $th = [Math]::Max(1, [int][Math]::Round($bmp.Height * $scale)); $outBmp = New-Object System.Drawing.Bitmap($tw, $th); $g2 = [System.Drawing.Graphics]::FromImage($outBmp); $g2.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic; $g2.DrawImage($bmp, 0, 0, $tw, $th); $enc = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' } | Select-Object -First 1; $ep = New-Object System.Drawing.Imaging.EncoderParameters(1); $ep.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality, 75L); $outBmp.Save($env:MRC_SHOT_PATH, $enc, $ep); $g2.Dispose(); $outBmp.Dispose(); $g.Dispose(); $bmp.Dispose()";
    let (rc, _, _) = win_run_ps(cfg, ps_script, 8.0, &[("MRC_SHOT_PATH", &shot_str)]);
    if rc == 0 && fs::metadata(&shot_path).map(|m| m.len()).unwrap_or(0) > 500 {
        fs::read(&shot_path).ok().map(|b| (b, "image/jpeg"))
    } else {
        None
    }
}

pub(super) fn switch_workspace(
    _cfg: &ConfigStore,
    _tel: &TelemetryState,
    _val_num: i64,
) -> Result<(), String> {
    Err("Workspace switching is not supported on Windows".into())
}

pub(super) fn spawn_windows_launch(exe: &str, args: &[&str], new_console: bool) -> bool {
    let mut cmd = Command::new(exe);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if new_console {
        cmd.creation_flags(0x0000_0010); // CREATE_NEW_CONSOLE
    } else {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
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

pub(super) fn win_open_url(url: &str) -> bool {
    spawn_windows_launch("rundll32.exe", &["url.dll,FileProtocolHandler", url], false)
}

//! Linux / Unix host actions: services, POSIX signals, Wayland/X11 input, screenshots, and workspaces.

use super::{val_as_f64, ALLOWED_REMOTE_KEYS};
use crate::config::{chown_path, is_root_or_admin, ConfigStore};
use crate::telemetry::{
    find_bin, get_active_compositor, get_desktop_env, has_internal_backlight, run_as_user, run_cmd,
    run_first_available, run_first_system_cmd, TelemetryState,
};
use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::Ordering;

pub(super) fn configure_tunnel_command(_cmd: &mut Command) {}

pub(super) fn set_private_file_permissions(path: &Path) {
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

pub(super) fn run_service_action(
    cfg: &ConfigStore,
    tel: &TelemetryState,
    svc: &str,
    act: &str,
) -> Result<(i32, String, String), String> {
    let init_sys = tel.detect_init_system(cfg);
    if init_sys == "openrc" && find_bin(cfg, "rc-service", None).is_some() {
        Ok(run_cmd(&["rc-service", svc, act], 20.0))
    } else if init_sys == "systemd" && find_bin(cfg, "systemctl", None).is_some() {
        Ok(run_cmd(&["systemctl", act, svc], 20.0))
    } else if init_sys == "runit" && find_bin(cfg, "sv", None).is_some() {
        let sv_act = if act == "reload" { "hup" } else { act };
        Ok(run_cmd(&["sv", sv_act, svc], 15.0))
    } else {
        Err(format!("Service control not supported on init system '{init_sys}'"))
    }
}

pub(super) fn signal_process(cfg: &ConfigStore, pid_val: i64, sig_key: &str) -> (bool, String) {
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
        match os_err.raw_os_error() {
            Some(e) if e == libc::ESRCH => (false, format!("Process {pid_val} not found")),
            Some(e) if e == libc::EPERM => (false, format!("Permission denied signaling PID {pid_val}")),
            _ => (false, os_err.to_string()),
        }
    }
}

pub(super) fn win_send_vk(_vk_code: u8, _hold_alt: bool) -> bool {
    false
}

pub(super) fn win_lock_workstation() -> bool {
    false
}

pub(super) fn win_dpms_off() -> bool {
    false
}

pub(super) fn spawn_windows_launch(_exe: &str, _args: &[&str], _new_console: bool) -> bool {
    false
}

pub(super) fn win_open_url(_url: &str) -> bool {
    false
}

pub(super) fn send_remote_input(cfg: &ConfigStore, k: &str, payload: &Value) -> (bool, String) {
    let env = get_desktop_env(cfg);
    let sp = env.get("PATH").map(String::as_str);
    let has_ydo = find_bin(cfg, "ydotool", sp).is_some();
    let has_xdo = find_bin(cfg, "xdotool", sp).is_some();
    let has_wtype = find_bin(cfg, "wtype", sp).is_some();

    match k {
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
        _ => (false, "Unsupported remote input kind".into()),
    }
}

pub(super) fn adjust_brightness(cfg: &ConfigStore, mode: &str, value: Option<i64>) -> bool {
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
            return true;
        }
        let sys_cmds: Vec<Vec<&str>> = cmds
            .iter()
            .map(|c| c.iter().map(String::as_str).collect())
            .collect();
        let sys_refs: Vec<&[&str]> = sys_cmds.iter().map(Vec::as_slice).collect();
        let (rc2, _, _) = run_first_system_cmd(cfg, &sys_refs, 8.0);
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
            return rc == 0;
        }
    }
    false
}

pub(super) fn type_prompt_to_active_window(
    cfg: &ConfigStore,
    text: &str,
    auto_enter: bool,
) -> (bool, String) {
    let env = get_desktop_env(cfg);
    let sp = env.get("PATH").map(String::as_str);

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

pub(super) fn spawn_terminal_with_command(cfg: &ConfigStore, cmd_str: &str) -> (bool, String) {
    let env = get_desktop_env(cfg);
    let sp = env.get("PATH").map(String::as_str);

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

pub(super) fn capture_desktop_screenshot(
    cfg: &ConfigStore,
    tmpdir: &Path,
) -> Option<(Vec<u8>, &'static str)> {
    let user = cfg.get_target_user_info();
    if is_root_or_admin() && user.uid != 0 {
        chown_path(tmpdir, user.uid, user.gid);
    }
    let _ = fs::set_permissions(tmpdir, fs::Permissions::from_mode(0o700));

    let raw_path = tmpdir.join("raw.png");
    let shot_path = tmpdir.join("shot.jpg");
    let raw_str = raw_path.to_string_lossy().into_owned();
    let shot_str = shot_path.to_string_lossy().into_owned();

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
}

pub(super) fn switch_workspace(
    cfg: &ConfigStore,
    tel: &TelemetryState,
    val_num: i64,
) -> Result<(), String> {
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
    let niri_cmds = vec![vec![
        "niri".into(),
        "msg".into(),
        "action".into(),
        "focus-workspace".into(),
        s.clone(),
    ]];
    let sway_cmds = vec![vec!["swaymsg".into(), "workspace".into(), s.clone()]];
    let kde_cmds = vec![
        vec![
            "qdbus6".into(),
            "org.kde.KWin".into(),
            "/KWin".into(),
            "org.kde.KWin.setCurrentDesktop".into(),
            s.clone(),
        ],
        vec![
            "qdbus".into(),
            "org.kde.KWin".into(),
            "/KWin".into(),
            "org.kde.KWin.setCurrentDesktop".into(),
            s.clone(),
        ],
        vec![
            "dbus-send".into(),
            "--session".into(),
            "--dest=org.kde.KWin".into(),
            "/KWin".into(),
            "org.kde.KWin.setCurrentDesktop".into(),
            dbus_int,
        ],
        vec!["kdotool".into(), "set_desktop".into(), s],
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
    Ok(())
}

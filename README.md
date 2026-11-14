# Mobile-RC — Cross-Platform Control Center (Linux & Windows)

> [!NOTE]
> **Project Status: Under Active Development**
> Core monitoring, Bento Grid responsive UI, live screen preview, multi-boot switching, process/service manager, paired device management, remote touchpad, Windows 10/11 host support, OTP authentication, and the Pure Rust daemon (`daemon-rs/`, `axum` + `tokio`) with **Hybrid Runtime (`MRC_RUNTIME=auto`)** are live. Native mobile apps (`mobile-app/`) remain under active development.

A lightweight Web Dashboard & remote control daemon (native **Rust `axum` + `tokio`** binary with automatic **Python 3 Standard Library** fallback via Hybrid Metode C) to monitor hardware health (with real-time sparklines), manage processes and system services, inspect logs/OS inventory, preview live desktop screens, and control Linux Desktop PCs, Laptops, Workstations, and **Windows 10/11** machines directly from your smartphone (locally or over the internet).

Universally engineered to work seamlessly across major Linux distributions and desktop environments / window managers.

---

##  Compatibility & Supported Environments

Linux Mobile Control Center is designed to be universal across the entire Linux ecosystem. It auto-detects your active init system, display server, and desktop environment dynamically.

###  Supported Linux Distributions

| Distribution Family | Distros Tested / Supported | Init System | Support Status |
| :--- | :--- | :--- | :---: |
| **Arch Family** | Arch Linux, CachyOS, GarudaOS, EndeavourOS, Manjaro | `systemd` | Supported |
| **Gentoo / Source** | Gentoo Linux, Funtoo | `OpenRC` / `systemd` | Supported |
| **NixOS (Non-FHS)** | NixOS (`flake.nix` & `services.mobile-rc`) | `systemd` (Declarative) | Supported |
| **Debian / Ubuntu** | Ubuntu, Debian, Linux Mint, Pop!_OS, Zorin OS, Kali | `systemd` | Supported |
| **Fedora / RHEL** | Fedora Workstation/Silverblue, RHEL, AlmaLinux, Rocky | `systemd` | Supported |
| **openSUSE** | openSUSE Tumbleweed, openSUSE Leap | `systemd` | Supported |
| **Independent / Minimal**| Alpine Linux, Artix Linux, Chimera Linux, Void Linux | `OpenRC` / `dinit` / `runit` / `systemd` | Supported |
| **Microsoft Windows** | Windows 10, Windows 11 (x64 / ARM64) | `Task Scheduler` (`schtasks`) | Supported |

---

###  Supported Window Managers & Desktop Environments

Linux Mobile Control Center intelligently adapts its screen capture, clipboard synchronization, and window management to match whatever you are running:

#### 1. Wayland Compositors
| Environment | Screen Capture Tool | Window & Workspace Control | Clipboard Tool |
| :--- | :--- | :--- | :--- |
| **Hyprland** | `grim` / `wayshot` | `hyprctl` (`0.57.1+` Lua `hl.dsp.*` & classic syntax) | `wl-copy` |
| **Niri** | `grim` / `wayshot` | `niri msg` (`workspaces`, `focus-workspace`, `fullscreen-window`, `close-window`, `power-off-monitors`) | `wl-copy` |
| **KDE Plasma 6 / 5 (Wayland)** | `spectacle` | `qdbus6` / `qdbus` / `dbus-send` / `kdotool` (KWin desktops, Fullscreen, Close Window, PowerDevil DPMS) | `wl-copy` |
| **River** | `grim` / `wayshot` | `riverctl` (tags 1-9, `toggle-fullscreen`, `close`), `wlopm` | `wl-copy` |
| **Sway / Wayfire / Labwc** | `grim` / `wayshot` | `swaymsg`, `wlopm` | `wl-copy` |
| **GNOME (Wayland)** | `gnome-screenshot` / `spectacle` | `loginctl` | `wl-copy` |

#### 2. X11 Window Managers & Desktop Environments
| Environment | Screen Capture Tool | Window & Workspace Control | Clipboard Tool |
| :--- | :--- | :--- | :--- |
| **Tiling WMs** (`i3`, `bspwm`, `awesome`, `dwm`, `xmonad`) | `maim` / `scrot` / `import` | `wmctrl` (`-d`, `-s`, `-r :ACTIVE: -b toggle,fullscreen`, `-c :ACTIVE:`) / `xdotool` / `xset` | `xclip` / `xsel` |
| **Traditional Desktops** (`XFCE`, `MATE`, `LXQt`, `Cinnamon`) | `maim` / `scrot` / `import` / `spectacle` | `wmctrl` / `xdotool` | `xclip` / `xsel` |
| **KDE Plasma (X11)** / **GNOME (X11)** | `spectacle` / `gnome-screenshot` / `import` | `qdbus6` / `wmctrl` / `xdotool` / `loginctl` | `xclip` / `xsel` |

---

##  Features

- **Bento Grid Responsive UI & Real-Time Telemetry:** Adaptive sidebar rail on desktop/tablet (`>=768px`) and thumb-friendly bottom bar on phones (`<768px`), tabular numbers, 30-point CPU & Network throughput SVG sparklines, visibility-aware polling (`/api/telemetry` every 3.5s, auto-paused when tab hidden), and zero external font/icon CDN requests.
- **Silent Live Screen Preview & Fullscreen Viewer:** Configurable live refresh selector (`Off`, `1s`, `2s`, `5s`), click-to-expand fullscreen desktop view, and dynamic workspace/window controls across Linux compositors (`Hyprland`, `Niri`, `KDE Plasma 6`, `River`, `Sway`, `X11`) and Windows Desktop (`CopyFromScreen`, `F11`, `Alt+F4`, display sleep).
- **System Logs, Live Processes & Service Manager:** Inspect `journalctl`, OpenRC/syslog/dmesg or Windows Event Logs (`System`/`Application`), view top CPU/RAM processes with safe kill confirmation, and `start` / `stop` / `restart` host services (`systemd`, `OpenRC`, `dinit`, `runit`, or Windows Services).
- **Paired Mobile Devices, LAN/WoL & File Sharing:** Revoke paired mobile Bearer tokens on demand, inspect LAN IPs & Wake-on-LAN MAC addresses, upload/download files (`Downloads`), and toggle opt-in HTTPS tunneling (`localhost.run`).
- **Installed OS Scanner & Multi-Boot Switcher:** Inspect UEFI boot entries, `systemd-boot`/`GRUB`, WSL2 distros (on Windows), Btrfs subvolumes, and optional unmounted Linux root probing, paired with safe modal-confirmed Reboot, Shutdown, Lock, Sleep, and UEFI Firmware setup.
- **Media, Volume, Display Brightness & Remote Touchpad:** Control playback, audio volume (`wpctl`/`pactl` on Linux, Windows CoreAudio COM), display brightness (`brightnessctl`/`ddcutil`/`hyprsunset` on Linux, Windows WMI), and low-latency relative cursor/click/scroll/key injection (`ydotool`/`wtype`/`xdotool` on Linux, Win32 `user32` on Windows).
- **On-Demand Random Code (RAC), Device Tokens & Email OTP:** Single-use 6-digit codes (`control-access`), hashed Bearer tokens for native clients, and remote SMTP Email OTP for non-local access.
- **Hybrid Runtime Architecture (Rust + Python 3 Fallback):** `daemon-rs/` compiles into a standalone ~1.9 MiB native binary (`axum` + `tokio`, ~4.6-6.3 MB live RSS on Gentoo OpenRC), while `server.py` (strictly Python 3 Standard Library) stays bundled alongside it so any host runs out-of-the-box with zero external dependencies (`MRC_RUNTIME=auto|rust|python`).

---

##  Project Structure

```text
linux-mobile-remote-control/
├── .github/
│   └── workflows/
│       └── release.yml   # GitHub Actions release builds (Linux x86_64/aarch64 & Windows x64)
├── daemon-rs/            # Native Rust daemon (axum + tokio)
│   ├── Cargo.toml
│   ├── Cargo.lock
│   ├── assets/
│   │   └── index.html    # Embedded Bento web dashboard
│   └── src/
│       ├── main.rs       # Axum HTTP router, streaming I/O & UDP 8001 discovery
│       ├── config.rs     # Settings, TTL/mtime caches & 0600 atomic storage
│       ├── auth.rs       # RAC, sessions, CSRF, device tokens & SMTP/feedback delivery
│       ├── telemetry.rs  # Cross-platform Linux/Windows telemetry, logs & boot entries
│       └── actions.rs    # Shell, input/touchpad, brightness, media, power & tunnels
├── nix/
│   └── module.nix        # Declarative NixOS module (`services.mobile-rc`)
├── flake.nix             # NixOS / Nix Flake package & module definition
├── bin/
│   └── control-access    # Host CLI: random codes, Termux setup, --pair-info & Email OTP
├── termux/
│   └── control-access    # Termux client CLI for smartphone pairing & quick login
├── server.py             # Python 3 stdlib HTTP daemon & fallback runtime
├── install.sh            # Universal Linux hybrid installer (systemd, OpenRC, dinit & runit)
├── update.sh             # Safe Linux hybrid updater (updates unit/runtime & auto-rolls back)
├── uninstall.sh          # Clean Linux uninstaller
├── install.ps1           # Windows 10/11 hybrid installer (Scheduled Task, Firewall & control-access.cmd)
├── update.ps1            # Safe Windows hybrid updater with auto-rollback
├── uninstall.ps1         # Clean Windows uninstaller
├── .gitignore            # Git exclusion rules
├── LICENSE               # MIT License
└── README.md             # Project documentation
```

---

##  Requirements

- **Python 3.8+** (Standard Library only; required for CLI tools & universal `server.py` fallback)
- **Rust / Cargo (optional on host):** Used automatically during `install.sh` / `update.sh` / `install.ps1` / `update.ps1` when compiling `daemon-rs/` from source; when absent, installers attempt to fetch the matching prebuilt binary from GitHub Releases or fall back cleanly to `server.py`
- **Screenshot capture (any of):** `grim` / `wayshot` (Wayland), `spectacle`, `gnome-screenshot`, `maim`, `scrot`, or `import` (`magick` / `convert` / Pillow optional for JPEG resizing)
- **Window / Workspace control (depending on DE/WM):** `hyprctl`, `niri`, `qdbus6`/`qdbus`/`kdotool`, `riverctl`, `swaymsg`, `wlopm`, `wmctrl`, `xdotool`, or `xset`
- **Audio, Backlight & Media:** `wpctl` / `pactl`, `playerctl`, `brightnessctl` / `light`
- **Multi-boot & Tunnel (optional):** `efibootmgr`, `ssh` (for opt-in `localhost.run` reverse tunnel)

---

##  Installation

### Standard Linux (Arch / CachyOS / Gentoo / Void / Artix / Debian / Fedora)

1. Clone this repository to your Linux machine:
   ```bash
   git clone https://github.com/739202873/linux-mobile-remote-control.git
   cd linux-mobile-remote-control
   ```

2. Make scripts executable and run the universal installer:
   ```bash
   chmod +x install.sh update.sh uninstall.sh
   sudo ./install.sh
   ```

3. The installer will automatically detect your init system (**systemd**, **OpenRC**, **dinit**, or **runit**), register the background service, and launch the dashboard on port `8000`.

### Windows 10 / 11 (Administrator PowerShell)

1. Install **Python 3.8+** (`winget install Python.Python.3.12`) and clone this repository:
   ```powershell
   git clone https://github.com/739202873/linux-mobile-remote-control.git
   cd linux-mobile-remote-control
   ```
2. Run the PowerShell installer as **Administrator**:
   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass -Force
   .\install.ps1
   ```
3. To update or uninstall later:
   ```powershell
   .\update.ps1
   .\uninstall.ps1
   ```

The Windows installer configures `%ProgramData%\Mobile-RC`, opens Windows Firewall TCP `8000` / UDP `8001`, registers interactive Scheduled Task `Mobile-RC`, and installs `control-access.cmd` into `System32`.

### NixOS (Declarative Flake Module)

Because NixOS uses an immutable non-FHS layout, add this repository as a flake input and enable the included NixOS module (`services.mobile-rc`):

```nix
# flake.nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    mobile-rc.url = "github:739202873/linux-mobile-remote-control";
  };

  outputs = { nixpkgs, mobile-rc, ... }: {
    nixosConfigurations.your-host = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ./configuration.nix
        mobile-rc.nixosModules.default
        {
          services.mobile-rc = {
            enable = true;
            openFirewall = true; # opens TCP port 8000 on LAN
            # user = "youruser"; # optional override for MRC_USER
          };
        }
      ];
    };
  };
}
```

Then rebuild and switch:
```bash
sudo nixos-rebuild switch --flake .#your-host
sudo control-access
```

---

##  Accessing the Dashboard

### 1. Local Network (Same Wi-Fi / Hotspot)
Open your smartphone browser and navigate to:
```text
http://<HOST_IP>:8000
```
*(Example: `http://192.168.1.15:8000` or `http://10.11.5.233:8000`)*

### 2. Termux CLI & Random One-Time Codes (RAC)
Mobile-RC uses **on-demand random 6-digit codes (RAC)** by default (codes expire in 180s, are invalidated immediately after one login, and **no secret token is stored on your smartphone**):
1. On your PC/Laptop, print the one-line Termux setup command:
   ```bash
   sudo control-access --setup-termux
   ```
2. Paste that command once into **Termux** on your smartphone to install the token-free `control-access` helper.
3. Whenever you want to log in from your phone, run `control-access` in Termux (or open the web URL directly):
   - **Same Network (Local LAN)**: Run `sudo control-access` on your PC/Laptop to display a 6-digit RAC, enter that 6-digit RAC in Termux (`control-access` or `control-access <6-DIGIT-RAC>`) or in the web login box, and it **automatically logs in and opens the dashboard**.
   - **Different Network (Non-Local / Online)**: `control-access` in Termux (or the web login screen) prompts for your registered email address, sends a 6-digit RAC to your email inbox, and **automatically logs in and opens the dashboard** once you enter that code.
   - Useful Termux subcommands: `control-access status` (list saved URLs and email), `control-access add-url <URL>`, or `control-access <URL>`. To use a fixed PIN on local LAN instead, set `"pin_mode": "static"` in `/opt/mobile-rc/config.json` or `MRC_PIN` env var.

### 3. Over the Internet (Opt-In Tunnel / Online Email OTP)
For security, the internet tunnel is **disabled by default**. When you explicitly start it from the rightmost **Net & Feed** tab (or set `MRC_AUTO_TUNNEL=1` / `"auto_tunnel": true` in `/opt/mobile-rc/config.json`), `server.py` opens an HTTPS tunnel (`localhost.run`) and publishes the active link to the private random notification portal generated during installation:
```text
https://ntfy.sh/<your-generated-topic>
```
Check your installer output or `/opt/mobile-rc/config.json` (`ntfy_topic`) on your PC.

To log in via **one-time Email OTP** whenever you open the dashboard from a non-local / internet tunnel URL (detected automatically via proxy headers or non-local host/IP), run once on your PC:
```bash
sudo control-access --setup-email
sudo control-access --test-email   # optional: test SMTP delivery anytime
```
Use a dedicated Gmail account with **2-Step Verification** enabled and a **16-character Google App Password**, then list allowed recipient email(s). On remote connections, the login screen automatically displays the Email OTP input and only sends codes to whitelisted recipients (with per-IP cooldown and hourly send limits).

> **Tip:** In Chrome or Safari on your phone, tap **"Add to Home Screen"** to use Mobile-RC as a fullscreen Progressive Web App (PWA)!

---

##  Configuration & Environment Variables

Runtime configuration and secrets are stored outside the repository in `/opt/mobile-rc/config.json` (mode `0600`). Optional environment variable overrides:

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `MRC_PORT` | `8000` | HTTP server listen port |
| `MRC_USER` | Detected desktop user | Target user for Wayland/X11, audio, files & commands |
| `MRC_CONFIG_DIR` | `/opt/mobile-rc` | Config, PIN, and SSH key directory |
| `MRC_PIN` | *(unset)* | Forces `static` PIN mode with supplied PIN |
| `MRC_CODE_TTL` | `180` | One-time code lifetime in seconds (`30`-`600`) |
| `MRC_DISABLE_SHELL` | `0` | Set to `1` to disable Quick Web Terminal execution |
| `MRC_AUTO_TUNNEL` | `0` | Set to `1` to start the remote SSH tunnel on boot |
| `MRC_MAX_UPLOAD_MB` | `500` | Max file upload size in MiB |
| `MRC_EMAIL_COOLDOWN` | `30` | Minimum seconds between Email OTP / feedback requests per IP (min `10`) |
| `MRC_EMAIL_HOURLY_MAX` | `12` | Max Email OTP / feedback emails sent per hour (min `3`) |
| `MRC_FEEDBACK_EMAIL` | `brypra4@gmail.com` | Destination inbox for Feedback & Bug Report form when using local SMTP |
| `MRC_FEEDBACK_WEBHOOK` | *(unset)* | Optional HTTPS webhook URL (e.g. Web3Forms/Formspree) for zero-SMTP feedback relay |
| `MRC_RUNTIME` | `auto` | Runtime engine selection: `auto` (use/build native Rust binary if available, else Python `server.py`), `rust`, or `python` |
| `MRC_DISCOVERY` | `1` | Set to `0` to disable background LAN UDP auto-discovery listener |

---

##  Service & Boot Auto-Start Control

Manage the background service and boot auto-start (supports systemd, OpenRC, dinit, and runit) directly with `control-access`:

```bash
control-access --status              # check running state & boot auto-start
sudo control-access --disable        # disable auto-start on boot (keep manual)
sudo control-access --disable --stop # disable auto-start & stop service now
sudo control-access --enable --start # re-enable auto-start & start now
sudo control-access --start          # start manually
sudo control-access --stop           # stop manually
sudo control-access --restart        # restart service
```

---

##  Updating

To pull the latest updates, resolve the active hybrid runtime (native Rust binary when available, or Python `server.py` fallback), and safely restart the background service while preserving your existing PIN, configuration, and SSH keys:
```bash
sudo ./update.sh
```
To explicitly switch runtimes on an existing installation:
```bash
sudo MRC_RUNTIME=python ./update.sh --no-pull   # switch service launcher to server.py
sudo MRC_RUNTIME=rust ./update.sh --no-pull     # build/install and activate native mobile-rc
```

---

##  Uninstallation

To cleanly stop and remove the service and files from your system:
```bash
sudo ./uninstall.sh
```

---

##  License

This project is licensed under the [MIT License](LICENSE).

# Linux Mobile Control Center 

A lightweight, zero-dependency Web Dashboard written in pure Python 3 to monitor hardware health, preview desktop screens, and control multi-boot Linux machines directly from your smartphone or web browser (locally or over the internet).

Universally engineered to work seamlessly across major Linux distributions and desktop environments / window managers.

---

##  Compatibility & Supported Environments

Linux Mobile Control Center is designed to be universal across the entire Linux ecosystem. It auto-detects your active init system, display server, and desktop environment dynamically.

###  Supported Linux Distributions

| Distribution Family | Distros Tested / Supported | Init System | Support Status |
| :--- | :--- | :--- | :---: |
| **Arch Family** | Arch Linux, GarudaOS, EndeavourOS, Manjaro | `systemd` | ✅ Fully Supported |
| **Gentoo / Source** | Gentoo Linux, Funtoo | `OpenRC` / `systemd` | ✅ Fully Supported |
| **Debian / Ubuntu** | Ubuntu, Debian, Linux Mint, Pop!_OS, Zorin OS, Kali | `systemd` | ✅ Fully Supported |
| **Fedora / RHEL** | Fedora Workstation/Silverblue, RHEL, AlmaLinux, Rocky | `systemd` | ✅ Fully Supported |
| **openSUSE** | openSUSE Tumbleweed, openSUSE Leap | `systemd` | ✅ Fully Supported |
| **Independent / Minimal**| Alpine Linux, Artix Linux, Void Linux | `OpenRC` / `systemd` / `runit` | ✅ Supported |

---

###  Supported Window Managers & Desktop Environments

Linux Mobile Control Center intelligently adapts its screen capture, clipboard synchronization, and window management to match whatever you are running:

#### 1. Wayland Compositors
| Environment | Screen Capture Tool | Window & Workspace Control | Clipboard Tool |
| :--- | :--- | :--- | :--- |
| **Hyprland** | `grim` (PIL / ImageMagick compression) | `hyprctl` (`0.57.1+` Lua `hl.dsp.*` and classic syntax) | `wl-copy` |
| **KDE Plasma 6 / 5 (Wayland)** | `spectacle` (background CLI mode) | `hyprctl` / `swaymsg` / `wmctrl` / `xdotool` (XWayland) | `wl-copy` |
| **Sway / Wayfire / River** | `grim` | `swaymsg` / `wlopm` | `wl-copy` |
| **GNOME (Wayland)** | `gnome-screenshot` / `spectacle` | `loginctl` | `wl-copy` |

#### 2. X11 Window Managers & Desktop Environments
| Environment | Screen Capture Tool | Window & Workspace Control | Clipboard Tool |
| :--- | :--- | :--- | :--- |
| **Tiling WMs** (`i3`, `bspwm`, `awesome`, `dwm`, `xmonad`) | `maim` / `scrot` / `import` | `wmctrl` / `xdotool` / `xset` | `xclip` / `xsel` |
| **Traditional Desktops** (`XFCE`, `MATE`, `LXQt`, `Cinnamon`) | `maim` / `scrot` / `import` / `spectacle` | `wmctrl` / `xdotool` | `xclip` / `xsel` |
| **KDE Plasma (X11)** / **GNOME (X11)** | `spectacle` / `gnome-screenshot` / `import` | `wmctrl` / `xdotool` / `loginctl` | `xclip` / `xsel` |

---

##  Features

- **Real-time System Monitor:** Live telemetry of CPU load, CPU temperatures, RAM usage, battery status, and disk partitions (NVMe, SATA, LVM/LUKS).
- **Silent Live Screen Preview & Dynamic Workspaces:** Auto-refreshing desktop preview (`Live ON / PAUSED` toggle) without switching windows or tabs on the laptop, paired with dynamic workspace buttons matching active PC workspaces (wrapping below after 4 columns) plus Fullscreen, Screen On/Off (DPMS), and Close App controls supporting Hyprland `0.57.1+` Lua API (`hl.dsp.*`), classic Hyprland, Sway, `wlopm`, `wmctrl`, `xdotool`, and `xset`.
- **Multi-Boot OS Switcher:** One-click instant reboot to any installed OS using UEFI NVRAM (`efibootmgr -n`), reboot into BIOS/UEFI firmware, lock screen, reboot, or shut down.
- **Media, Volume & Brightness Remote:** Control system volume (slider, +/-5%, mute), screen brightness backlight (`brightnessctl` / `light`), and media playback (Play/Pause/Next/Prev) via `playerctl`, `wpctl`, and `pactl`.
- **Bi-directional File Sharing:** Upload files from smartphone to PC `~/Downloads` and download PC files with filename sanitization.
- **Remote Input & Web Terminal:** Send desktop notifications (`notify-send` / `hyprctl notify`), paste text into Wayland/X11 clipboards, open HTTP/HTTPS URLs on the PC browser, launch preset apps, and run remote terminal commands (`MRC_DISABLE_SHELL=1` to disable).
- **On-Demand Random Code & Online Email OTP:** Random single-use 6-digit codes generated on demand via Termux (`control-access`) or PC (`sudo control-access`), backed by brute-force lockout, `HttpOnly` sessions, Origin checks, and CSRF tokens. When accessed remotely via a tunnel or non-local host, the login screen automatically offers one-time **Email OTP** delivery over SMTP (`STARTTLS` / `SMTP_SSL`, e.g. Gmail + App Password) restricted to whitelisted recipient emails.
- **Zero External Python Dependencies:** Built entirely on the Python 3 Standard Library.

---

##  Project Structure

```text
linux-mobile-remote-control/
├── bin/
│   └── control-access    # Host CLI: random codes, Termux setup & Email OTP wizard
├── termux/
│   └── control-access    # Termux client CLI for smartphone pairing & quick login
├── server.py             # Core HTTP API server & web dashboard UI (Pure Python 3)
├── install.sh            # Universal system installer (auto-detects systemd & OpenRC)
├── update.sh             # Safe updater script (preserves tokens, config & SSH keys)
├── uninstall.sh          # Clean uninstaller script
├── .gitignore            # Git exclusion rules
├── LICENSE               # MIT License
└── README.md             # Project documentation
```

---

##  Requirements

- **Python 3.8+** (Standard Library only)
- **Screenshot capture (any of):** `grim` (Wayland), `spectacle`, `gnome-screenshot`, `maim`, `scrot`, or `import` (`magick` / `convert` / Pillow optional for JPEG resizing)
- **Window / Workspace control (depending on DE/WM):** `hyprctl`, `swaymsg`, `wlopm`, `wmctrl`, `xdotool`, or `xset`
- **Audio, Backlight & Media:** `wpctl` / `pactl`, `playerctl`, `brightnessctl` / `light`
- **Multi-boot & Tunnel (optional):** `efibootmgr`, `ssh` (for opt-in `localhost.run` reverse tunnel)

---

##  Installation

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

3. The installer will automatically detect your init system (**systemd** or **OpenRC**), register the background service, and launch the dashboard on port `8000`.

---

##  Accessing the Dashboard

### 1. Local Network (Same Wi-Fi / Hotspot)
Open your smartphone browser and navigate to:
```text
http://<LAPTOP_IP>:8000
```
*(Example: `http://192.168.1.15:8000` or `http://10.11.5.233:8000`)*

### 2. Termux Pairing & Random One-Time Codes
Mobile-RC uses **on-demand random codes** by default (codes expire in 180s and are invalidated immediately after one login):
1. On your PC, print the one-line Termux setup command:
   ```bash
   sudo control-access --setup-termux
   ```
2. Paste that command once into **Termux** on your smartphone.
3. Whenever you want to log in from your phone, run in Termux:
   ```bash
   control-access          # generate code
   control-access --open   # generate code & open dashboard URL
   ```
   Useful Termux subcommands: `control-access status` (list saved URLs), `control-access add-url <URL>`, or `control-access <URL>`. On the PC directly, run `sudo control-access`. To use a fixed PIN instead, set `"pin_mode": "static"` in `/opt/mobile-rc/config.json` or `MRC_PIN` env var.

### 3. Over the Internet (Opt-In Tunnel / Online Email OTP)
For security, the internet tunnel is **disabled by default**. When you explicitly start it from the **Files & Net** tab (or set `MRC_AUTO_TUNNEL=1` / `"auto_tunnel": true` in `/opt/mobile-rc/config.json`), `server.py` opens an HTTPS tunnel (`localhost.run`) and publishes the active link to the private random notification portal generated during installation:
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
| `MRC_EMAIL_COOLDOWN` | `30` | Minimum seconds between Email OTP requests per IP (min `10`) |
| `MRC_EMAIL_HOURLY_MAX` | `12` | Max Email OTP messages sent per hour (min `3`) |

---

##  Updating

To pull the latest updates and safely restart the background service while preserving your existing PIN, configuration, and SSH keys:
```bash
sudo ./update.sh
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

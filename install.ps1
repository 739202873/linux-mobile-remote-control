<#
.SYNOPSIS
Mobile-RC Cross-Platform Control Center - Windows 10/11 Installer
Supports zero-pip Python stdlib runtime and Hybrid native Rust binary resolution (Metode C).
#>
[CmdletBinding()]
param(
    [ValidateSet("auto", "python", "rust")]
    [string]$Runtime = $(if ($env:MRC_RUNTIME) { $env:MRC_RUNTIME } else { "auto" }),
    [int]$Port = $(if ($env:MRC_PORT) { [int]$env:MRC_PORT } else { 8000 })
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "Error: Please run this installer from an Administrator PowerShell terminal." -ForegroundColor Red
        exit 1
    }
}

function Resolve-Python {
    foreach ($cand in @("python", "python3")) {
        $cmd = Get-Command $cand -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source -notlike "*\WindowsApps\*") {
            try {
                $ver = & $cmd.Source -c "import sys; print(1 if sys.version_info >= (3,8) else 0)" 2>$null
                if ($ver -eq "1") { return @{ Exe = $cmd.Source; Args = @() } }
            } catch {}
        }
    }
    $pyLauncher = Get-Command "py" -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        try {
            $exePath = & $pyLauncher.Source -3 -c "import sys; print(sys.executable if sys.version_info >= (3,8) else '')" 2>$null
            if ($exePath -and (Test-Path $exePath)) {
                return @{ Exe = $exePath.Trim(); Args = @() }
            }
        } catch {}
    }
    return $null
}

function Resolve-DesktopUser {
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($cs -and $cs.UserName) {
            return $cs.UserName
        }
    } catch {}
    if ($env:USERDOMAIN -and $env:USERNAME) {
        return "$($env:USERDOMAIN)\$($env:USERNAME)"
    }
    return $env:USERNAME
}

Assert-Admin

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$InstallDir = Join-Path $env:ProgramData "Mobile-RC"
$TargetUser = Resolve-DesktopUser
$TargetUserLeaf = ($TargetUser -split "\\")[-1]

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "   Mobile-RC - Windows 10/11 Automated Installer" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "Target Desktop User : $TargetUser"

$PyInfo = Resolve-Python
if (-not $PyInfo) {
    Write-Host "Error: Python 3.8+ was not found in PATH." -ForegroundColor Red
    Write-Host "Install Python 3 from https://www.python.org/downloads/ (check 'Add python.exe to PATH') or 'winget install Python.Python.3.12'." -ForegroundColor Yellow
    exit 1
}
$PythonExe = $PyInfo.Exe
Write-Host "Python Runtime      : $PythonExe" -ForegroundColor Green

if (-not (Test-Path (Join-Path $ScriptDir "server.py"))) {
    Write-Host "Error: server.py not found next to install.ps1." -ForegroundColor Red
    exit 1
}

Write-Host "1. Creating installation directory and copying files..." -ForegroundColor Blue
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item (Join-Path $ScriptDir "server.py") (Join-Path $InstallDir "server.py") -Force
if (Test-Path (Join-Path $ScriptDir "bin\control-access")) {
    Copy-Item (Join-Path $ScriptDir "bin\control-access") (Join-Path $InstallDir "control-access.py") -Force
}

$Env:MRC_CONFIG_DIR = $InstallDir

# Restrict ACL cleanly to Administrators, SYSTEM, and active desktop user
try {
    & icacls $InstallDir /inheritance:r /grant:r "BUILTIN\Administrators:(OI)(CI)F" "NT AUTHORITY\SYSTEM:(OI)(CI)F" "${TargetUser}:(OI)(CI)F" | Out-Null
} catch {}

# Metode C: Hybrid native Rust resolution (falls back cleanly to server.py)
$UseRust = ($Runtime -in @("auto", "rust")) -and ($env:MRC_USE_RUST -ne "0")
if (-not $env:MRC_RUNTIME -and ($env:MRC_USE_RUST -eq "1")) { $UseRust = $true }
$TaskExe = $PythonExe
$TaskArg = "`"$InstallDir\server.py`""
$RustOut = Join-Path $InstallDir "mobile-rc.exe"

if ($UseRust) {
    Stop-ScheduledTask -TaskName "Mobile-RC" -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like "*Mobile-RC\server.py*" -or $_.ExecutablePath -like "*Mobile-RC\mobile-rc.exe" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 400

    $LocalRust = Join-Path $ScriptDir "daemon-rs\target\release\mobile-rc.exe"
    $CargoToml = Join-Path $ScriptDir "daemon-rs\Cargo.toml"
    $RustReady = $false
    if ((Test-Path $CargoToml) -and (Get-Command "cargo" -ErrorAction SilentlyContinue)) {
        Write-Host "   Building native Rust daemon (cargo build --release)..." -ForegroundColor Blue
        try { & cargo build --release --manifest-path $CargoToml } catch {}
        if (Test-Path $LocalRust) {
            Copy-Item $LocalRust $RustOut -Force
            $RustReady = $true
        }
    }
    if (-not $RustReady -and (Test-Path $LocalRust)) {
        Copy-Item $LocalRust $RustOut -Force
        $RustReady = $true
    }
    if (-not $RustReady) {
        try {
            $dlUrl = "https://github.com/739202873/linux-mobile-remote-control/releases/latest/download/mobile-rc-windows-x86_64.exe"
            Invoke-WebRequest -Uri $dlUrl -OutFile "$RustOut.tmp" -UseBasicParsing -TimeoutSec 20 -ErrorAction Stop
            Move-Item "$RustOut.tmp" $RustOut -Force
            $RustReady = $true
        } catch {
            Remove-Item "$RustOut.tmp" -Force -ErrorAction SilentlyContinue
        }
    }
    if ($RustReady -and (Test-Path $RustOut)) {
        $TaskExe = $RustOut
        $TaskArg = ""
        Write-Host "   Using Hybrid native runtime: $RustOut" -ForegroundColor Green
    } else {
        Write-Host "   Native Rust binary unavailable; using Python server.py runtime." -ForegroundColor Yellow
    }
}

Write-Host "2. Initializing secure configuration..." -ForegroundColor Blue
$CfgPath = Join-Path $InstallDir "config.json"
$PinPath = Join-Path $InstallDir "pin.txt"
$InitScript = @'
import json, os, secrets, sys
cfg_path, pin_path, target_user = sys.argv[1], sys.argv[2], sys.argv[3]
cfg = {}
if os.path.exists(cfg_path):
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                cfg = data
    except Exception:
        cfg = {}
if not cfg.get("ntfy_topic"):
    cfg["ntfy_topic"] = f"mobile-rc-{secrets.token_hex(12)}"
cfg["target_user"] = target_user
cfg.pop("user", None)
cfg.setdefault("auto_tunnel", False)
cfg.setdefault("pin_mode", "on_demand")
if not cfg.get("termux_token"):
    cfg["termux_token"] = secrets.token_urlsafe(32)
with open(cfg_path, "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
if cfg["pin_mode"] == "on_demand" and os.path.exists(pin_path):
    try: os.remove(pin_path)
    except OSError: pass
print(cfg["ntfy_topic"])
print(cfg["pin_mode"])
'@
$InitLines = ($InitScript | & $PythonExe -B - $CfgPath $PinPath $TargetUserLeaf)
$NtfyTopic = if ($InitLines -is [array] -and $InitLines.Length -ge 1) { $InitLines[0] } else { "" }
$PinMode = if ($InitLines -is [array] -and $InitLines.Length -ge 2) { $InitLines[1] } else { "on_demand" }

Write-Host "3. Installing control-access CLI wrapper..." -ForegroundColor Blue
$CmdContent = "@echo off`r`nset `"MRC_CONFIG_DIR=$InstallDir`"`r`nset `"MRC_PORT=$Port`"`r`n`"$PythonExe`" -B `"$InstallDir\control-access.py`" %*`r`n"
$LocalCmd = Join-Path $InstallDir "control-access.cmd"
$Sys32Cmd = Join-Path $env:SystemRoot "System32\control-access.cmd"
Set-Content -Path $LocalCmd -Value $CmdContent -Encoding Ascii
Set-Content -Path $Sys32Cmd -Value $CmdContent -Encoding Ascii

Write-Host "4. Configuring Windows Firewall & Scheduled Task..." -ForegroundColor Blue
Remove-NetFirewallRule -DisplayName "Mobile-RC HTTP (TCP $Port)" -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName "Mobile-RC Discovery (UDP 8001)" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Mobile-RC HTTP (TCP $Port)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -Profile Any | Out-Null
New-NetFirewallRule -DisplayName "Mobile-RC Discovery (UDP 8001)" -Direction Inbound -Action Allow -Protocol UDP -LocalPort 8001 -Profile Any | Out-Null

# Stop existing process/task before re-registering
Unregister-ScheduledTask -TaskName "Mobile-RC" -Confirm:$false -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*Mobile-RC\server.py*" -or $_.ExecutablePath -like "*Mobile-RC\mobile-rc.exe" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

$Action = if ($TaskArg) {
    New-ScheduledTaskAction -Execute $TaskExe -Argument $TaskArg -WorkingDirectory $InstallDir
} else {
    New-ScheduledTaskAction -Execute $TaskExe -WorkingDirectory $InstallDir
}
$TriggerLogon = New-ScheduledTaskTrigger -AtLogOn -User $TargetUser
$Principal = New-ScheduledTaskPrincipal -UserId $TargetUser -LogonType Interactive -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Days 3650) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName "Mobile-RC" -Action $Action -Trigger $TriggerLogon -Principal $Principal -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName "Mobile-RC"

Start-Sleep -Seconds 2
$LanIPs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.IPAddress -notlike "169.254.*" } |
    Select-Object -ExpandProperty IPAddress
$PrimaryIP = if ($LanIPs) { ($LanIPs | Select-Object -First 1) } else { "127.0.0.1" }

Write-Host ""
Write-Host "====================================================" -ForegroundColor Green
Write-Host "   Mobile-RC Installed on Windows!" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green
Write-Host "   Dashboard URL   : http://${PrimaryIP}:${Port}" -ForegroundColor Cyan
Write-Host "   Config Dir      : $InstallDir"
Write-Host "   PIN Mode        : $PinMode"
Write-Host "   Generate Code   : control-access" -ForegroundColor Yellow
Write-Host "   Setup Email OTP : control-access --setup-email" -ForegroundColor Yellow
Write-Host "   Service Status  : control-access --status" -ForegroundColor Yellow
if ($NtfyTopic) {
    Write-Host "   Remote ntfy     : https://ntfy.sh/$NtfyTopic" -ForegroundColor Cyan
}
Write-Host "====================================================" -ForegroundColor Green

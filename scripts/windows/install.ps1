<#
.SYNOPSIS
Mobile-RC Cross-Platform Control Center - Windows 10/11 Installer
Supports zero-pip Python stdlib runtime and Hybrid native Rust binary resolution.
#>
[CmdletBinding()]
param(
    [ValidateSet("auto", "python", "rust")]
    [string]$Runtime = $(if ($env:MRC_RUNTIME) { $env:MRC_RUNTIME } else { "auto" }),
    [int]$Port = $(if ($env:MRC_PORT) { [int]$env:MRC_PORT } else { 8000 })
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common.ps1")

Assert-MrcAdmin -ScriptName "install.ps1"

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$InstallDir = Join-Path $env:ProgramData "Mobile-RC"
$TargetUser = Resolve-MrcDesktopUser
$TargetUserLeaf = ($TargetUser -split "\\")[-1]

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "   Mobile-RC - Windows 10/11 Automated Installer" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "Target Desktop User : $TargetUser"

$PythonExe = Resolve-MrcPython
if (-not $PythonExe) {
    Write-Host "Error: Python 3.8+ was not found in PATH." -ForegroundColor Red
    Write-Host "Install Python 3 from https://www.python.org/downloads/ (check 'Add python.exe to PATH') or 'winget install Python.Python.3.12'." -ForegroundColor Yellow
    exit 1
}
Write-Host "Python Runtime      : $PythonExe" -ForegroundColor Green

$SrcServer = Join-Path $RepoRoot "fallback\server.py"
if (-not (Test-Path $SrcServer)) {
    Write-Host "Error: fallback\server.py not found in $RepoRoot." -ForegroundColor Red
    exit 1
}

Write-Host "1. Creating installation directory and copying files..." -ForegroundColor Blue
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item $SrcServer (Join-Path $InstallDir "server.py") -Force
if (Test-Path (Join-Path $RepoRoot "bin\control-access")) {
    Copy-Item (Join-Path $RepoRoot "bin\control-access") (Join-Path $InstallDir "control-access.py") -Force
}

$Env:MRC_CONFIG_DIR = $InstallDir

try {
    & icacls $InstallDir /inheritance:r /grant:r "BUILTIN\Administrators:(OI)(CI)F" "NT AUTHORITY\SYSTEM:(OI)(CI)F" "${TargetUser}:(OI)(CI)F" | Out-Null
} catch {}

Stop-MrcRunningProcesses
Start-Sleep -Milliseconds 400

$RtInfo = Resolve-MrcRuntime -RepoRoot $RepoRoot -InstallDir $InstallDir -PythonExe $PythonExe -RuntimeMode $Runtime
if (-not $RtInfo.Success) {
    exit 1
}
Write-MrcRuntimeMarker -InstallDir $InstallDir -RuntimeName $RtInfo.Name

Write-Host "2. Initializing secure configuration..." -ForegroundColor Blue
$Meta = Sync-MrcMetadata -PythonExe $PythonExe -InstallDir $InstallDir -TargetUserLeaf $TargetUserLeaf

Write-Host "3. Installing control-access CLI wrapper..." -ForegroundColor Blue
$CmdContent = "@echo off`r`nset `"MRC_CONFIG_DIR=$InstallDir`"`r`nset `"MRC_PORT=$Port`"`r`n`"$PythonExe`" -B `"$InstallDir\control-access.py`" %*`r`n"
Set-Content -Path (Join-Path $InstallDir "control-access.cmd") -Value $CmdContent -Encoding Ascii
Set-Content -Path (Join-Path $env:SystemRoot "System32\control-access.cmd") -Value $CmdContent -Encoding Ascii

Write-Host "4. Configuring Windows Firewall & Scheduled Task..." -ForegroundColor Blue
Remove-NetFirewallRule -DisplayName "Mobile-RC HTTP (TCP $Port)" -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName "Mobile-RC Discovery (UDP 8001)" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Mobile-RC HTTP (TCP $Port)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -Profile Any | Out-Null
New-NetFirewallRule -DisplayName "Mobile-RC Discovery (UDP 8001)" -Direction Inbound -Action Allow -Protocol UDP -LocalPort 8001 -Profile Any | Out-Null

Unregister-ScheduledTask -TaskName "Mobile-RC" -Confirm:$false -ErrorAction SilentlyContinue
Stop-MrcRunningProcesses

$Action = if ($RtInfo.Arg) {
    New-ScheduledTaskAction -Execute $RtInfo.Exe -Argument $RtInfo.Arg -WorkingDirectory $InstallDir
} else {
    New-ScheduledTaskAction -Execute $RtInfo.Exe -WorkingDirectory $InstallDir
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
Write-Host "   Runtime Engine  : $($RtInfo.Label)" -ForegroundColor Cyan
Write-Host "   Dashboard URL   : http://${PrimaryIP}:${Port}" -ForegroundColor Cyan
Write-Host "   Config Dir      : $InstallDir"
Write-Host "   PIN Mode        : $($Meta.PinMode)"
Write-Host "   Generate Code   : control-access" -ForegroundColor Yellow
Write-Host "   Setup Email OTP : control-access --setup-email" -ForegroundColor Yellow
Write-Host "   Service Status  : control-access --status" -ForegroundColor Yellow
if ($Meta.NtfyTopic) {
    Write-Host "   Remote ntfy     : https://ntfy.sh/$($Meta.NtfyTopic)" -ForegroundColor Cyan
}
Write-Host "====================================================" -ForegroundColor Green

<#
.SYNOPSIS
Mobile-RC Cross-Platform Control Center - Windows 10/11 Uninstaller
#>
$ErrorActionPreference = "SilentlyContinue"

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Error: Please run uninstall.ps1 from an Administrator PowerShell terminal." -ForegroundColor Red
    exit 1
}

Write-Host "Stopping and removing Mobile-RC from Windows..." -ForegroundColor Red

Stop-ScheduledTask -TaskName "Mobile-RC"
Unregister-ScheduledTask -TaskName "Mobile-RC" -Confirm:$false

Get-CimInstance Win32_Process |
    Where-Object { $_.CommandLine -like "*Mobile-RC\server.py*" -or $_.ExecutablePath -like "*Mobile-RC\mobile-rc.exe" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force }

Get-NetFirewallRule -DisplayName "Mobile-RC*" | Remove-NetFirewallRule

$InstallDir = Join-Path $env:ProgramData "Mobile-RC"
$Sys32Cmd = Join-Path $env:SystemRoot "System32\control-access.cmd"

if (Test-Path $Sys32Cmd) { Remove-Item $Sys32Cmd -Force }
if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }

Write-Host "Mobile-RC has been completely removed." -ForegroundColor Green

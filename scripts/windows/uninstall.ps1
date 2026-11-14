<#
.SYNOPSIS
Mobile-RC Cross-Platform Control Center - Windows 10/11 Uninstaller
#>
$ErrorActionPreference = "SilentlyContinue"
. (Join-Path $PSScriptRoot "common.ps1")

Assert-MrcAdmin -ScriptName "uninstall.ps1"

Write-Host "Stopping and removing Mobile-RC from Windows..." -ForegroundColor Red

Unregister-ScheduledTask -TaskName "Mobile-RC" -Confirm:$false
Stop-MrcRunningProcesses

Get-NetFirewallRule -DisplayName "Mobile-RC*" | Remove-NetFirewallRule

$InstallDir = Join-Path $env:ProgramData "Mobile-RC"
$Sys32Cmd = Join-Path $env:SystemRoot "System32\control-access.cmd"

if (Test-Path $Sys32Cmd) { Remove-Item $Sys32Cmd -Force }
if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }

Write-Host "Mobile-RC has been completely removed." -ForegroundColor Green

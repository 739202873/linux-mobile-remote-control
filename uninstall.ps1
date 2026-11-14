<#
.SYNOPSIS
Mobile-RC Cross-Platform Control Center - Windows 10/11 Uninstaller Entrypoint
#>
& (Join-Path $PSScriptRoot "scripts\windows\uninstall.ps1") @args
exit $LASTEXITCODE

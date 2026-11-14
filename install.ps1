<#
.SYNOPSIS
Mobile-RC Cross-Platform Control Center - Windows 10/11 Installer Entrypoint
#>
[CmdletBinding()]
param(
    [ValidateSet("auto", "python", "rust")]
    [string]$Runtime = $(if ($env:MRC_RUNTIME) { $env:MRC_RUNTIME } else { "auto" }),
    [int]$Port = $(if ($env:MRC_PORT) { [int]$env:MRC_PORT } else { 8000 })
)
& (Join-Path $PSScriptRoot "scripts\windows\install.ps1") @PSBoundParameters
exit $LASTEXITCODE

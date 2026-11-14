<#
.SYNOPSIS
Mobile-RC Cross-Platform Control Center - Windows 10/11 Updater
Preserves config.json, validates syntax before restarting, and rolls back automatically on failure.
#>
[CmdletBinding()]
param(
    [switch]$NoPull,
    [ValidateSet("auto", "python", "rust")]
    [string]$Runtime = $(if ($env:MRC_RUNTIME) { $env:MRC_RUNTIME } else { "auto" }),
    [int]$Port = $(if ($env:MRC_PORT) { [int]$env:MRC_PORT } else { 8000 })
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common.ps1")

Assert-MrcAdmin -ScriptName "update.ps1"

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$InstallDir = Join-Path $env:ProgramData "Mobile-RC"
$InstalledServer = Join-Path $InstallDir "server.py"

if (-not (Test-Path $InstallDir) -or -not (Test-Path $InstalledServer)) {
    Write-Host "Mobile-RC is not installed in $InstallDir yet. Running install.ps1..." -ForegroundColor Yellow
    & (Join-Path $PSScriptRoot "install.ps1") -Runtime $Runtime -Port $Port
    exit $LASTEXITCODE
}

if (-not $NoPull -and (Test-Path (Join-Path $RepoRoot ".git")) -and (Get-Command "git" -ErrorAction SilentlyContinue)) {
    Write-Host "1. Checking git remote updates..." -ForegroundColor Blue
    try {
        & git -C $RepoRoot pull --ff-only
    } catch {
        Write-Host "   Note: git pull skipped; continuing with local source files." -ForegroundColor Yellow
    }
}

$PythonExe = Resolve-MrcPython
if (-not $PythonExe) {
    Write-Host "Error: Python 3 executable not found." -ForegroundColor Red
    exit 1
}

$SrcServer = Join-Path $RepoRoot "fallback\server.py"
if (-not (Test-Path $SrcServer)) {
    Write-Host "Error: Fallback server $SrcServer not found." -ForegroundColor Red
    exit 1
}

Write-Host "2. Validating syntax..." -ForegroundColor Blue
& $PythonExe -B -c "import py_compile, sys; py_compile.compile(sys.argv[1], doraise=True)" $SrcServer
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Syntax validation failed on fallback\server.py! Update aborted." -ForegroundColor Red
    exit 1
}

Write-Host "3. Stopping active service & updating core files (config.json preserved)..." -ForegroundColor Blue
$PrevTask = Get-ScheduledTask -TaskName "Mobile-RC" -ErrorAction SilentlyContinue
Stop-MrcRunningProcesses
Start-Sleep -Milliseconds 600

$BackupPath = Join-Path $InstallDir "server.py.bak"
Copy-Item $InstalledServer $BackupPath -Force
Copy-Item $SrcServer $InstalledServer -Force
if (Test-Path (Join-Path $RepoRoot "bin\control-access")) {
    Copy-Item (Join-Path $RepoRoot "bin\control-access") (Join-Path $InstallDir "control-access.py") -Force
}

$RustOut = Join-Path $InstallDir "mobile-rc.exe"
$RustBak = Join-Path $InstallDir "mobile-rc.exe.bak"
$HadRust = Test-Path $RustOut
if ($HadRust) { Copy-Item $RustOut $RustBak -Force }

$MarkerFile = Join-Path $InstallDir ".runtime"
$OldRuntime = if (Test-Path $MarkerFile) { (Get-Content -Path $MarkerFile -Raw -ErrorAction SilentlyContinue).Trim() } else { "" }

$RtInfo = Resolve-MrcRuntime -RepoRoot $RepoRoot -InstallDir $InstallDir -PythonExe $PythonExe -RuntimeMode $Runtime
if (-not $RtInfo.Success) {
    if (Test-Path $BackupPath) { Move-Item $BackupPath $InstalledServer -Force }
    if ($HadRust -and (Test-Path $RustBak)) { Move-Item $RustBak $RustOut -Force }
    if ($PrevTask -and $PrevTask.Actions -and $PrevTask.Actions.Count -gt 0) {
        Set-ScheduledTask -TaskName "Mobile-RC" -Action $PrevTask.Actions[0] | Out-Null
    }
    Start-ScheduledTask -TaskName "Mobile-RC" -ErrorAction SilentlyContinue
    exit 1
}
Write-MrcRuntimeMarker -InstallDir $InstallDir -RuntimeName $RtInfo.Name
$null = Sync-MrcMetadata -PythonExe $PythonExe -InstallDir $InstallDir

if ($PrevTask) {
    $NewAction = if ($RtInfo.Arg) {
        New-ScheduledTaskAction -Execute $RtInfo.Exe -Argument $RtInfo.Arg -WorkingDirectory $InstallDir
    } else {
        New-ScheduledTaskAction -Execute $RtInfo.Exe -WorkingDirectory $InstallDir
    }
    Set-ScheduledTask -TaskName "Mobile-RC" -Action $NewAction | Out-Null
}

Write-Host "4. Starting Scheduled Task ($($RtInfo.Label)) & verifying listener..." -ForegroundColor Blue
Start-ScheduledTask -TaskName "Mobile-RC"

$Alive = $false
for ($i = 0; $i -lt 10; $i++) {
    Start-Sleep -Milliseconds 600
    $conn = Test-NetConnection -ComputerName "127.0.0.1" -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue
    if ($conn) { $Alive = $true; break }
}

if (-not $Alive) {
    Write-Host "Error: Server did not respond on port $Port. Rolling back..." -ForegroundColor Red
    Stop-MrcRunningProcesses
    if (Test-Path $BackupPath) { Move-Item $BackupPath $InstalledServer -Force }
    if ($HadRust -and (Test-Path $RustBak)) {
        Move-Item $RustBak $RustOut -Force
    } else {
        Remove-Item $RustOut, $RustBak -Force -ErrorAction SilentlyContinue
    }
    if ($OldRuntime) {
        Write-MrcRuntimeMarker -InstallDir $InstallDir -RuntimeName $OldRuntime
    } else {
        Remove-Item $MarkerFile -Force -ErrorAction SilentlyContinue
    }
    if ($PrevTask -and $PrevTask.Actions -and $PrevTask.Actions.Count -gt 0) {
        Set-ScheduledTask -TaskName "Mobile-RC" -Action $PrevTask.Actions[0] | Out-Null
    }
    Start-ScheduledTask -TaskName "Mobile-RC" -ErrorAction SilentlyContinue
    exit 1
}

Remove-Item $BackupPath, $RustBak -Force -ErrorAction SilentlyContinue
Write-Host "Mobile-RC updated ($($RtInfo.Label)) and verified running on port $Port!" -ForegroundColor Green

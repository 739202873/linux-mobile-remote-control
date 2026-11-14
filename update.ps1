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

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Error: Please run update.ps1 from an Administrator PowerShell terminal." -ForegroundColor Red
    exit 1
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$InstallDir = Join-Path $env:ProgramData "Mobile-RC"
$InstalledServer = Join-Path $InstallDir "server.py"

if (-not (Test-Path $InstallDir) -or -not (Test-Path $InstalledServer)) {
    Write-Host "Mobile-RC is not installed in $InstallDir yet. Running install.ps1..." -ForegroundColor Yellow
    & (Join-Path $ScriptDir "install.ps1") -Runtime $Runtime -Port $Port
    exit $LASTEXITCODE
}

if (-not $NoPull -and (Test-Path (Join-Path $ScriptDir ".git")) -and (Get-Command "git" -ErrorAction SilentlyContinue)) {
    Write-Host "1. Checking git remote updates..." -ForegroundColor Blue
    try {
        & git -C $ScriptDir pull --ff-only
    } catch {
        Write-Host "   Note: git pull skipped; continuing with local source files." -ForegroundColor Yellow
    }
}

$PythonExe = $null
foreach ($cand in @("python", "python3")) {
    $c = Get-Command $cand -ErrorAction SilentlyContinue
    if ($c -and $c.Source -notlike "*\WindowsApps\*") { $PythonExe = $c.Source; break }
}
if (-not $PythonExe -and (Get-Command "py" -ErrorAction SilentlyContinue)) {
    $PythonExe = (& py -3 -c "import sys; print(sys.executable)" 2>$null).Trim()
}
if (-not $PythonExe) {
    Write-Host "Error: Python 3 executable not found." -ForegroundColor Red
    exit 1
}

$SrcServer = Join-Path $ScriptDir "server.py"
Write-Host "2. Validating syntax..." -ForegroundColor Blue
& $PythonExe -B -c "import py_compile, sys; py_compile.compile(sys.argv[1], doraise=True)" $SrcServer
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Syntax validation failed on server.py! Update aborted." -ForegroundColor Red
    exit 1
}

Write-Host "3. Stopping active service & updating core files (config.json preserved)..." -ForegroundColor Blue
$PrevTask = Get-ScheduledTask -TaskName "Mobile-RC" -ErrorAction SilentlyContinue
Stop-ScheduledTask -TaskName "Mobile-RC" -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*Mobile-RC\server.py*" -or $_.ExecutablePath -like "*Mobile-RC\mobile-rc.exe" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Milliseconds 600

$BackupPath = Join-Path $InstallDir "server.py.bak"
Copy-Item $InstalledServer $BackupPath -Force
Copy-Item $SrcServer $InstalledServer -Force
if (Test-Path (Join-Path $ScriptDir "bin\control-access")) {
    Copy-Item (Join-Path $ScriptDir "bin\control-access") (Join-Path $InstallDir "control-access.py") -Force
}

$UseRust = ($Runtime -in @("auto", "rust")) -and ($env:MRC_USE_RUST -ne "0")
if (-not $env:MRC_RUNTIME -and ($env:MRC_USE_RUST -eq "1")) { $UseRust = $true }
$RustOut = Join-Path $InstallDir "mobile-rc.exe"
$RustBak = Join-Path $InstallDir "mobile-rc.exe.bak"
$HadRust = Test-Path $RustOut
if ($HadRust) { Copy-Item $RustOut $RustBak -Force }

$RustReady = $false
if ($UseRust) {
    $LocalRust = Join-Path $ScriptDir "daemon-rs\target\release\mobile-rc.exe"
    $CargoToml = Join-Path $ScriptDir "daemon-rs\Cargo.toml"
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
}

$TaskExe = $PythonExe
$TaskArg = "`"$InstalledServer`""
$ActiveLabel = "Python 3 ($InstalledServer)"
if ($UseRust -and $RustReady -and (Test-Path $RustOut)) {
    $TaskExe = $RustOut
    $TaskArg = ""
    $ActiveLabel = "Native Rust ($RustOut)"
} elseif ($UseRust) {
    Write-Host "   Native Rust binary unavailable; falling back to Python server.py runtime." -ForegroundColor Yellow
}

if ($PrevTask) {
    $NewAction = if ($TaskArg) {
        New-ScheduledTaskAction -Execute $TaskExe -Argument $TaskArg -WorkingDirectory $InstallDir
    } else {
        New-ScheduledTaskAction -Execute $TaskExe -WorkingDirectory $InstallDir
    }
    Set-ScheduledTask -TaskName "Mobile-RC" -Action $NewAction | Out-Null
}

Write-Host "4. Starting Scheduled Task ($ActiveLabel) & verifying listener..." -ForegroundColor Blue
Start-ScheduledTask -TaskName "Mobile-RC"

$Alive = $false
for ($i = 0; $i -lt 10; $i++) {
    Start-Sleep -Milliseconds 600
    $conn = Test-NetConnection -ComputerName "127.0.0.1" -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue
    if ($conn) { $Alive = $true; break }
}

if (-not $Alive) {
    Write-Host "Error: Server did not respond on port $Port. Rolling back..." -ForegroundColor Red
    Stop-ScheduledTask -TaskName "Mobile-RC" -ErrorAction SilentlyContinue
    if (Test-Path $BackupPath) {
        Move-Item $BackupPath $InstalledServer -Force
    }
    if ($HadRust -and (Test-Path $RustBak)) {
        Move-Item $RustBak $RustOut -Force
    } else {
        Remove-Item $RustBak -Force -ErrorAction SilentlyContinue
    }
    if ($PrevTask -and $PrevTask.Actions -and $PrevTask.Actions.Count -gt 0) {
        Set-ScheduledTask -TaskName "Mobile-RC" -Action $PrevTask.Actions[0] | Out-Null
    }
    Start-ScheduledTask -TaskName "Mobile-RC" -ErrorAction SilentlyContinue
    exit 1
}

Remove-Item $BackupPath, $RustBak -Force -ErrorAction SilentlyContinue
Write-Host "Mobile-RC updated ($ActiveLabel) and verified running on port $Port!" -ForegroundColor Green

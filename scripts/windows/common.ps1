# Shared PowerShell helpers for Mobile-RC Windows scripts.

$script:MrcReleaseBaseUrl = "https://github.com/739202873/linux-mobile-remote-control/releases/latest/download"

function Assert-MrcAdmin {
    param([string]$ScriptName = "script")
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "Error: Please run $ScriptName from an Administrator PowerShell terminal." -ForegroundColor Red
        exit 1
    }
}

function Resolve-MrcPython {
    foreach ($cand in @("python", "python3")) {
        $cmd = Get-Command $cand -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source -notlike "*\WindowsApps\*") {
            try {
                $ver = & $cmd.Source -c "import sys; print(1 if sys.version_info >= (3,8) else 0)" 2>$null
                if ($ver -eq "1") { return $cmd.Source }
            } catch {}
        }
    }
    $pyLauncher = Get-Command "py" -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        try {
            $exePath = & $pyLauncher.Source -3 -c "import sys; print(sys.executable if sys.version_info >= (3,8) else '')" 2>$null
            if ($exePath -and (Test-Path $exePath.Trim())) {
                return $exePath.Trim()
            }
        } catch {}
    }
    return $null
}

function Resolve-MrcDesktopUser {
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

function Stop-MrcRunningProcesses {
    Stop-ScheduledTask -TaskName "Mobile-RC" -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like "*Mobile-RC\server.py*" -or $_.ExecutablePath -like "*Mobile-RC\mobile-rc.exe" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

function Get-MrcVerifiedReleaseBinary {
    param([string]$OutPath)
    $asset = "mobile-rc-windows-x86_64.exe"
    $tmpDir = Join-Path ([IO.Path]::GetTempPath()) ("mrc-dl-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    $tmpBin = Join-Path $tmpDir $asset
    $tmpSums = Join-Path $tmpDir "SHA256SUMS.txt"
    try {
        Invoke-WebRequest -Uri "$script:MrcReleaseBaseUrl/$asset" -OutFile $tmpBin -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        Invoke-WebRequest -Uri "$script:MrcReleaseBaseUrl/SHA256SUMS.txt" -OutFile $tmpSums -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop

        $expectedHash = $null
        foreach ($line in (Get-Content -Path $tmpSums -ErrorAction Stop)) {
            if ($line -match '^\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*$') {
                $hashCand = $Matches[1].ToLowerInvariant()
                $fileName = [IO.Path]::GetFileName($Matches[2].Replace("/", "\"))
                if ($fileName -eq $asset) {
                    $expectedHash = $hashCand
                    break
                }
            }
        }
        if (-not $expectedHash) {
            Write-Host "   Warning: SHA256SUMS.txt has no entry for $asset; skipping unverified download." -ForegroundColor Yellow
            return $false
        }
        $actualHash = (Get-FileHash -Path $tmpBin -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $expectedHash) {
            Write-Host "   Error: SHA-256 checksum mismatch for $asset (expected $expectedHash, got $actualHash)." -ForegroundColor Red
            return $false
        }
        Move-Item -Path $tmpBin -Destination $OutPath -Force
        Write-Host "   Verified GitHub Release binary checksum (SHA-256)." -ForegroundColor Green
        return $true
    } catch {
        return $false
    } finally {
        Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Resolve-MrcRuntime {
    param(
        [string]$RepoRoot,
        [string]$InstallDir,
        [string]$PythonExe,
        [string]$RuntimeMode
    )
    $mode = if ($RuntimeMode) { $RuntimeMode } else { "auto" }
    if (-not $env:MRC_RUNTIME) {
        if ($env:MRC_USE_RUST -eq "0") { $mode = "python" }
        elseif ($env:MRC_USE_RUST -eq "1") { $mode = "rust" }
    }

    $installedServer = Join-Path $InstallDir "server.py"
    $rustOut = Join-Path $InstallDir "mobile-rc.exe"
    $rustReady = $false

    if ($mode -ne "python") {
        $localRust = Join-Path $RepoRoot "daemon-rs\target\release\mobile-rc.exe"
        $cargoToml = Join-Path $RepoRoot "daemon-rs\Cargo.toml"
        if ((Test-Path $cargoToml) -and (Get-Command "cargo" -ErrorAction SilentlyContinue)) {
            Write-Host "   Building native Rust daemon (cargo build --release)..." -ForegroundColor Blue
            try { & cargo build --release --manifest-path $cargoToml } catch {}
            if (Test-Path $localRust) {
                Copy-Item $localRust $rustOut -Force
                $rustReady = $true
            }
        }
        if (-not $rustReady -and (Test-Path $localRust)) {
            Copy-Item $localRust $rustOut -Force
            $rustReady = $true
        }
        if (-not $rustReady) {
            $rustReady = Get-MrcVerifiedReleaseBinary -OutPath $rustOut
        }
        if ($rustReady -and (Test-Path $rustOut)) {
            Write-Host "   Using Hybrid native runtime: $rustOut" -ForegroundColor Green
            return @{
                Success = $true
                Exe     = $rustOut
                Arg     = ""
                Name    = "rust"
                Label   = "Native Rust ($rustOut)"
            }
        }
        if ($mode -eq "rust") {
            Write-Host "Error: -Runtime rust was requested, but native binary build/download failed." -ForegroundColor Red
            return @{ Success = $false }
        }
        Write-Host "   Native Rust binary unavailable; using Python server.py runtime." -ForegroundColor Yellow
    } else {
        Write-Host "   Python runtime requested; using Python server.py runtime." -ForegroundColor Blue
    }

    return @{
        Success = $true
        Exe     = $PythonExe
        Arg     = "`"$installedServer`""
        Name    = "python"
        Label   = "Python 3 ($installedServer)"
    }
}

function Write-MrcRuntimeMarker {
    param([string]$InstallDir, [string]$RuntimeName)
    $marker = Join-Path $InstallDir ".runtime"
    Set-Content -Path $marker -Value $RuntimeName -Encoding Ascii
}

function Sync-MrcMetadata {
    param(
        [string]$PythonExe,
        [string]$InstallDir,
        [string]$TargetUserLeaf = ""
    )
    $cfgPath = Join-Path $InstallDir "config.json"
    $pinPath = Join-Path $InstallDir "pin.txt"
    $pyScript = @'
import json, os, secrets, sys
cfg_path, pin_path, forced_user = sys.argv[1], sys.argv[2], sys.argv[3].strip()
cfg = {}
if os.path.exists(cfg_path):
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                cfg = data
    except Exception:
        cfg = {}
if forced_user:
    cfg["target_user"] = forced_user
elif "user" in cfg and not cfg.get("target_user"):
    cfg["target_user"] = cfg["user"]
cfg.pop("user", None)
if not cfg.get("ntfy_topic"):
    cfg["ntfy_topic"] = f"mobile-rc-{secrets.token_hex(12)}"
cfg.setdefault("auto_tunnel", False)
cfg.setdefault("pin_mode", "on_demand")
if not cfg.get("termux_token"):
    cfg["termux_token"] = secrets.token_urlsafe(32)
with open(cfg_path, "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
pin_val = "(On-Demand via control-access)"
if cfg.get("pin_mode") == "on_demand" and os.path.exists(pin_path):
    try: os.remove(pin_path)
    except OSError: pass
elif cfg.get("pin_mode") == "static" and os.path.exists(pin_path):
    try:
        with open(pin_path, "r", encoding="utf-8") as f:
            val = f.read().strip()
            if val:
                pin_val = val
    except Exception:
        pass
print(cfg.get("ntfy_topic") or "")
print(cfg.get("pin_mode") or "on_demand")
print(pin_val)
'@
    $lines = ($pyScript | & $PythonExe -B - $cfgPath $pinPath $TargetUserLeaf)
    $ntfy = if ($lines -is [array] -and $lines.Length -ge 1) { $lines[0] } else { "" }
    $mode = if ($lines -is [array] -and $lines.Length -ge 2) { $lines[1] } else { "on_demand" }
    $pinVal = if ($lines -is [array] -and $lines.Length -ge 3) { $lines[2] } else { "(On-Demand via control-access)" }
    return @{ NtfyTopic = $ntfy; PinMode = $mode; PinVal = $pinVal }
}

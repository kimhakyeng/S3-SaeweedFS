# ============================================================================
#  file-agent  Windows single-exe build + deploy packaging (PyInstaller)
#  Output:
#    dist\file-agent.exe        single daemon executable
#    dist\ (run folder)         exe + config.json + scripts
#    file-agent.zip             zip of dist (carry this one file)
#  Usage:  powershell -ExecutionPolicy Bypass -File build-windows.ps1
#  NOTE: ASCII-only on purpose (Windows PowerShell 5.x reads non-BOM files as
#        the system codepage, which corrupts non-ASCII text and breaks parsing).
# ============================================================================
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

# Stop any running file-agent so the exe is not locked during build/zip.
Write-Host "Stopping any running file-agent (if any)..." -ForegroundColor DarkGray
cmd /c "schtasks /End /TN file-agent >nul 2>&1"
cmd /c "taskkill /IM file-agent.exe /F >nul 2>&1"
Start-Sleep -Milliseconds 700

# Find a real Python launcher (skip the Microsoft Store stub)
$py = $null
$cands = @()
$g = Get-Command python.exe -ErrorAction SilentlyContinue
if ($g -and $g.Source -notlike "*WindowsApps*") { $cands += $g.Source }
$cands += @(
    "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
    "C:\Python312\python.exe","C:\Python311\python.exe"
)
foreach ($c in $cands) {
    if ($c -and (Test-Path $c)) {
        try { & $c --version *>$null; if ($LASTEXITCODE -eq 0) { $py = $c; break } } catch {}
    }
}
if (-not $py) { $launcher = Get-Command py -ErrorAction SilentlyContinue; if ($launcher) { $py = "py" } }
if (-not $py) { Write-Error "No working Python 3 found (install real Python, not the Microsoft Store stub)."; exit 1 }
Write-Host "python: $py"

Write-Host "[1/4] Installing deps (watchdog, websocket-client, boto3, pyinstaller)..." -ForegroundColor Cyan
& $py -m pip install --upgrade pip
& $py -m pip install -r requirements.txt pyinstaller
if ($LASTEXITCODE -ne 0) { Write-Error "dependency install failed"; exit 1 }

Write-Host "[2/4] PyInstaller build..." -ForegroundColor Cyan
# boto3/botocore ship data files (endpoints.json etc.) -> collect-all so direct mode works.
& $py -m PyInstaller --onefile --name file-agent `
    --collect-submodules watchdog `
    --collect-submodules websocket `
    --collect-all boto3 `
    --collect-all botocore `
    --distpath dist --workpath build --specpath build agent.py
if ($LASTEXITCODE -ne 0) { Write-Error "build failed"; exit 1 }

Write-Host "[3/4] Staging run files next to exe in dist..." -ForegroundColor Cyan
# PyInstaller already produced dist\file-agent.exe. Keep only the run files beside it.
if (-not (Test-Path "dist\config.json") -and (Test-Path "config.json")) {
    Copy-Item "config.json" "dist\config.json" -Force   # keep existing dist\config.json if present
}
foreach ($f in @("config.s3-direct.example.json","config.push.example.json","install.bat","uninstall.bat","install.ps1","uninstall.ps1","README.md")) {
    if (Test-Path $f) { Copy-Item $f (Join-Path "dist" $f) -Force }
}
Get-ChildItem "dist" -Filter "_*.txt" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

Write-Host "[4/4] Zipping dist..." -ForegroundColor Cyan
cmd /c "taskkill /IM file-agent.exe /F >nul 2>&1"   # ensure exe not locked
Start-Sleep -Milliseconds 300
$zip = Join-Path $root "file-agent.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path "dist\*" -DestinationPath $zip -Force

Write-Host ""
Write-Host "DONE:" -ForegroundColor Green
Write-Host "  run folder : $root\dist  (file-agent.exe + config.json + scripts)"
Write-Host "  deploy zip : $zip"
Write-Host ""
Write-Host "Deploy to another Windows PC with just the exe:"
Write-Host "  1) copy file-agent.exe to the target PC"
Write-Host "  2) admin PowerShell:  file-agent.exe --install"
Write-Host "  3) edit the config.json created next to the exe"
Write-Host ""

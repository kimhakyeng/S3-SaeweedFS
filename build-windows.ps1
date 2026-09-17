# ============================================================================
#  file-agent  Windows single-exe build + deploy packaging (PyInstaller)
#  Output:
#    build\release-bin\file-agent.exe      daemon
#    build\release-bin\file-agent-ui.exe   control UI
#    file-agent.zip                        deploy package (one top-level folder: file-agent\)
#    file-agent.zip.sha256                 package checksum
#    file-agent.zip.manifest.json          package provenance and file hashes
#    build\releases\file-agent-<ver>-<commit>[-dirty]-<zipsha8>.zip   kept copy of every package
#  Usage:  powershell -ExecutionPolicy Bypass -File build-windows.ps1
#          powershell -ExecutionPolicy Bypass -File build-windows.ps1 -PackageOnly
#            (-PackageOnly repackages the exes already in build\release-bin)
#          powershell -ExecutionPolicy Bypass -File build-windows.ps1 -AllowDirty
#            (test build from uncommitted sources; the package is marked dirty)
#  Exit codes: 0 ok, 1 error, 3 working tree has uncommitted changes (rerun with -AllowDirty)
#  NOTE: ASCII-only on purpose (Windows PowerShell 5.x reads non-BOM files as
#        the system codepage, which corrupts non-ASCII text and breaks parsing).
# ============================================================================
param(
    [switch]$PackageOnly,
    [switch]$AllowDirty
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$releaseBin = Join-Path $root "build\release-bin"
$releaseWork = Join-Path $root "build\release-work"
$releaseStageRoot = Join-Path $root "build\release-stage"
$packageFolder = "file-agent"
$releaseStage = Join-Path $releaseStageRoot $packageFolder
$releaseVerify = Join-Path $root "build\release-verify"
$releaseKeep = Join-Path $root "build\releases"
$placeholderToken = "change-me-please-long-random-token"

# Remove a directory reliably. Remove-Item fails on deep PyInstaller trees
# ("directory is not empty") when a virus scanner briefly holds a file.
# Fall back to rd, which retries internally.
function Remove-Tree([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return }
    try { Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop; return } catch {}
    Start-Sleep -Milliseconds 800
    & cmd /c "rd /s /q `"$path`"" 2>$null
    if (Test-Path -LiteralPath $path) {
        Write-Error "cannot clean $path - a file is in use. Close any Explorer window or program using it, then retry."
        exit 1
    }
}

function Get-SourceVersion([string]$file, [string]$name) {
    $text = [System.IO.File]::ReadAllText((Join-Path $root $file))
    $m = [regex]::Match($text, "(?m)^$name\s*=\s*`"([^`"]+)`"")
    if ($m.Success) { return $m.Groups[1].Value }
    return "0.0.0"
}

# PyInstaller --version-file input (Windows VS_VERSIONINFO resource).
# Shows product / version / commit in Explorer > Properties > Details, which helps
# customer IT tell builds apart and whitelist them.
function Write-VersionFile([string]$path, [string]$version, [string]$desc, [string]$internal, [string]$product) {
    $nums = @($version.Split('.') | ForEach-Object { [int]($_ -replace '[^0-9]', '') })
    while ($nums.Count -lt 4) { $nums += 0 }
    $tuple = "({0}, {1}, {2}, {3})" -f $nums[0], $nums[1], $nums[2], $nums[3]
    $body = @"
VSVersionInfo(
  ffi=FixedFileInfo(filevers=$tuple, prodvers=$tuple, mask=0x3f, flags=0x0, OS=0x40004,
                    fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'DLIT'),
      StringStruct('FileDescription', '$desc'),
      StringStruct('FileVersion', '$version'),
      StringStruct('InternalName', '$internal'),
      StringStruct('OriginalFilename', '$internal.exe'),
      StringStruct('ProductName', 'TERESA MQ file-agent'),
      StringStruct('ProductVersion', '$product')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"@
    [System.IO.File]::WriteAllText($path, $body, (New-Object System.Text.UTF8Encoding($false)))
}

# ---------------------------------------------------------------------------
#  Provenance (needed for the version resource, BUILD-INFO.txt and the manifest)
# ---------------------------------------------------------------------------
$version = Get-SourceVersion "agent.py" "VERSION"
$uiVersion = Get-SourceVersion "agent_ui.py" "UI_VERSION"
$sourceCommit = "unknown"
$sourceDirty = $true
$git = Get-Command git.exe -ErrorAction SilentlyContinue
if ($git) {
    # git may print CRLF warnings on stderr; under EAP=Stop that would abort the lookup on PowerShell 5.1.
    $ErrorActionPreference = "Continue"
    try {
        $head = & $git.Source -C $root rev-parse HEAD 2>$null
        if ($LASTEXITCODE -eq 0 -and $head) { $sourceCommit = ("$head").Trim() }
        $statusLines = @(& $git.Source -C $root status --porcelain 2>$null | Where-Object { "$_".Trim() -ne "" })
        if ($LASTEXITCODE -eq 0) { $sourceDirty = $statusLines.Count -gt 0 }
    } catch {
        Write-Warning "Git provenance unavailable: $($_.Exception.Message)"
    }
    $ErrorActionPreference = "Stop"
}
$shortCommit = if ($sourceCommit.Length -ge 7) { $sourceCommit.Substring(0, 7) } else { $sourceCommit }
$productTag = "$version+$shortCommit" + $(if ($sourceDirty) { "-dirty" } else { "" })
if ($sourceDirty) {
    if (-not $AllowDirty) {
        Write-Host "STOP: the working tree has uncommitted changes." -ForegroundColor Red
        Write-Host "      A customer package must be built from a commit (so it can be reproduced and patched)." -ForegroundColor Red
        Write-Host "      Commit first, or rerun with -AllowDirty for a test build." -ForegroundColor Red
        exit 3
    }
    Write-Host "WARNING: test build from uncommitted sources. The package is marked 'dirty' - do not ship it." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
#  Template guard: the package must never carry a real token or credentials.
# ---------------------------------------------------------------------------
$templatePath = Join-Path $root "config.template.json"
if (-not (Test-Path -LiteralPath $templatePath -PathType Leaf)) { Write-Error "Missing config.template.json"; exit 1 }
$templateText = [System.IO.File]::ReadAllText($templatePath)
$guards = [ordered]@{
    "token is the placeholder" = ('"token"\s*:\s*"' + [regex]::Escape($placeholderToken) + '"')
    "ws_url is empty" = '"ws_url"\s*:\s*""'
    "s3_endpoint is empty" = '"s3_endpoint"\s*:\s*""'
    "s3_bucket is empty" = '"s3_bucket"\s*:\s*""'
    "s3_access_key is empty" = '"s3_access_key"\s*:\s*""'
    "s3_secret_key is empty" = '"s3_secret_key"\s*:\s*""'
    "watch_dirs is empty" = '"watch_dirs"\s*:\s*\[\s*\]'
}
foreach ($label in $guards.Keys) {
    if (-not [regex]::IsMatch($templateText, $guards[$label])) {
        Write-Error "config.template.json check failed: $label. Refusing to package site values."
        exit 1
    }
}
# No IPv4 literal anywhere (comments included): site addresses must not ship in the template.
if ([regex]::IsMatch($templateText, '\b\d{1,3}(\.\d{1,3}){3}\b')) {
    Write-Error "config.template.json contains an IP address. Remove site-specific values before packaging."
    exit 1
}
# Each key once (a duplicate would silently override the guarded value).
$keyNames = @([regex]::Matches(($templateText -replace '(?m)//.*$', ''), '"([A-Za-z0-9_]+)"\s*:') | ForEach-Object { $_.Groups[1].Value })
$dupKeys = @($keyNames | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
if ($dupKeys.Count -gt 0) {
    Write-Error ("config.template.json has duplicate keys: " + ($dupKeys -join ', '))
    exit 1
}

if (-not $PackageOnly) {
    # Build outside the active dist directory. A running agent is not touched.
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

    # Skip pip when everything is already importable. pip blocks for a long time with no
    # output on an offline or proxied network (closed-network sites).
    Write-Host "[1/4] Checking deps (watchdog, websocket-client, boto3, pyinstaller)..." -ForegroundColor Cyan
    # Native stderr under EAP=Stop is a terminating error on PowerShell 5.1 - relax it for this probe.
    $ErrorActionPreference = "Continue"
    & $py -c "import PyInstaller, watchdog, websocket, boto3, botocore" 2>$null
    $depsOk = ($LASTEXITCODE -eq 0)
    $ErrorActionPreference = "Stop"
    if ($depsOk) {
        Write-Host "      all deps already installed - skipping pip" -ForegroundColor Green
    } else {
        Write-Host "      installing missing deps..." -ForegroundColor Yellow
        $ErrorActionPreference = "Continue"
        & $py -m pip install -r requirements.txt pyinstaller
        $pipOk = ($LASTEXITCODE -eq 0)
        $ErrorActionPreference = "Stop"
        if (-not $pipOk) { Write-Error "dependency install failed (offline? install the wheels manually)"; exit 1 }
    }

    Write-Host "[2/4] PyInstaller build in isolated release directories..." -ForegroundColor Cyan
    foreach ($p in @($releaseBin, $releaseWork)) {
        Remove-Tree $p
        New-Item -ItemType Directory -Force -Path $p | Out-Null
    }
    # Absolute paths: --specpath points at release-work, and PyInstaller resolves
    # relative --icon / --add-data paths against the spec file, not the repo root.
    $iconPath = Join-Path $root "assets\dlit.ico"
    $logoPath = Join-Path $root "assets\dlit-logo-header.png"
    foreach ($a in @($iconPath, $logoPath)) {
        if (-not (Test-Path -LiteralPath $a -PathType Leaf)) { Write-Error "Missing asset: $a"; exit 1 }
    }
    $daemonVer = Join-Path $releaseWork "version-daemon.txt"
    $uiVer = Join-Path $releaseWork "version-ui.txt"
    Write-VersionFile $daemonVer $version "TERESA MQ file-agent daemon" "file-agent" $productTag
    Write-VersionFile $uiVer $uiVersion "TERESA MQ file-agent control UI" "file-agent-ui" "$uiVersion (agent $productTag)"

    # Daemon.
    #   --noconsole  : true background daemon (no console window). Logs go next to the exe.
    #   --uac-admin  : 'requireAdministrator' manifest (firewall rule, replacing an elevated instance).
    #   --disable-windowed-traceback : an unhandled Python error is not shown in a dialog (agent.py also
    #                  catches it and writes agent-crash.log). Bootloader-level failures (e.g. the
    #                  temp extraction failing) can still show a dialog; the 5-minute trigger cannot
    #                  help while such a dialog keeps the process alive.
    #   boto3/botocore ship data files (endpoints.json etc.) -> collect-all so direct mode works.
    & $py -m PyInstaller --clean --noconfirm --onefile --noconsole --uac-admin --disable-windowed-traceback `
        --name file-agent `
        --icon $iconPath `
        --version-file $daemonVer `
        --collect-submodules watchdog `
        --collect-submodules websocket `
        --collect-all boto3 `
        --collect-all botocore `
        --distpath $releaseBin --workpath $releaseWork --specpath $releaseWork agent.py
    if ($LASTEXITCODE -ne 0) { Write-Error "build failed"; exit 1 }

    # Control UI (agent_ui.py) - a SEPARATE executable next to the daemon.
    #   --onefile   : unzip -> file-agent-ui.exe is right there, no subfolder to dig into.
    #   --uac-admin : the UI controls a SYSTEM-level daemon (scheduled task, firewall rule).
    #                 Elevating once when it opens beats prompting on every button.
    Write-Host "[2b/4] PyInstaller build: control UI..." -ForegroundColor Cyan
    & $py -m PyInstaller --clean --noconfirm --onefile --noconsole --uac-admin --name file-agent-ui `
        --icon $iconPath `
        --version-file $uiVer `
        --add-data "$iconPath;assets" `
        --add-data "$logoPath;assets" `
        --collect-all boto3 `
        --collect-all botocore `
        --distpath $releaseBin --workpath $releaseWork --specpath $releaseWork agent_ui.py
    if ($LASTEXITCODE -ne 0) { Write-Error "UI build failed"; exit 1 }
} else {
    Write-Host "[1/4] Package-only mode: reusing the executables in build\release-bin." -ForegroundColor Cyan
}
$exeSource = Join-Path $releaseBin "file-agent.exe"
$uiSource = Join-Path $releaseBin "file-agent-ui.exe"

Write-Host "[3/4] Creating clean release staging..." -ForegroundColor Cyan
foreach ($p in @($releaseStageRoot, $releaseVerify)) {
    Remove-Tree $p
}
New-Item -ItemType Directory -Force -Path $releaseStage | Out-Null
New-Item -ItemType Directory -Force -Path $releaseVerify | Out-Null
# Core deploy files (always required). The template is shipped instead of config.json so that
# extracting a new package over an existing install never overwrites the site's settings.
$sources = [ordered]@{
    "file-agent.exe" = $exeSource
    "file-agent-ui.exe" = $uiSource
    "config.template.json" = $templatePath
    "install.bat" = (Join-Path $root "install.bat")
    "uninstall.bat" = (Join-Path $root "uninstall.bat")
}
foreach ($name in $sources.Keys) {
    $src = $sources[$name]
    if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { Write-Error "Missing release input: $src"; exit 1 }
    Copy-Item -LiteralPath $src -Destination (Join-Path $releaseStage $name) -Force
}
# Optional operational helpers: every file inside deploy-extras\ is added to the
# package folder. A helper whose name collides with a core file is rejected.
$extraNames = @()
$extrasDir = Join-Path $root "deploy-extras"
if (Test-Path -LiteralPath $extrasDir) {
    foreach ($f in @(Get-ChildItem -LiteralPath $extrasDir -File)) {
        if ((@($sources.Keys) + @("BUILD-INFO.txt", "config.json")) -contains $f.Name) {
            Write-Error "deploy-extras name collides with a core file: $($f.Name)"; exit 1
        }
        Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $releaseStage $f.Name) -Force
        $extraNames += $f.Name
    }
    Write-Host ("      deploy-extras included: {0}" -f ($(if ($extraNames.Count) { $extraNames -join ', ' } else { "(none)" })))
}

$exeHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $exeSource).Hash
$uiHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $uiSource).Hash
$buildInfo = @(
    "TERESA MQ file-agent package",
    "agent version : $version",
    "ui version    : $uiVersion",
    "source commit : $sourceCommit",
    "source dirty  : $sourceDirty",
    "package only  : $([bool]$PackageOnly)",
    "built (UTC)   : $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss'))",
    "file-agent.exe    sha256 $exeHash",
    "file-agent-ui.exe sha256 $uiHash",
    "",
    "Customer IT: allow-list these two files by the SHA256 values above if antivirus or",
    "SmartScreen blocks them (the executables are not code-signed)."
)
Set-Content -LiteralPath (Join-Path $releaseStage "BUILD-INFO.txt") -Value $buildInfo -Encoding ASCII

$expectedNames = @(@($sources.Keys) + @("BUILD-INFO.txt") + $extraNames | Sort-Object)
$stagedNames = @(Get-ChildItem -LiteralPath $releaseStage -File | ForEach-Object Name | Sort-Object)
if (Compare-Object $expectedNames $stagedNames) { Write-Error "Release staging entry mismatch"; exit 1 }

Write-Host "[4/4] Creating and verifying ZIP..." -ForegroundColor Cyan
$zip = Join-Path $root "file-agent.zip"
$tmpZip = Join-Path $root "file-agent.tmp.zip"
if (Test-Path $tmpZip) { Remove-Item $tmpZip -Force }
# Build the archive entry by entry: forward-slash names under one top-level folder.
# (Compress-Archive on PowerShell 5.1 writes backslash separators.)
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$fs = [System.IO.File]::Open($tmpZip, [System.IO.FileMode]::CreateNew)
try {
    $archive = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($name in $expectedNames) {
            [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $archive, (Join-Path $releaseStage $name), "$packageFolder/$name",
                [System.IO.Compression.CompressionLevel]::Optimal)
        }
    } finally { $archive.Dispose() }
} finally { $fs.Dispose() }

$expectedEntries = @($expectedNames | ForEach-Object { "$packageFolder/$_" } | Sort-Object)
$reader = [System.IO.Compression.ZipFile]::OpenRead($tmpZip)
try {
    $zipEntries = @($reader.Entries | ForEach-Object FullName | Sort-Object)
} finally {
    $reader.Dispose()
}
if (Compare-Object $expectedEntries $zipEntries) { Write-Error "ZIP entry mismatch"; exit 1 }
[System.IO.Compression.ZipFile]::ExtractToDirectory($tmpZip, $releaseVerify)
foreach ($name in $expectedNames) {
    $stageHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $releaseStage $name)).Hash
    $verifyHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path (Join-Path $releaseVerify $packageFolder) $name)).Hash
    if ($stageHash -ne $verifyHash) { Write-Error "ZIP content hash mismatch: $name"; exit 1 }
}
if (Test-Path $zip) {
    $previousZip = Join-Path $root "file-agent.previous.zip"
    if (Test-Path $previousZip) { Remove-Item $previousZip -Force }
    [System.IO.File]::Replace($tmpZip, $zip, $previousZip, $true)
    Remove-Item -LiteralPath $previousZip -Force
} else {
    Move-Item -LiteralPath $tmpZip -Destination $zip
}
$zipHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash
Set-Content -LiteralPath "$zip.sha256" -Encoding ASCII -Value ("{0} *file-agent.zip" -f $zipHash)

$entryRecords = @($expectedNames | ForEach-Object {
    $entryPath = Join-Path $releaseStage $_
    [ordered]@{
        name = "$packageFolder/$_"
        bytes = (Get-Item -LiteralPath $entryPath).Length
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $entryPath).Hash
    }
})
$manifest = [ordered]@{
    schemaVersion = 2
    artifact = "file-agent.zip"
    version = $version
    uiVersion = $uiVersion
    platform = "windows-x64"
    createdAtUtc = [DateTime]::UtcNow.ToString("o")
    sourceCommit = $sourceCommit
    sourceDirty = $sourceDirty
    packageOnly = [bool]$PackageOnly
    authenticodeStatus = [ordered]@{
        daemon = (Get-AuthenticodeSignature -LiteralPath $exeSource).Status.ToString()
        ui = (Get-AuthenticodeSignature -LiteralPath $uiSource).Status.ToString()
    }
    entries = $entryRecords
    zipBytes = (Get-Item -LiteralPath $zip).Length
    zipSha256 = $zipHash
}
[System.IO.File]::WriteAllText("$zip.manifest.json", ($manifest | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))

# Keep every package that was produced, named by version / commit / hash.
New-Item -ItemType Directory -Force -Path $releaseKeep | Out-Null
$keepName = "file-agent-$version-$shortCommit" + $(if ($sourceDirty) { "-dirty" } else { "" }) + "-" + $zipHash.Substring(0, 8).ToLower() + ".zip"
Copy-Item -LiteralPath $zip -Destination (Join-Path $releaseKeep $keepName) -Force
Copy-Item -LiteralPath "$zip.manifest.json" -Destination (Join-Path $releaseKeep ($keepName + ".manifest.json")) -Force
Copy-Item -LiteralPath "$zip.sha256" -Destination (Join-Path $releaseKeep ($keepName + ".sha256")) -Force

Write-Host ""
Write-Host "DONE:" -ForegroundColor Green
Write-Host "  deploy zip : $zip"
Write-Host "  zip sha256 : $zipHash"
Write-Host "  daemon     : $version  sha256 $exeHash"
Write-Host "  ui         : $uiVersion  sha256 $uiHash"
Write-Host "  source     : $productTag"
Write-Host "  kept copy  : build\releases\$keepName"
Write-Host "  entries    : $($expectedEntries -join ', ')"
Write-Host ""
Write-Host "Deploy to another Windows PC:"
Write-Host "  1) extract the zip; it contains one folder 'file-agent' - move it to e.g. C:\file-agent"
Write-Host "  2) run file-agent-ui.exe inside it (approve the admin prompt once)"
Write-Host "  3) Connection tab: backend host / port, [New token], [Test backend], [Save only]"
Write-Host "  4) canvas: set the same token on the node, set WatchDir, activate the edge"
Write-Host "  5) [Autostart on boot: On]  - firewall rule + SYSTEM boot task + 5-minute watchdog"
Write-Host "  Upgrade: if the old install used the default token, change the canvas node token first."
Write-Host "           [Stop] (or uninstall.bat for versions without the UI), back up config.json and sent.jsonl,"
Write-Host "           copy the files INSIDE file-agent\ over the install folder, then [Autostart: On]."
Write-Host ""

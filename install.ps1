# file-agent 자동 셋업 스크립트 (Windows)
# 1) 방화벽 룰 등록
# 2) 작업 스케줄러 등록 (At Logon + 죽으면 3회 재시작)
# 3) 즉시 시작
# 4) 상태 확인
#
# 사용법:
#   관리자 PowerShell 에서:
#     powershell -ExecutionPolicy Bypass -File install.ps1
#
# 옵션:
#   -ExePath "...\file-agent.exe"   exe 위치 (기본: 스크립트와 같은 폴더의 dist\file-agent.exe)
#   -Port 8765                       방화벽 열 포트 (기본 8765)
#   -TaskName "file-agent"           스케줄러 이름 (기본 file-agent)

param(
    [string]$ExePath = "",
    [int]$Port = 8765,
    [string]$TaskName = "file-agent"
)

# 관리자 권한 검사
$current = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($current)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] 관리자 권한이 필요합니다." -ForegroundColor Red
    Write-Host "       PowerShell 을 우클릭 → '관리자 권한으로 실행' 으로 다시 실행하세요." -ForegroundColor Yellow
    exit 1
}

# ExePath 기본값 — 스크립트 위치 기준
if ([string]::IsNullOrWhiteSpace($ExePath)) {
    # ps1 직접 실행: $MyInvocation.MyCommand.Path / PS2EXE exe 실행: 프로세스 실행 파일 경로로 폴백
    $selfPath = $MyInvocation.MyCommand.Path
    if ([string]::IsNullOrWhiteSpace($selfPath)) {
        $selfPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    }
    $scriptDir = Split-Path -Parent $selfPath
    $ExePath = Join-Path $scriptDir "dist\file-agent.exe"
}

if (-not (Test-Path $ExePath)) {
    Write-Host "[ERROR] 실행파일을 찾을 수 없습니다: $ExePath" -ForegroundColor Red
    Write-Host "       먼저 build-windows.ps1 로 exe 를 빌드하세요." -ForegroundColor Yellow
    exit 1
}

$workingDir = Split-Path -Parent $ExePath
$configPath = Join-Path $workingDir "config.json"

if (-not (Test-Path $configPath)) {
    Write-Host "[WARN] config.json 이 없습니다: $configPath" -ForegroundColor Yellow
    Write-Host "       실행 시 데몬이 곧바로 종료될 수 있으니 셋업 후 만들어주세요." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "==================== file-agent install ====================" -ForegroundColor Cyan
Write-Host "Exe path     : $ExePath"
Write-Host "Working dir  : $workingDir"
Write-Host "Config       : $configPath"
Write-Host "Firewall port: $Port"
Write-Host "Task name    : $TaskName"
Write-Host "============================================================="
Write-Host ""

# 1) 방화벽 룰
Write-Host "[1/3] 방화벽 인바운드 룰 등록 (TCP $Port)..." -ForegroundColor Green
try {
    $existing = Get-NetFirewallRule -DisplayName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "      이미 존재 → 그대로 둠"
    } else {
        New-NetFirewallRule -DisplayName $TaskName `
            -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow | Out-Null
        Write-Host "      OK"
    }
} catch {
    Write-Host "[WARN] 방화벽 룰 등록 실패: $_" -ForegroundColor Yellow
}

# 2) 작업 스케줄러
Write-Host "[2/3] 작업 스케줄러 등록 ($TaskName)..." -ForegroundColor Green
try {
    $action = New-ScheduledTaskAction -Execute $ExePath -WorkingDirectory $workingDir
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
    $principal = New-ScheduledTaskPrincipal `
        -UserId "$env:USERDOMAIN\$env:USERNAME" `
        -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -MultipleInstances IgnoreNew

    Register-ScheduledTask -TaskName $TaskName `
        -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
        -Description "TERESA MQ file watcher agent" -Force | Out-Null
    Write-Host "      OK (다음 로그인부터 자동 시작 + 죽으면 3회 자동 재시작)"
} catch {
    Write-Host "[ERROR] 작업 스케줄러 등록 실패: $_" -ForegroundColor Red
    exit 2
}

# 3) 즉시 시작
Write-Host "[3/3] 데몬 즉시 시작..." -ForegroundColor Green
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 2

# 상태 확인
$proc = Get-Process file-agent -ErrorAction SilentlyContinue
if ($proc) {
    Write-Host "      OK — PID: $($proc.Id)" -ForegroundColor Green
} else {
    Write-Host "      [WARN] 프로세스가 안 보입니다. agent.log 확인 필요:" -ForegroundColor Yellow
    Write-Host "      $workingDir\agent.log"
}

Write-Host ""
Write-Host "==================== 셋업 완료 ====================" -ForegroundColor Cyan
Write-Host ""
Write-Host "다음에 유용한 명령:"
Write-Host "  상태 확인 : tasklist | findstr file-agent"
Write-Host "  로그 실시간: Get-Content $workingDir\agent.log -Wait -Tail 20"
Write-Host "  정지     : schtasks /End /TN $TaskName"
Write-Host "  시작     : schtasks /Run /TN $TaskName"
Write-Host "  제거     : Unregister-ScheduledTask -TaskName $TaskName -Confirm:`$false"
Write-Host ""

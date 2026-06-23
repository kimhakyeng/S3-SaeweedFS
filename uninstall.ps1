# file-agent 제거 스크립트 (Windows)
# 1) 작업 정지 + 프로세스 강제 종료
# 2) 작업 스케줄러 등록 해제
# 3) 방화벽 룰 삭제
#
# 데이터 파일(events.jsonl, agent.log) 과 폴더는 그대로 둠.
# 폴더 통째로 지우려면 별도로 Remove-Item.

param(
    [string]$TaskName = "file-agent"
)

$current = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($current)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] 관리자 권한이 필요합니다." -ForegroundColor Red
    exit 1
}

Write-Host "[1/3] 데몬 정지..." -ForegroundColor Green
try {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Stop-Process -Name file-agent -Force -ErrorAction SilentlyContinue
    Write-Host "      OK"
} catch {
    Write-Host "      이미 정지된 상태"
}

Write-Host "[2/3] 작업 스케줄러 해제..." -ForegroundColor Green
try {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
    Write-Host "      OK"
} catch {
    Write-Host "      작업이 없음 또는 이미 해제됨"
}

Write-Host "[3/3] 방화벽 룰 삭제..." -ForegroundColor Green
try {
    Remove-NetFirewallRule -DisplayName $TaskName -ErrorAction Stop
    Write-Host "      OK"
} catch {
    Write-Host "      룰이 없음"
}

Write-Host ""
Write-Host "제거 완료. 폴더와 데이터 파일은 그대로 있습니다." -ForegroundColor Cyan
Write-Host "완전히 지우려면: Remove-Item C:\path\to\file-agent -Recurse -Force"

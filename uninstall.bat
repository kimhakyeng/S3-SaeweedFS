@echo off
title file-agent uninstaller
REM file-agent uninstaller (fallback when file-agent-ui.exe cannot be used). Self-elevates to admin.
REM Administrator check: the High Mandatory Level SID is present only in an elevated token.
whoami /groups | find "S-1-16-12288" >nul 2>&1
if %errorlevel% equ 0 goto :admin
if /i "%~1"=="elevated" (
  echo ERROR: administrator rights were not granted.
  pause
  exit /b 5
)
echo Requesting administrator privileges...
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList 'elevated' -Verb RunAs"
exit /b
:admin
cd /d "%~dp0"
echo.
echo Uninstalling file-agent ^(stop daemon + remove task + firewall rules^)...
echo.
schtasks /End /TN file-agent >nul 2>&1
if exist file-agent.exe (
  REM windowless program: wait until it has removed the task and firewall rules
  start "" /wait file-agent.exe --uninstall
) else (
  schtasks /Delete /TN file-agent /F >nul 2>&1
)
REM also remove per-port rules (file-agent-8765 ...) that a running daemon may have created
powershell -NoProfile -Command "Get-NetFirewallRule -DisplayName 'file-agent','file-agent-*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match '^file-agent(-\d+)?$' } | Remove-NetFirewallRule -ErrorAction SilentlyContinue"
set tries=0
:killloop
taskkill /F /T /IM file-agent.exe >nul 2>&1
taskkill /F /T /IM file-agent.new.exe >nul 2>&1
tasklist /FI "IMAGENAME eq file-agent.exe" 2>nul | find /I "file-agent.exe" >nul
if %errorlevel% neq 0 goto :killed
set /a tries+=1
if %tries% geq 10 goto :stillrunning
timeout /t 1 /nobreak >nul
goto :killloop
:stillrunning
echo WARNING: file-agent.exe is still running.
:killed
if exist stopped.flag del /f /q stopped.flag >nul 2>&1
schtasks /Query /TN file-agent >nul 2>&1
if %errorlevel% equ 0 (
  echo WARNING: the scheduled task is still registered.
) else (
  echo Scheduled task: removed
)
powershell -NoProfile -Command "if (@(Get-NetFirewallRule -DisplayName 'file-agent','file-agent-*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match '^file-agent(-\d+)?$' }).Count -gt 0) { 'WARNING: firewall rules are still present' } else { 'Firewall rules: removed' }"
echo.
echo Done. Press any key to close.
pause >nul

@echo off
title file-agent installer
REM file-agent installer (fallback when file-agent-ui.exe cannot be used). Self-elevates to admin.
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
if not exist file-agent.exe (
  echo ERROR: file-agent.exe is missing. Extract the whole package first.
  goto :fail
)
if not exist config.json (
  if exist config.template.json (
    copy /y config.template.json config.json >nul
    echo config.json was created from config.template.json.
  ) else (
    echo ERROR: config.json and config.template.json are both missing.
    goto :fail
  )
)
findstr /C:"change-me-please-long-random-token" config.json >nul 2>&1
if %errorlevel% equ 0 (
  echo ERROR: the token in config.json is still the default value.
  echo        Open file-agent-ui.exe, press [New token], then [Save only].
  goto :fail
)
findstr /R /C:"\"token\" *: *\"\"" config.json >nul 2>&1
if %errorlevel% equ 0 (
  echo ERROR: the token in config.json is empty.
  goto :fail
)
echo Installing file-agent ^(firewall + SYSTEM boot task + 5-minute watchdog^)...
echo.
schtasks /End /TN file-agent >nul 2>&1
taskkill /F /T /IM file-agent.exe >nul 2>&1
taskkill /F /T /IM file-agent.new.exe >nul 2>&1
if exist stopped.flag del /f /q stopped.flag >nul 2>&1
REM file-agent.exe is a windowless program: wait for it explicitly.
start "" /wait file-agent.exe --install
set rc=%errorlevel%
if not "%rc%"=="0" (
  echo ERROR: installation failed ^(code %rc%^). The reason is in agent.log in this folder
  echo        ^(for example: backend address missing, default token, network path^).
  goto :fail
)
schtasks /Query /TN file-agent >nul 2>&1
if %errorlevel% neq 0 (
  echo ERROR: the scheduled task was not created. See agent.log in this folder.
  goto :fail
)
echo Done. The daemon now runs in the background, also after reboot.
echo Press any key to close.
pause >nul
exit /b 0

:fail
echo.
echo Press any key to close.
pause >nul
exit /b 2

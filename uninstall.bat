@echo off
title file-agent uninstaller
REM file-agent uninstaller (double-click). Self-elevates to admin.
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Requesting administrator privileges...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
cd /d "%~dp0"
echo.
echo Uninstalling file-agent ^(stop daemon + remove task + firewall^)...
echo.
file-agent.exe --uninstall
taskkill /IM file-agent.exe /F >nul 2>&1
echo.
echo Done. Press any key to close.
pause >nul

@echo off
title file-agent installer
REM file-agent installer (double-click). Self-elevates to admin.
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Requesting administrator privileges...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
cd /d "%~dp0"
echo.
echo Installing file-agent ^(firewall + boot autostart^)...
echo.
file-agent.exe --install
echo.
echo Done. Press any key to close.
pause >nul

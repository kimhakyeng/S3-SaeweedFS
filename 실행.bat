@echo off
chcp 65001 >nul
cd /d "%~dp0"
title File Generator
echo ============================================
echo   File Generator  (Press Ctrl+C to stop)
echo ============================================
echo.

where python >nul 2>nul
if %errorlevel%==0 (
    set PY=python
) else (
    set PY=py
)

echo [Setup] checking psutil ...
%PY% -m pip install psutil >nul 2>nul

%PY% file_generator.py %*

echo.
echo [Finished] Press any key to close.
pause >nul

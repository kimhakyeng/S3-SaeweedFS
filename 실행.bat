@echo off
chcp 65001 >nul
cd /d "%~dp0"
title File Generator
echo ============================================
echo   File Generator 실행
echo   (중지하려면 Ctrl+C)
echo ============================================
echo.

REM python 또는 py 자동 감지
where python >nul 2>nul
if %errorlevel%==0 (
    python file_generator.py %*
) else (
    py file_generator.py %*
)

echo.
echo [종료됨] 창을 닫으려면 아무 키나 누르세요.
pause >nul

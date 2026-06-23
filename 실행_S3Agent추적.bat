@echo off
chcp 65001 >nul
cd /d "%~dp0"
title File Generator (S3Agent RAM 추적)
echo ============================================
echo   File Generator + S3Agent 메모리 추적
echo   (중지하려면 Ctrl+C)
echo ============================================
echo.

REM python 또는 py 자동 감지
where python >nul 2>nul
if %errorlevel%==0 (
    set PY=python
) else (
    set PY=py
)

echo [준비] psutil 설치 확인 중...
%PY% -m pip install psutil >nul 2>nul

%PY% file_generator.py --watch-process S3Agent %*

echo.
echo [종료됨] 창을 닫으려면 아무 키나 누르세요.
pause >nul

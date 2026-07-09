@echo off
REM ============================================================
REM  file-agent rebuild (double-click to run)
REM  ASCII-only on purpose: Windows CMD corrupts non-ASCII .bat text.
REM ============================================================
cd /d "%~dp0"
echo.
echo [file-agent] Building... please wait (1-3 min).
echo.
powershell -ExecutionPolicy Bypass -File "%~dp0build-windows.ps1"
echo.
if %ERRORLEVEL% NEQ 0 (
  echo [FAILED] Build error. See messages above.
) else (
  echo [DONE] dist\file-agent.exe has been rebuilt.
)
echo.
pause

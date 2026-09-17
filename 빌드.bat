@echo off
REM ============================================================
REM  file-agent rebuild (double-click to run)
REM  ASCII-only on purpose: Windows CMD corrupts non-ASCII .bat text.
REM  A running agent is not touched; only build\ and file-agent.zip change.
REM ============================================================
cd /d "%~dp0"
echo.
echo [file-agent] Building... please wait (1-3 min).
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build-windows.ps1"
set rc=%ERRORLEVEL%
if %rc% EQU 3 goto :dirty
if %rc% NEQ 0 goto :failed
goto :done

:dirty
echo.
echo The sources have uncommitted changes. A customer package must be built from a commit.
choice /C YN /M "Build a TEST package anyway (marked dirty, do not ship)"
if errorlevel 2 goto :end
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build-windows.ps1" -AllowDirty
if %ERRORLEVEL% NEQ 0 goto :failed
goto :done

:done
echo [DONE] deploy package has been generated.
echo   ZIP     : file-agent.zip   (one folder inside: file-agent)
echo   HASH    : file-agent.zip.sha256, file-agent.zip.manifest.json
echo   EXE     : build\release-bin\file-agent.exe, file-agent-ui.exe
echo   HISTORY : build\releases
goto :end

:failed
echo [FAILED] Build error. See messages above.

:end
echo.
pause

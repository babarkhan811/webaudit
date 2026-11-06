@echo off
REM ============================================================
REM  webaudit dashboard launcher
REM  Double-click this file to open the dashboard in your browser.
REM ============================================================

REM Always run from the folder this script lives in.
cd /d "%~dp0"

REM Prefer the virtual-env Python; fall back to whatever "python" is on PATH.
set "PY=%~dp0.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"

echo Starting the webaudit dashboard...
echo A browser window will open. Keep this window open while you use it.
echo Close this window (or press Ctrl+C) to stop the dashboard.
echo.

"%PY%" -m webaudit gui

REM If the server exits (or fails to start), keep the window open so any
REM message stays readable instead of the window vanishing instantly.
echo.
echo The dashboard has stopped.
pause

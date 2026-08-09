@echo off
chcp 65001 >nul
cd /d "%~dp0.."
echo ======================================================
echo   JVP Selbst-Check - Sicherheitspruefung deines Netzes
echo ======================================================
echo.
where python >nul 2>nul
if %errorlevel%==0 (
  python selbst_check.py
) else (
  py selbst_check.py
)
echo.
echo Fertig. Fenster mit einer Taste schliessen.
pause >nul

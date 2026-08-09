@echo off
chcp 65001 >nul
cd /d "%~dp0.."
echo ======================================================
echo   JVP Rattenfalle - Angriffs-Falle fuer den Webserver
echo ======================================================
echo.
echo HINWEIS: Fuer ECHTE IP-Sperren diese Datei per Rechtsklick
echo          "Als Administrator ausfuehren" starten.
echo          Ohne Admin laeuft nur der Test-Modus (logonly).
echo.
where python >nul 2>nul
if %errorlevel%==0 (
  python rattenfalle.py --config config.json
) else (
  py rattenfalle.py --config config.json
)
echo.
pause >nul

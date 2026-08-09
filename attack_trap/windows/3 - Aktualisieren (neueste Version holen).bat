@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ======================================================
echo   Neueste Version von GitHub holen (git pull)
echo ======================================================
echo.
where git >nul 2>nul
if %errorlevel%==0 (
  git pull
) else (
  echo FEHLER: Git ist nicht installiert.
  echo Installiere Git von https://git-scm.com/download/win
  echo oder lade das Paket manuell als ZIP von GitHub.
)
echo.
echo Fertig. Fenster mit einer Taste schliessen.
pause >nul

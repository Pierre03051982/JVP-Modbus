@echo off
chcp 65001 >nul
title JVP-Rattenfalle - Einrichtung auf C:\SI-PS\JVPRattenfalle

set "BASE=C:\SI-PS"
set "DIR=%BASE%\JVPRattenfalle"
set "REPO=https://github.com/Pierre03051982/JVP-Modbus.git"
set "BRANCH=claude/webserver-attack-trap-6ipul8"

echo ======================================================
echo   JVP-Rattenfalle nach %DIR% holen
echo ======================================================
echo.

where git >nul 2>nul
if %errorlevel% neq 0 (
  echo FEHLER: Git ist nicht installiert.
  echo Bitte zuerst installieren:  https://git-scm.com/download/win
  echo Danach diese Datei erneut starten.
  echo.
  pause
  exit /b 1
)

if not exist "%BASE%" mkdir "%BASE%"

if exist "%DIR%\.git" (
  echo Ordner ist schon eingerichtet - hole nur die neueste Version ...
  cd /d "%DIR%"
  git pull
) else (
  echo Lade Dateien nach %DIR% ...
  git clone -b %BRANCH% "%REPO%" "%DIR%"
)

if %errorlevel% neq 0 (
  echo.
  echo FEHLER beim Laden. Internetverbindung/Zugriff pruefen.
  pause
  exit /b 1
)

echo.
echo ======================================================
echo   FERTIG. Alles liegt jetzt unter:
echo     %DIR%\attack_trap
echo.
echo   Werkzeuge / Startdateien:
echo     %DIR%\attack_trap\windows
echo.
echo   Naechster Schritt fuer Dauerbetrieb:
echo     dort "4 - Einrichten (Autostart installieren).bat"
echo     per RECHTSKLICK "Als Administrator ausfuehren".
echo ======================================================
echo.
pause

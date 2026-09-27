@echo off
rem JVP Projekt Export/Import - grafische Oberflaeche (startet als Administrator)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0JVP-ProjektBackup.ps1" %*

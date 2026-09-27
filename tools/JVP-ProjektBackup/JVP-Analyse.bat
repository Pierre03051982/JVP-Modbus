@echo off
rem Analyse: sucht JVP-Programme, Dienste, IIS-Ordner, *.prj und JUNG-Verknuepfungen.
rem Optional: Zip-Datei oder Ordner mit von JVP erzeugten Zips auf diese Datei ziehen.
if "%~1"=="" (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0JVP-ProjektBackup.ps1" -Mode Analyse
) else (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0JVP-ProjektBackup.ps1" -Mode Analyse -ZipPath "%~1"
)

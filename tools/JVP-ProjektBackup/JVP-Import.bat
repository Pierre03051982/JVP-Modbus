@echo off
rem Import: Zip-Datei auf diese Datei ziehen (Drag and Drop) oder als Parameter angeben
if "%~1"=="" (
  echo Bitte die Zip-Datei auf JVP-Import.bat ziehen.
  pause
  exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0JVP-ProjektBackup.ps1" -Mode Import -ZipPath "%~1"

@echo off
rem Export ohne Oberflaeche, z.B. fuer die Aufgabenplanung (keine Rueckfrage)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0JVP-ProjektBackup.ps1" -Mode Export -Force %*

@echo off
chcp 65001 >nul
title JVP-Rattenfalle einrichten

:: Administrator-Rechte pruefen (fuer geplante Aufgabe + Firewall noetig)
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo(
  echo Diese Einrichtung braucht Administrator-Rechte.
  echo Bitte diese Datei per RECHTSKLICK  -^>  "Als Administrator ausfuehren".
  echo(
  pause
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0einrichten.ps1"

echo(
pause

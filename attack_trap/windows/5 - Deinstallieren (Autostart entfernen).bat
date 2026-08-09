@echo off
chcp 65001 >nul
title JVP-Rattenfalle deinstallieren

net session >nul 2>&1
if %errorlevel% neq 0 (
  echo(
  echo Bitte diese Datei per RECHTSKLICK  -^>  "Als Administrator ausfuehren".
  echo(
  pause
  exit /b 1
)

echo Stoppe und entferne die geplante Aufgabe "JVP-Rattenfalle" ...
schtasks /End /TN "JVP-Rattenfalle" >nul 2>&1
schtasks /Delete /TN "JVP-Rattenfalle" /F

echo Entferne Firewall-Freigaben ...
for %%p in (8179 8080 2323 8081 8443) do (
  netsh advfirewall firewall delete rule name="JVP-Rattenfalle TCP %%p" >nul 2>&1
)

echo(
echo Autostart entfernt. Die Falle startet nicht mehr automatisch.
echo (Bereits gesetzte Firewall-Sperren bleiben bis zum Ablauf bestehen.)
echo(
pause

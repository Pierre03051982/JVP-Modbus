# Richtet die JVP-Rattenfalle als automatisch startenden Hintergrunddienst ein.
# Wird von "4 - Einrichten (Autostart installieren).bat" aufgerufen.
$ErrorActionPreference = 'Stop'

# Ordner attack_trap (eine Ebene ueber diesem windows-Ordner)
$trapDir = Split-Path -Parent $PSScriptRoot
$script  = Join-Path $trapDir 'rattenfalle.py'
$config  = Join-Path $trapDir 'config.json'

Write-Host '======================================================'
Write-Host '  JVP-Rattenfalle - Autostart einrichten'
Write-Host '======================================================'

if (-not (Test-Path $script)) {
    Write-Host "FEHLER: rattenfalle.py nicht gefunden in $trapDir" -ForegroundColor Red
    exit 1
}

# Python finden (python oder py)
$py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $py) { $py = (Get-Command py -ErrorAction SilentlyContinue).Source }
if (-not $py) {
    Write-Host 'FEHLER: Python nicht gefunden.' -ForegroundColor Red
    Write-Host 'Bitte von https://www.python.org/downloads/ installieren'
    Write-Host 'und dabei "Add python.exe to PATH" anhaken.'
    exit 1
}

Write-Host "Python : $py"
Write-Host "Skript : $script"
Write-Host ''

# Aufgabe anlegen: Start beim Systemstart, als SYSTEM mit hoechsten Rechten
# (SYSTEM-Rechte werden fuer die Firewall-Sperren via netsh benoetigt).
$arg       = '"{0}" --config "{1}"' -f $script, $config
$action    = New-ScheduledTaskAction -Execute $py -Argument $arg -WorkingDirectory $trapDir
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
                -DontStopIfGoingOnBatteries -RestartCount 3 `
                -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName 'JVP-Rattenfalle' -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings `
    -Description 'JVP Rattenfalle - defensive Angriffs-Falle (Autostart)' -Force | Out-Null

# sofort starten
Start-ScheduledTask -TaskName 'JVP-Rattenfalle'

Write-Host 'FERTIG.' -ForegroundColor Green
Write-Host '  * Die Rattenfalle laeuft ab jetzt automatisch bei jedem Windows-Start.'
Write-Host '  * Sie laeuft im Hintergrund und sperrt Angreifer per Firewall.'
Write-Host ''
Write-Host 'Status pruefen:  python rattenfalle.py --status'
Write-Host 'Entfernen:       "5 - Deinstallieren (Autostart entfernen).bat"'

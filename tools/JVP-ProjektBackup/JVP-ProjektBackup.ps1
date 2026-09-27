<#
.SYNOPSIS
    Export / Import der JUNG Visu Pro (JVP) Projektdateien (Visu + PRJ) als eine Zip-Datei.

.DESCRIPTION
    Export:  Programme (SDV, KNX, ...) sauber beenden ("Wirklich beenden?" wird bestaetigt),
             Dienste und IIS stoppen, alle konfigurierten Projektordner sowie die aus den
             Projektdateien (*.prj, ...) referenzierten Dateien in EINE Zip packen,
             danach alles wieder starten.
    Import:  Zip pruefen (SHA256), alles stoppen, Sicherheits-Export des aktuellen Stands,
             Projektdateien ueberschreiben (optional Ordner spiegeln), alles wieder starten.
    Analyse: Sucht auf dem Server nach JUNG-Verknuepfungen (z.B. "Import und Export der
             Projektdaten"), JVP-Prozessen, -Diensten, IIS-Verzeichnissen und *.prj-Dateien
             und schreibt einen Bericht + Konfigurationsvorschlag.

    Ohne Parameter startet eine grafische Oberflaeche.

.EXAMPLE
    .\JVP-ProjektBackup.ps1 -Mode Export -OutputFolder D:\JVP-Backup
.EXAMPLE
    .\JVP-ProjektBackup.ps1 -Mode Import -ZipPath D:\JVP-Backup\JVP-Projekt_SERVER_20260927_120000.zip
.EXAMPLE
    .\JVP-ProjektBackup.ps1 -Mode Analyse
#>
[CmdletBinding()]
param(
    [ValidateSet('Gui', 'Export', 'Import', 'Analyse')]
    [string]$Mode = 'Gui',
    [string]$ConfigPath,
    [string]$OutputFolder,
    [string]$ZipPath,
    # Nur kopieren, nichts beenden/stoppen (z.B. zum Testen)
    [switch]$NoStop,
    # Beim Import keinen Sicherheits-Export des aktuellen Stands anlegen
    [switch]$NoSafetyBackup,
    # Keine Rueckfragen (fuer Aufgabenplanung / Skripte)
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$script:ToolVersion  = '1.0.0'
$script:FormatName   = 'JVP-ProjektBackup'
$script:ScriptDir    = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:IsWin        = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
$script:LogFile      = $null
$script:LogBox       = $null

if (-not $ConfigPath) { $ConfigPath = Join-Path $script:ScriptDir 'JVP-ProjektBackup.config.json' }

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

#region Allgemein ---------------------------------------------------------------------------

function Write-Log {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'FEHLER', 'OK')][string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'WARN'   { Write-Host $line -ForegroundColor Yellow }
        'FEHLER' { Write-Host $line -ForegroundColor Red }
        'OK'     { Write-Host $line -ForegroundColor Green }
        default  { Write-Host $line }
    }
    if ($script:LogFile) {
        try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 } catch { }
    }
    if ($script:LogBox) {
        $script:LogBox.AppendText($line + [Environment]::NewLine)
        [System.Windows.Forms.Application]::DoEvents()
    }
}

function Expand-PathVars {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    return [Environment]::ExpandEnvironmentVariables($Path)
}

function Get-Prop {
    # Liest eine optionale Eigenschaft aus einem JSON-Objekt (StrictMode-sicher)
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p -or $null -eq $p.Value) { return $Default }
    return $p.Value
}

function Read-Config {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Konfigurationsdatei nicht gefunden: $Path" }
    $cfg = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not (Get-Prop $cfg 'Sources')) { throw "In der Konfiguration sind keine 'Sources' eingetragen." }
    return $cfg
}

function Initialize-Log {
    param([string]$Folder, [string]$Name)
    try {
        $logDir = Join-Path $Folder 'Logs'
        if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
        $script:LogFile = Join-Path $logDir ('{0}_{1}.log' -f $Name, (Get-Date -Format 'yyyyMMdd_HHmmss'))
    } catch {
        $script:LogFile = $null
    }
}

function Test-IsAdmin {
    if (-not $script:IsWin) { return $true }
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RelativePathSafe {
    param([string]$Root, [string]$FullPath)
    $r = $Root.TrimEnd('\', '/')
    return $FullPath.Substring($r.Length).TrimStart('\', '/').Replace('\', '/')
}

function Test-Wildcards {
    # $RelPath mit '/' - Muster duerfen '\' oder '/' enthalten
    param([string]$RelPath, $Patterns)
    if ($null -eq $Patterns) { return $false }
    $name = $RelPath.Split('/')[-1]
    foreach ($p in @($Patterns)) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        $pat = ([string]$p).Replace('\', '/')
        if ($RelPath -like $pat -or $name -like $pat) { return $true }
        # "Ordner/*" soll auch Unterordner treffen
        if ($pat.EndsWith('/*') -and $RelPath -like ($pat.Substring(0, $pat.Length - 1) + '*')) { return $true }
    }
    return $false
}

function Get-FilesRecursive {
    # Robuste Dateiaufzaehlung: ueberspringt gesperrte Ordner und Verknuepfungspunkte (Junctions)
    param([string]$Root, [int]$MaxDepth = 64, [string[]]$SkipDirNames = @())
    $result = New-Object System.Collections.Generic.List[string]
    if (-not [IO.Directory]::Exists($Root)) { return , $result }
    $stack = New-Object System.Collections.Generic.Stack[object]
    $stack.Push(@($Root, 0))
    while ($stack.Count -gt 0) {
        $item = $stack.Pop()
        $dir = [string]$item[0]; $depth = [int]$item[1]
        try {
            foreach ($f in [IO.Directory]::GetFiles($dir)) { $result.Add($f) }
            if ($depth -lt $MaxDepth) {
                foreach ($d in [IO.Directory]::GetDirectories($dir)) {
                    $leaf = [IO.Path]::GetFileName($d)
                    if ($SkipDirNames -contains $leaf) { continue }
                    $attr = [IO.File]::GetAttributes($d)
                    if (($attr -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                    $stack.Push(@($d, ($depth + 1)))
                }
            }
        } catch {
            Write-Log "Kein Zugriff auf '$dir': $($_.Exception.Message)" 'WARN'
        }
    }
    return , $result
}

function Get-StreamSha256 {
    param([IO.Stream]$Stream)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Stream))).Replace('-', '') }
    finally { $sha.Dispose() }
}

function Get-FileSha256 {
    param([string]$Path)
    $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try { return Get-StreamSha256 $fs } finally { $fs.Dispose() }
}

function ConvertTo-SafeName {
    param([string]$Name)
    $n = $Name
    foreach ($c in [IO.Path]::GetInvalidFileNameChars()) { $n = $n.Replace([string]$c, '_') }
    return $n.Replace(' ', '_')
}

#endregion

#region Win32 (Fenster / Dialoge) ----------------------------------------------------------

function Initialize-Win32 {
    if (-not $script:IsWin) { return }
    if ('JvpWin' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class JvpWin {
    private delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumProc cb, IntPtr lParam);
    [DllImport("user32.dll")] private static extern bool EnumChildWindows(IntPtr parent, EnumProc cb, IntPtr lParam);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetClassName(IntPtr hWnd, StringBuilder sb, int max);
    [DllImport("user32.dll")] private static extern bool PostMessage(IntPtr hWnd, uint msg, IntPtr w, IntPtr l);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint msg, IntPtr w, StringBuilder l, uint flags, uint timeout, out IntPtr result);
    [DllImport("user32.dll")]
    private static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint msg, IntPtr w, IntPtr l, uint flags, uint timeout, out IntPtr result);

    private const uint WM_CLOSE = 0x0010, WM_GETTEXT = 0x000D, WM_GETTEXTLENGTH = 0x000E, BM_CLICK = 0x00F5;
    private const uint SMTO_ABORTIFHUNG = 0x0002;

    public static IntPtr[] TopWindows(int pid) {
        var list = new List<IntPtr>();
        EnumWindows((h, l) => { uint p; GetWindowThreadProcessId(h, out p); if (p == (uint)pid) list.Add(h); return true; }, IntPtr.Zero);
        return list.ToArray();
    }
    public static IntPtr[] Children(IntPtr parent) {
        var list = new List<IntPtr>();
        EnumChildWindows(parent, (h, l) => { list.Add(h); return true; }, IntPtr.Zero);
        return list.ToArray();
    }
    public static string ClassOf(IntPtr h) {
        var sb = new StringBuilder(256); GetClassName(h, sb, sb.Capacity); return sb.ToString();
    }
    public static string TextOf(IntPtr h) {
        IntPtr len;
        if (SendMessageTimeout(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero, SMTO_ABORTIFHUNG, 1000, out len) == IntPtr.Zero) return "";
        int n = len.ToInt32(); if (n <= 0) return ""; if (n > 4096) n = 4096;
        var sb = new StringBuilder(n + 1); IntPtr r;
        SendMessageTimeout(h, WM_GETTEXT, new IntPtr(sb.Capacity), sb, SMTO_ABORTIFHUNG, 1000, out r);
        return sb.ToString();
    }
    public static void PostClose(IntPtr h) { PostMessage(h, WM_CLOSE, IntPtr.Zero, IntPtr.Zero); }
    public static void Click(IntPtr h) { IntPtr r; SendMessageTimeout(h, BM_CLICK, IntPtr.Zero, IntPtr.Zero, SMTO_ABORTIFHUNG, 3000, out r); }
}
'@
}

$script:SystemWindowClasses = @('IME', 'MSCTFIME UI', 'GDI+ Hook Window Class', 'tooltips_class32', 'OleMainThreadWndClass', 'CicMarshalWndClass')

function Test-SystemWindowClass {
    param([string]$Class)
    if ($script:SystemWindowClasses -contains $Class) { return $true }
    if ($Class -like '.NET-BroadcastEventWindow*' -or $Class -like '*SystemEvent*' -or $Class -like 'HwndWrapper*Broadcast*') { return $true }
    return $false
}

function Invoke-ConfirmDialogs {
    # Sucht sichtbare Fenster des Prozesses mit passendem Text ("beenden", "speichern" ...)
    # und klickt die Bestaetigungs-Schaltflaeche ("Ja", "Yes", "OK" ...). Gibt $true zurueck, wenn geklickt wurde.
    param([int]$ProcessId, $DialogTexts, $Buttons)
    $clicked = $false
    foreach ($h in [JvpWin]::TopWindows($ProcessId)) {
        if (-not [JvpWin]::IsWindowVisible($h)) { continue }
        $children = [JvpWin]::Children($h)
        $texts = New-Object System.Collections.Generic.List[string]
        $texts.Add([JvpWin]::TextOf($h))
        foreach ($c in $children) { $texts.Add([JvpWin]::TextOf($c)) }
        $allText = ($texts -join ' | ')

        $match = $false
        foreach ($t in @($DialogTexts)) { if ($allText -like "*$t*") { $match = $true; break } }

        # Win32 / WinForms Schaltflaechen
        if ($match) {
            foreach ($c in $children) {
                $cls = [JvpWin]::ClassOf($c)
                if ($cls -notlike '*BUTTON*' -and $cls -notlike '*Button*') { continue }
                if (-not [JvpWin]::IsWindowVisible($c)) { continue }
                $bt = ([JvpWin]::TextOf($c)).Replace('&', '').Trim()
                foreach ($b in @($Buttons)) {
                    if ($bt -ieq ([string]$b).Replace('&', '').Trim()) {
                        Write-Log "  Dialog '$([JvpWin]::TextOf($h))' erkannt ('$($allText.Substring(0, [Math]::Min(120, $allText.Length)))') -> klicke '$bt'"
                        [JvpWin]::SetForegroundWindow($h) | Out-Null
                        [JvpWin]::Click($c)
                        $clicked = $true
                        break
                    }
                }
                if ($clicked) { break }
            }
        }

        # Fallback: UI Automation (WPF-Dialoge haben keine eigenen Fenster-Handles fuer Schaltflaechen)
        if (-not $clicked) {
            try {
                $clicked = Invoke-ConfirmDialogUia -Handle $h -DialogTexts $DialogTexts -Buttons $Buttons -AlreadyMatched:$match
            } catch { }
        }
        if ($clicked) { break }
    }
    return $clicked
}

function Invoke-ConfirmDialogUia {
    param([IntPtr]$Handle, $DialogTexts, $Buttons, [switch]$AlreadyMatched)
    if (-not ('System.Windows.Automation.AutomationElement' -as [type])) {
        Add-Type -AssemblyName UIAutomationClient
        Add-Type -AssemblyName UIAutomationTypes
    }
    $el = [System.Windows.Automation.AutomationElement]::FromHandle($Handle)
    if ($null -eq $el) { return $false }
    $all = $el.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
    $names = New-Object System.Collections.Generic.List[string]
    $names.Add($el.Current.Name)
    $btns = @()
    foreach ($e in $all) {
        $names.Add($e.Current.Name)
        if ($e.Current.ControlType -eq [System.Windows.Automation.ControlType]::Button) { $btns += $e }
    }
    $allText = $names -join ' | '
    $match = [bool]$AlreadyMatched
    if (-not $match) { foreach ($t in @($DialogTexts)) { if ($allText -like "*$t*") { $match = $true; break } } }
    if (-not $match) { return $false }
    foreach ($btn in $btns) {
        $bt = ([string]$btn.Current.Name).Replace('&', '').Trim()
        foreach ($b in @($Buttons)) {
            if ($bt -ieq ([string]$b).Replace('&', '').Trim()) {
                Write-Log "  Dialog (UIA) erkannt -> klicke '$bt'"
                $pat = $btn.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
                $pat.Invoke()
                return $true
            }
        }
    }
    return $false
}

#endregion

#region Programme / Dienste / IIS stoppen und starten ---------------------------------------

function Get-ProcessInfo {
    param([System.Diagnostics.Process]$Process)
    $path = $null; $cmd = $null
    try { $path = $Process.MainModule.FileName } catch { }
    try {
        $wmi = Get-CimInstance Win32_Process -Filter "ProcessId=$($Process.Id)" -ErrorAction Stop
        $cmd = $wmi.CommandLine
        if (-not $path) { $path = $wmi.ExecutablePath }
    } catch { }
    $procArgs = ''
    if ($cmd -and $path) {
        $c = $cmd.Trim()
        if ($c.StartsWith('"')) { $end = $c.IndexOf('"', 1); if ($end -gt 0) { $procArgs = $c.Substring($end + 1).Trim() } }
        elseif ($c.ToLower().StartsWith($path.ToLower())) { $procArgs = $c.Substring($path.Length).Trim() }
        else { $sp = $c.IndexOf(' '); if ($sp -gt 0) { $procArgs = $c.Substring($sp + 1).Trim() } }
    }
    return [pscustomobject]@{ Id = $Process.Id; Name = $Process.ProcessName; Path = $path; Arguments = $procArgs }
}

function Stop-JvpProgram {
    # Beendet ein Programm "sauber" und bestaetigt die Rueckfrage "Wirklich beenden?".
    # Gibt Liste der beendeten Prozesse (fuer den Neustart) zurueck.
    param($ProgramCfg, $Config)
    $name        = Get-Prop $ProgramCfg 'Name' (Get-Prop $ProgramCfg 'ProcessName')
    $procPattern = Get-Prop $ProgramCfg 'ProcessName'
    $texts       = @(Get-Prop $ProgramCfg 'ConfirmDialogTexts' @('beenden', 'speichern'))
    $buttons     = @(Get-Prop $ProgramCfg 'ConfirmButtons' @('Ja', 'Yes', 'OK'))
    $timeout     = [int](Get-Prop $ProgramCfg 'CloseTimeoutSeconds' 90)
    $kill        = [bool](Get-Prop $ProgramCfg 'KillIfNotClosed' (Get-Prop $Config 'KillIfNotClosed' $false))

    $stopped = @()
    $procs = @(Get-Process -Name $procPattern -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $PID })
    if ($procs.Count -eq 0) {
        Write-Log "Programm '$name' ($procPattern) laeuft nicht."
        return , $stopped
    }
    foreach ($p in $procs) {
        $info = Get-ProcessInfo $p
        Write-Log "Beende Programm '$name' ($($p.ProcessName), PID $($p.Id), Sitzung $($p.SessionId))"
        if ($p.SessionId -ne (Get-Process -Id $PID).SessionId) {
            Write-Log "  Achtung: '$($p.ProcessName)' laeuft in einer anderen Windows-Sitzung (Sitzung $($p.SessionId)). Die Rueckfrage kann von hier aus evtl. nicht bestaetigt werden - Tool in derselben Sitzung ausfuehren." 'WARN'
        }

        # 1) sauber schliessen (wie Klick auf X / Menue Beenden)
        $sent = $false
        try { $p.Refresh(); if ($p.MainWindowHandle -ne [IntPtr]::Zero) { $sent = $p.CloseMainWindow() } } catch { }
        if (-not $sent) {
            # Programm liegt z.B. nur im Infobereich (Tray) -> WM_CLOSE an seine Fenster
            foreach ($h in [JvpWin]::TopWindows($p.Id)) {
                $cls = [JvpWin]::ClassOf($h)
                if (Test-SystemWindowClass $cls) { continue }
                if ([string]::IsNullOrEmpty([JvpWin]::TextOf($h)) -and $cls -notlike 'WindowsForms*' -and $cls -notlike 'HwndWrapper*') { continue }
                [JvpWin]::PostClose($h); $sent = $true
            }
        }
        if (-not $sent) { Write-Log "  Kein Fenster zum Schliessen gefunden." 'WARN' }

        # 2) warten, dabei "Wirklich beenden?" / "Speichern?" bestaetigen
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $retried = $false
        while (-not $p.HasExited -and $sw.Elapsed.TotalSeconds -lt $timeout) {
            $null = Invoke-ConfirmDialogs -ProcessId $p.Id -DialogTexts $texts -Buttons $buttons
            Start-Sleep -Milliseconds 400
            if (-not $retried -and $sw.Elapsed.TotalSeconds -gt 15 -and -not $p.HasExited) {
                # zweiter Versuch: WM_CLOSE an alle (nicht System-) Fenster
                $retried = $true
                foreach ($h in [JvpWin]::TopWindows($p.Id)) {
                    if (-not (Test-SystemWindowClass ([JvpWin]::ClassOf($h)))) { [JvpWin]::PostClose($h) }
                }
            }
            try { $p.Refresh() } catch { }
        }

        if (-not $p.HasExited) {
            if ($kill) {
                Write-Log "  '$name' hat sich nach $timeout s nicht beendet -> wird hart beendet (KillIfNotClosed)." 'WARN'
                Stop-Process -Id $p.Id -Force
                $p.WaitForExit(10000) | Out-Null
            } else {
                throw "Programm '$name' (PID $($p.Id)) hat sich nach $timeout s nicht beendet. Bitte manuell beenden und erneut starten (oder 'KillIfNotClosed' setzen)."
            }
        }
        Write-Log "  '$name' beendet." 'OK'
        $stopped += [pscustomobject]@{ Config = $ProgramCfg; Info = $info }
    }
    return , $stopped
}

function Start-JvpProgram {
    param($Stopped, $Config)
    $info = $Stopped.Info
    $cfg  = $Stopped.Config
    if (-not [bool](Get-Prop $cfg 'Restart' $true)) { return }
    $exe = Expand-PathVars (Get-Prop $cfg 'ExePath' $info.Path)
    if (-not $exe -or -not (Test-Path -LiteralPath $exe)) {
        Write-Log "Programm '$($info.Name)' kann nicht neu gestartet werden (Pfad unbekannt: '$exe')." 'WARN'
        return
    }
    $procArgs = Get-Prop $cfg 'Arguments' $info.Arguments
    $wd = Split-Path -Parent $exe
    Write-Log "Starte Programm '$($info.Name)': $exe $procArgs"
    try {
        if ([bool](Get-Prop $Config 'StartProgramsUnelevated' $true) -and [string]::IsNullOrWhiteSpace($procArgs)) {
            # ueber den Explorer starten -> laeuft wieder mit normalen Benutzerrechten
            Start-Process -FilePath (Join-Path $env:SystemRoot 'explorer.exe') -ArgumentList ('"{0}"' -f $exe)
        } elseif ([string]::IsNullOrWhiteSpace($procArgs)) {
            Start-Process -FilePath $exe -WorkingDirectory $wd
        } else {
            Start-Process -FilePath $exe -ArgumentList $procArgs -WorkingDirectory $wd
        }
    } catch {
        Write-Log "  Start fehlgeschlagen: $($_.Exception.Message)" 'FEHLER'
    }
}

function Stop-JvpEnvironment {
    # Reihenfolge: Programme -> Dienste -> IIS. Gibt Status-Objekt fuer Start-JvpEnvironment zurueck.
    # $State wird schrittweise gefuellt, damit bei einem Fehler das bereits Gestoppte wieder gestartet wird.
    param($Config, $State)
    Initialize-Win32
    $state = $State

    foreach ($pc in @(Get-Prop $Config 'Programs' @())) {
        $state.Programs += @(Stop-JvpProgram -ProgramCfg $pc -Config $Config)
    }

    foreach ($sc in @(Get-Prop $Config 'Services' @())) {
        $svcName = if ($sc -is [string]) { $sc } else { Get-Prop $sc 'Name' }
        foreach ($svc in @(Get-Service -Name $svcName -ErrorAction SilentlyContinue)) {
            if ($svc.Status -eq 'Running') {
                Write-Log "Stoppe Dienst '$($svc.DisplayName)' ($($svc.Name))"
                Stop-Service -Name $svc.Name -Force
                $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(120))
                $state.Services += $svc.Name
                Write-Log "  Dienst gestoppt." 'OK'
            } else {
                Write-Log "Dienst '$($svc.Name)' laeuft nicht ($($svc.Status))."
            }
        }
    }

    if ([bool](Get-Prop $Config 'StopIIS' $true)) {
        $w3 = Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue
        if ($null -eq $w3) {
            Write-Log 'IIS (W3SVC) ist nicht installiert.' 'WARN'
        } elseif ($w3.Status -ne 'Running') {
            Write-Log "IIS laeuft nicht ($($w3.Status))."
        } else {
            Write-Log 'Stoppe IIS (iisreset /stop) ...'
            $iisreset = Join-Path $env:SystemRoot 'System32\iisreset.exe'
            if (Test-Path -LiteralPath $iisreset) {
                & $iisreset /stop | ForEach-Object { Write-Log "  $_" }
            } else {
                Stop-Service -Name 'W3SVC' -Force
                Stop-Service -Name 'WAS' -Force -ErrorAction SilentlyContinue
            }
            (Get-Service -Name 'W3SVC').WaitForStatus('Stopped', [TimeSpan]::FromSeconds(120))
            $state.IIS = $true
            Write-Log 'IIS gestoppt.' 'OK'
        }
    }
}

function New-JvpState {
    return [pscustomobject]@{ Programs = @(); Services = @(); IIS = $false }
}

function Start-JvpEnvironment {
    # Reihenfolge: IIS -> Dienste -> Programme (nur was vorher lief)
    param($State, $Config)
    if ($null -eq $State) { return }
    if ($State.IIS) {
        Write-Log 'Starte IIS (iisreset /start) ...'
        try {
            $iisreset = Join-Path $env:SystemRoot 'System32\iisreset.exe'
            if (Test-Path -LiteralPath $iisreset) { & $iisreset /start | ForEach-Object { Write-Log "  $_" } }
            else { Start-Service -Name 'WAS' -ErrorAction SilentlyContinue; Start-Service -Name 'W3SVC' }
            Write-Log 'IIS gestartet.' 'OK'
        } catch { Write-Log "IIS-Start fehlgeschlagen: $($_.Exception.Message)" 'FEHLER' }
    }
    $svcs = @($State.Services); [array]::Reverse($svcs)
    foreach ($s in $svcs) {
        Write-Log "Starte Dienst '$s'"
        try { Start-Service -Name $s; Write-Log '  Dienst gestartet.' 'OK' }
        catch { Write-Log "  Start fehlgeschlagen: $($_.Exception.Message)" 'FEHLER' }
    }
    $delay = [int](Get-Prop $Config 'ProgramStartDelaySeconds' 5)
    if (@($State.Programs).Count -gt 0 -and $delay -gt 0) { Start-Sleep -Seconds $delay }
    foreach ($p in @($State.Programs)) { Start-JvpProgram -Stopped $p -Config $Config }
}

#endregion

#region Export --------------------------------------------------------------------------------

function Get-ReferencedFiles {
    # Liest Projektdateien (*.prj ...) als Text und sucht darin absolute Windows-Pfade auf vorhandene Dateien
    param([string[]]$ProjectFiles, $Config, [string[]]$AlreadyIncluded)
    $found = New-Object System.Collections.Generic.List[string]
    $included = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($f in $AlreadyIncluded) { [void]$included.Add($f) }
    $excludeRoots = @(@(Get-Prop $Config 'ReferenceExcludeRoots' @('%SystemRoot%', '%ProgramFiles%', '%ProgramFiles(x86)%')) |
        ForEach-Object { (Expand-PathVars $_).TrimEnd('\') + '\' } | Where-Object { $_ -ne '\' })
    $rx = New-Object Text.RegularExpressions.Regex('(?i)(?<![A-Za-z])[A-Z]:\\(?:[^\\/:*?"<>|\r\n\t]+\\)*[^\\/:*?"<>|\r\n\t]+')

    foreach ($pf in $ProjectFiles) {
        try {
            if ((New-Object IO.FileInfo $pf).Length -gt 50MB) { continue }
            $text = [IO.File]::ReadAllText($pf)
        } catch { continue }
        $text = $text.Replace('&amp;', '&').Replace('&quot;', '"').Replace('\\', '\')
        foreach ($m in $rx.Matches($text)) {
            $cand = $m.Value.Trim()
            # Treffer kann Text dahinter enthalten -> von hinten kuerzen bis eine Datei existiert
            $ok = $null
            for ($i = 0; $i -lt 6 -and $cand.Length -gt 3; $i++) {
                if ([IO.File]::Exists($cand)) { $ok = $cand; break }
                $cut = $cand.LastIndexOfAny([char[]]@(' ', ',', ';', "'", ')', ']', '}'))
                if ($cut -le 3) { break }
                $cand = $cand.Substring(0, $cut).TrimEnd()
            }
            if (-not $ok) { continue }
            $full = [IO.Path]::GetFullPath($ok)
            $skip = $false
            foreach ($er in $excludeRoots) { if ($full.StartsWith($er, [StringComparison]::OrdinalIgnoreCase)) { $skip = $true; break } }
            if ($skip -or $included.Contains($full)) { continue }
            [void]$included.Add($full)
            $found.Add($full)
            Write-Log "  Referenzierte Datei aus '$([IO.Path]::GetFileName($pf))': $full"
        }
    }
    return , $found
}

function Export-JvpProject {
    # Packt alle Quellen in eine Zip. Setzt voraus, dass Programme/Dienste bereits gestoppt sind (oder -NoStop).
    param($Config, [string]$TargetFolder, [string]$Suffix = '')
    $TargetFolder = Expand-PathVars $TargetFolder
    if (-not (Test-Path -LiteralPath $TargetFolder)) { New-Item -ItemType Directory -Path $TargetFolder -Force | Out-Null }
    $prefix = Get-Prop $Config 'ZipPrefix' 'JVP-Projekt'
    $zipName = '{0}_{1}_{2}{3}.zip' -f $prefix, (ConvertTo-SafeName ([Environment]::MachineName)), (Get-Date -Format 'yyyyMMdd_HHmmss'), $Suffix
    $zipPath = Join-Path $TargetFolder $zipName
    $partPath = $zipPath + '.part'
    if (Test-Path -LiteralPath $partPath) { Remove-Item -LiteralPath $partPath -Force }

    $scanExt = @(@(Get-Prop $Config 'ReferenceScanExtensions' @('.prj')) | ForEach-Object { ([string]$_).ToLower() })
    $scanRefs = [bool](Get-Prop $Config 'ScanProjectFilesForReferences' $true)

    $manifest = [ordered]@{
        Format        = $script:FormatName
        FormatVersion = 1
        ToolVersion   = $script:ToolVersion
        Created       = (Get-Date).ToString('o')
        Computer      = [Environment]::MachineName
        User          = [Environment]::UserName
        Sources       = @()
        Files         = @()
        Referenced    = @()
    }

    $allIncluded = New-Object System.Collections.Generic.List[string]
    $projectFiles = New-Object System.Collections.Generic.List[string]
    $totalFiles = 0; [long]$totalBytes = 0

    $zip = [IO.Compression.ZipFile]::Open($partPath, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($src in @($Config.Sources)) {
            $srcName = [string](Get-Prop $src 'Name')
            $root = Expand-PathVars ([string](Get-Prop $src 'Path'))
            $optional = [bool](Get-Prop $src 'Optional' $false)
            if ([string]::IsNullOrWhiteSpace($srcName) -or [string]::IsNullOrWhiteSpace($root)) { throw "Quelle ohne 'Name' oder 'Path' in der Konfiguration." }
            if (-not [IO.Directory]::Exists($root)) {
                if ($optional) { Write-Log "Quelle '$srcName' nicht vorhanden, uebersprungen: $root" 'WARN'; continue }
                throw "Quelle '$srcName' nicht gefunden: $root"
            }
            $root = [IO.Path]::GetFullPath($root).TrimEnd('\', '/')
            $include = @(Get-Prop $src 'Include' @('*'))
            $exclude = @(Get-Prop $src 'Exclude' @())
            Write-Log "Sichere Quelle '$srcName': $root"
            $count = 0; [long]$bytes = 0
            foreach ($file in (Get-FilesRecursive -Root $root)) {
                $rel = Get-RelativePathSafe -Root $root -FullPath $file
                if (-not (Test-Wildcards $rel $include)) { continue }
                if (Test-Wildcards $rel $exclude) { continue }
                $entryName = 'files/{0}/{1}' -f (ConvertTo-SafeName $srcName), $rel
                $hash = Get-FileSha256 $file
                [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $file, $entryName, [IO.Compression.CompressionLevel]::Optimal)
                $len = (New-Object IO.FileInfo $file).Length
                $manifest.Files += [ordered]@{ Entry = $entryName; Source = $srcName; Relative = $rel; Size = $len; Sha256 = $hash }
                $allIncluded.Add([IO.Path]::GetFullPath($file))
                if ($scanExt -contains ([IO.Path]::GetExtension($file).ToLower())) { $projectFiles.Add($file) }
                $count++; $bytes += $len
            }
            $manifest.Sources += [ordered]@{ Name = $srcName; Path = $root; FileCount = $count; Bytes = $bytes }
            Write-Log ("  {0} Dateien, {1:N1} MB" -f $count, ($bytes / 1MB)) 'OK'
            $totalFiles += $count; $totalBytes += $bytes
        }

        # Dateien, die in den Projektdateien (PRJ/Visu) referenziert sind, aber ausserhalb der Quellordner liegen
        if ($scanRefs -and $projectFiles.Count -gt 0) {
            Write-Log "Durchsuche $($projectFiles.Count) Projektdatei(en) nach verknuepften Dateien ..."
            $refs = Get-ReferencedFiles -ProjectFiles $projectFiles.ToArray() -Config $Config -AlreadyIncluded $allIncluded.ToArray()
            $i = 0
            foreach ($r in $refs) {
                $i++
                $entryName = 'referenced/{0:D4}/{1}' -f $i, [IO.Path]::GetFileName($r)
                $hash = Get-FileSha256 $r
                [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $r, $entryName, [IO.Compression.CompressionLevel]::Optimal)
                $len = (New-Object IO.FileInfo $r).Length
                $manifest.Referenced += [ordered]@{ Entry = $entryName; OriginalPath = $r; Size = $len; Sha256 = $hash }
                $totalFiles++; $totalBytes += $len
            }
            Write-Log "  $($refs.Count) zusaetzliche verknuepfte Datei(en) gesichert." 'OK'
        }

        if ($totalFiles -eq 0) { throw 'Es wurden keine Dateien gefunden - bitte Pfade in der Konfiguration pruefen (Modus Analyse hilft).' }

        $entry = $zip.CreateEntry('manifest.json')
        $w = New-Object IO.StreamWriter($entry.Open(), (New-Object Text.UTF8Encoding($false)))
        try { $w.Write(($manifest | ConvertTo-Json -Depth 6)) } finally { $w.Dispose() }
    } catch {
        $zip.Dispose(); $zip = $null
        Remove-Item -LiteralPath $partPath -Force -ErrorAction SilentlyContinue
        throw
    } finally {
        if ($null -ne $zip) { $zip.Dispose() }
    }
    Move-Item -LiteralPath $partPath -Destination $zipPath -Force
    Write-Log ("Export fertig: {0} ({1} Dateien, {2:N1} MB unkomprimiert, Zip {3:N1} MB)" -f $zipPath, $totalFiles, ($totalBytes / 1MB), ((Get-Item -LiteralPath $zipPath).Length / 1MB)) 'OK'
    return $zipPath
}

#endregion

#region Import --------------------------------------------------------------------------------

function Read-ZipManifest {
    param([IO.Compression.ZipArchive]$Zip)
    $me = $Zip.GetEntry('manifest.json')
    if ($null -eq $me) { throw 'Die Zip-Datei enthaelt keine manifest.json - kein Export dieses Tools.' }
    $r = New-Object IO.StreamReader($me.Open(), [Text.Encoding]::UTF8)
    try { $m = $r.ReadToEnd() | ConvertFrom-Json } finally { $r.Dispose() }
    if ((Get-Prop $m 'Format') -ne $script:FormatName) { throw "Unbekanntes Zip-Format '$(Get-Prop $m 'Format')'." }
    if ([int](Get-Prop $m 'FormatVersion' 0) -gt 1) { throw 'Die Zip-Datei wurde mit einer neueren Tool-Version erstellt.' }
    return $m
}

function Test-ZipIntegrity {
    param([IO.Compression.ZipArchive]$Zip, $Manifest)
    Write-Log 'Pruefe Zip-Datei (SHA256) ...'
    $items = @(@(Get-Prop $Manifest 'Files' @()) + @(Get-Prop $Manifest 'Referenced' @()))
    foreach ($f in $items) {
        $e = $Zip.GetEntry($f.Entry)
        if ($null -eq $e) { throw "Eintrag fehlt in der Zip: $($f.Entry)" }
        $s = $e.Open()
        try { $h = Get-StreamSha256 $s } finally { $s.Dispose() }
        if ($h -ne $f.Sha256) { throw "Pruefsumme falsch (Zip beschaedigt?): $($f.Entry)" }
    }
    Write-Log "  $($items.Count) Dateien in Ordnung." 'OK'
}

function Get-ImportPlan {
    # Zielpfad je Quelle: Pfad aus der aktuellen Konfiguration (gleicher Name) hat Vorrang, sonst Originalpfad
    param($Manifest, $Config)
    $plan = @()
    foreach ($s in @(Get-Prop $Manifest 'Sources' @())) {
        $cfgSrc = @($Config.Sources) | Where-Object { (Get-Prop $_ 'Name') -eq $s.Name } | Select-Object -First 1
        $target = if ($cfgSrc) { Expand-PathVars (Get-Prop $cfgSrc 'Path') } else { $s.Path }
        $mirror = [bool](Get-Prop $cfgSrc 'MirrorOnImport' (Get-Prop $Config 'MirrorOnImport' $true))
        $exclude = @(Get-Prop $cfgSrc 'Exclude' @())
        $plan += [pscustomobject]@{ Name = $s.Name; Target = $target; Mirror = $mirror; Exclude = $exclude; Include = @(Get-Prop $cfgSrc 'Include' @('*')); FileCount = $s.FileCount }
    }
    return , $plan
}

function Import-JvpProject {
    # Setzt voraus, dass Programme/Dienste bereits gestoppt sind (oder -NoStop).
    param([IO.Compression.ZipArchive]$Zip, $Manifest, $Plan)
    $files = @(Get-Prop $Manifest 'Files' @())
    foreach ($p in $Plan) {
        $root = [IO.Path]::GetFullPath($p.Target).TrimEnd('\', '/')
        Write-Log "Importiere '$($p.Name)' -> $root $(if ($p.Mirror) { '(spiegeln)' } else { '(ueberschreiben)' })"
        if (-not [IO.Directory]::Exists($root)) { New-Item -ItemType Directory -Path $root -Force | Out-Null }
        $mine = @($files | Where-Object { $_.Source -eq $p.Name })
        $wanted = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($f in $mine) { [void]$wanted.Add(([string]$f.Relative)) }

        if ($p.Mirror) {
            # Dateien loeschen, die es im Export nicht gibt (ausgeschlossene Dateien wie Logs/Lizenzen bleiben)
            $removed = 0
            foreach ($existing in (Get-FilesRecursive -Root $root)) {
                $rel = Get-RelativePathSafe -Root $root -FullPath $existing
                if ($wanted.Contains($rel)) { continue }
                if (Test-Wildcards $rel $p.Exclude) { continue }
                if (-not (Test-Wildcards $rel $p.Include)) { continue }
                [IO.File]::SetAttributes($existing, [IO.FileAttributes]::Normal)
                [IO.File]::Delete($existing)
                $removed++
            }
            if ($removed -gt 0) { Write-Log "  $removed nicht mehr vorhandene Datei(en) entfernt." }
        }

        $n = 0
        foreach ($f in $mine) {
            $rel = [string]$f.Relative
            if ($rel -match '(^|/)\.\.(/|$)' -or $rel.Contains(':')) { throw "Ungueltiger Pfad in der Zip: $rel" }
            $dest = [IO.Path]::GetFullPath((Join-Path $root ($rel.Replace('/', [IO.Path]::DirectorySeparatorChar))))
            if (-not $dest.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw "Ungueltiger Pfad in der Zip: $rel" }
            Expand-ZipEntryTo -Zip $Zip -EntryName $f.Entry -Destination $dest
            $n++
        }
        Write-Log "  $n Datei(en) geschrieben." 'OK'
    }

    $refs = @(Get-Prop $Manifest 'Referenced' @())
    if ($refs.Count -gt 0) {
        Write-Log "Stelle $($refs.Count) verknuepfte Datei(en) am Originalort wieder her ..."
        foreach ($r in $refs) { Expand-ZipEntryTo -Zip $Zip -EntryName $r.Entry -Destination ([string]$r.OriginalPath) }
        Write-Log '  fertig.' 'OK'
    }
}

function Expand-ZipEntryTo {
    param([IO.Compression.ZipArchive]$Zip, [string]$EntryName, [string]$Destination)
    $e = $Zip.GetEntry($EntryName)
    if ($null -eq $e) { throw "Eintrag fehlt in der Zip: $EntryName" }
    $dir = Split-Path -Parent $Destination
    if (-not [IO.Directory]::Exists($dir)) { [void][IO.Directory]::CreateDirectory($dir) }
    if ([IO.File]::Exists($Destination)) { [IO.File]::SetAttributes($Destination, [IO.FileAttributes]::Normal) }
    [IO.Compression.ZipFileExtensions]::ExtractToFile($e, $Destination, $true)
}

#endregion

#region Ablaeufe ------------------------------------------------------------------------------

function Invoke-Export {
    param($Config, [string]$TargetFolder)
    if (-not $TargetFolder) { $TargetFolder = Expand-PathVars (Get-Prop $Config 'ExportFolder' '%PUBLIC%\Documents\JVP-Backup') }
    Initialize-Log -Folder $TargetFolder -Name 'Export'
    Write-Log "=== JVP Projekt-Export (Tool $script:ToolVersion) ==="
    $state = New-JvpState
    try {
        if (-not $NoStop) { Stop-JvpEnvironment -Config $Config -State $state }
        return (Export-JvpProject -Config $Config -TargetFolder $TargetFolder)
    } finally {
        if (-not $NoStop) { Start-JvpEnvironment -State $state -Config $Config }
    }
}

function Invoke-Import {
    param($Config, [string]$Zip, [scriptblock]$Confirm)
    if (-not (Test-Path -LiteralPath $Zip)) { throw "Zip-Datei nicht gefunden: $Zip" }
    $backupFolder = Expand-PathVars (Get-Prop $Config 'ExportFolder' '%PUBLIC%\Documents\JVP-Backup')
    Initialize-Log -Folder $backupFolder -Name 'Import'
    Write-Log "=== JVP Projekt-Import (Tool $script:ToolVersion) ==="
    Write-Log "Zip: $Zip"

    $archive = [IO.Compression.ZipFile]::OpenRead($Zip)
    try {
        $manifest = Read-ZipManifest $archive
        Write-Log "Export vom $(Get-Prop $manifest 'Created') auf '$(Get-Prop $manifest 'Computer')'"
        Test-ZipIntegrity -Zip $archive -Manifest $manifest
        $plan = Get-ImportPlan -Manifest $manifest -Config $Config

        $summary = ($plan | ForEach-Object { '  {0}: {1} Dateien -> {2}{3}' -f $_.Name, $_.FileCount, $_.Target, $(if ($_.Mirror) { ' (Ordner wird gespiegelt)' } else { '' }) }) -join [Environment]::NewLine
        $refCount = @(Get-Prop $manifest 'Referenced' @()).Count
        if ($refCount -gt 0) { $summary += [Environment]::NewLine + "  + $refCount verknuepfte Datei(en) an ihren Originalpfad" }
        Write-Log "Geplante Wiederherstellung:$([Environment]::NewLine)$summary"
        if ($Confirm -and -not (& $Confirm $summary)) { Write-Log 'Import abgebrochen.' 'WARN'; return }

        $state = New-JvpState
        try {
            if (-not $NoStop) { Stop-JvpEnvironment -Config $Config -State $state }
            if (-not $NoSafetyBackup -and [bool](Get-Prop $Config 'SafetyBackupBeforeImport' $true)) {
                Write-Log 'Sicherheits-Export des aktuellen Stands ...'
                try { $null = Export-JvpProject -Config $Config -TargetFolder $backupFolder -Suffix '_vor-Import' }
                catch {
                    if ($_.Exception.Message -like 'Es wurden keine Dateien gefunden*') { Write-Log '  Kein aktueller Stand vorhanden - kein Sicherheits-Export noetig.' 'WARN' }
                    else { throw }
                }
            }
            Import-JvpProject -Zip $archive -Manifest $manifest -Plan $plan
            Write-Log 'Import fertig.' 'OK'
        } finally {
            if (-not $NoStop) { Start-JvpEnvironment -State $state -Config $Config }
        }
    } finally {
        $archive.Dispose()
    }
}

#endregion

#region Analyse -------------------------------------------------------------------------------

function Get-ZipOverview {
    # Beschreibt den Aufbau einer vorhandenen Zip (z.B. einer von JVP selbst erzeugten Projekt-Zip)
    param([string]$Path)
    $out = New-Object System.Collections.Generic.List[string]
    $zip = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $entries = @($zip.Entries)
        [long]$sum = 0; foreach ($e in $entries) { $sum += $e.Length }
        $out.Add(("Zip: {0}  ({1} Eintraege, {2:N1} MB unkomprimiert)" -f $Path, $entries.Count, ($sum / 1MB)))
        $out.Add('  Ordner (oberste Ebenen):')
        $entries | ForEach-Object { $parts = $_.FullName.Replace('\', '/').Split('/'); if ($parts.Count -gt 2) { $parts[0] + '/' + $parts[1] + '/' } elseif ($parts.Count -gt 1) { $parts[0] + '/' } else { '(Wurzel)' } } |
            Group-Object | Sort-Object Name | ForEach-Object { $out.Add(("    {0,-60} {1,6} Dateien" -f $_.Name, $_.Count)) }
        $out.Add('  Dateitypen:')
        $entries | Where-Object { $_.Name } | ForEach-Object { $x = [IO.Path]::GetExtension($_.Name).ToLower(); if (-not $x) { '(ohne)' } else { $x } } |
            Group-Object | Sort-Object Count -Descending | ForEach-Object { $out.Add(("    {0,-12} {1,6}" -f $_.Name, $_.Count)) }
        $out.Add('  Eintraege (max. 400):')
        foreach ($e in ($entries | Select-Object -First 400)) { $out.Add(("    {0,12:N0}  {1:yyyy-MM-dd HH:mm}  {2}" -f $e.Length, $e.LastWriteTime.DateTime, $e.FullName)) }
        # kleine Text-/XML-Dateien in der Wurzel (Manifest, Info) mit ausgeben
        foreach ($e in ($entries | Where-Object { $_.FullName -notmatch '[/\\]' -and $_.Length -lt 64KB -and $_.Name -match '(?i)\.(xml|json|txt|ini|info|manifest|prj)$' } | Select-Object -First 5)) {
            $out.Add("  ----- Inhalt $($e.FullName) -----")
            $r = New-Object IO.StreamReader($e.Open())
            try { foreach ($l in ($r.ReadToEnd() -split "`r?`n" | Select-Object -First 150)) { $out.Add("  | $l") } } finally { $r.Dispose() }
        }
    } finally { $zip.Dispose() }
    return , $out
}

function Invoke-Analyse {
    param($Config, [string]$TargetFolder, [string[]]$ReferenceZips = @())
    if (-not $TargetFolder) { $TargetFolder = Expand-PathVars (Get-Prop $Config 'ExportFolder' '%PUBLIC%\Documents\JVP-Backup') }
    if (-not (Test-Path -LiteralPath $TargetFolder)) { New-Item -ItemType Directory -Path $TargetFolder -Force | Out-Null }
    Initialize-Log -Folder $TargetFolder -Name 'Analyse'
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $reportPath = Join-Path $TargetFolder "JVP-Analyse_$stamp.txt"
    $proposalPath = Join-Path $TargetFolder "JVP-ProjektBackup.config.vorschlag_$stamp.json"
    $rep = New-Object System.Collections.Generic.List[string]
    $kw = '(?i)jung|jvp|visu|knx|sdv|eib'
    function Add-Rep([string]$s) { $rep.Add($s); Write-Log $s }

    Add-Rep "=== JVP Analyse $(Get-Date) auf $([Environment]::MachineName) ==="

    # 0) Von JVP selbst erzeugte Projekt-Zips (Vorlage fuer den Aufbau)
    $zipList = @()
    foreach ($z in @($ReferenceZips)) {
        if (-not $z) { continue }
        if (Test-Path -LiteralPath $z -PathType Container) { $zipList += @(Get-ChildItem -LiteralPath $z -Filter *.zip -File | ForEach-Object { $_.FullName }) }
        elseif (Test-Path -LiteralPath $z) { $zipList += $z }
    }
    if ($zipList.Count -gt 0) {
        Add-Rep ''; Add-Rep '--- 0. Vorhandene JVP-Zip-Dateien (Aufbau) ---'
        foreach ($z in $zipList) {
            try { foreach ($l in (Get-ZipOverview $z)) { $rep.Add($l) }; Write-Log "  Zip ausgewertet: $z" }
            catch { Add-Rep "  $z : $($_.Exception.Message)" }
        }
        if (-not $script:IsWin) {
            [IO.File]::WriteAllLines($reportPath, $rep.ToArray(), (New-Object Text.UTF8Encoding($true)))
            Write-Log "Bericht: $reportPath" 'OK'
            return $reportPath
        }
    }

    # 1) Wie macht JUNG es? -> Verknuepfungen "Import und Export der Projektdaten" & Co. auswerten
    Add-Rep ''; Add-Rep '--- 1. JUNG-Verknuepfungen (Desktop / Startmenue) ---'
    $lnkDirs = @("$env:PUBLIC\Desktop", [Environment]::GetFolderPath('Desktop'), "$env:ProgramData\Microsoft\Windows\Start Menu\Programs", "$env:APPDATA\Microsoft\Windows\Start Menu\Programs")
    $shell = $null; try { $shell = New-Object -ComObject WScript.Shell } catch { }
    foreach ($d in $lnkDirs) {
        if (-not $d -or -not (Test-Path -LiteralPath $d)) { continue }
        foreach ($lnk in @(Get-ChildItem -LiteralPath $d -Recurse -Include *.lnk, *.url, *.bat, *.cmd -ErrorAction SilentlyContinue)) {
            $target = ''; $lnkArgs = ''; $wd = ''
            if ($lnk.Extension -eq '.lnk' -and $shell) { $s = $shell.CreateShortcut($lnk.FullName); $target = $s.TargetPath; $lnkArgs = $s.Arguments; $wd = $s.WorkingDirectory }
            if (($lnk.Name + $target + $lnkArgs) -notmatch "$kw|import|export|projekt|backup|sicher") { continue }
            Add-Rep ("{0}`r`n    Ziel: {1} {2}`r`n    Arbeitsordner: {3}" -f $lnk.FullName, $target, $lnkArgs, $wd)
            $toDump = @()
            if ($lnk.Extension -in '.bat', '.cmd') { $toDump += $lnk.FullName }
            if ($target -and (Test-Path -LiteralPath $target) -and ([IO.Path]::GetExtension($target) -in '.bat', '.cmd', '.ps1', '.vbs', '.xml', '.config', '.ini')) { $toDump += $target }
            foreach ($a in ($lnkArgs -split '"')) { $a = $a.Trim(); if ($a -and ([IO.Path]::GetExtension($a) -in '.bat', '.cmd', '.ps1', '.vbs') -and (Test-Path -LiteralPath $a)) { $toDump += $a } }
            if ($target -and ([IO.Path]::GetExtension($target) -eq '.exe') -and (Test-Path -LiteralPath $target)) {
                $exeDir = Split-Path -Parent $target
                Add-Rep "    Programmordner: $exeDir"
                foreach ($cf in @(Get-ChildItem -LiteralPath $exeDir -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.config', '.xml', '.ini', '.json', '.bat', '.cmd', '.ps1' -and $_.Length -lt 512KB })) { $toDump += $cf.FullName }
            }
            foreach ($f in ($toDump | Select-Object -Unique)) {
                Add-Rep "    ----- Inhalt $f -----"
                foreach ($l in @(Get-Content -LiteralPath $f -TotalCount 300 -ErrorAction SilentlyContinue)) { $rep.Add("    | $l") }
            }
        }
    }

    # 2) Prozesse
    Add-Rep ''; Add-Rep '--- 2. Laufende Programme (JUNG/JVP/Visu/KNX/SDV) ---'
    $procProposals = @()
    foreach ($w in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
        $blob = "$($w.Name) $($w.ExecutablePath)"
        $company = ''
        try { if ($w.ExecutablePath) { $company = (Get-Item -LiteralPath $w.ExecutablePath).VersionInfo.CompanyName } } catch { }
        if ("$blob $company" -notmatch $kw) { continue }
        $title = ''
        try { $title = (Get-Process -Id $w.ProcessId).MainWindowTitle } catch { }
        Add-Rep ("{0} (PID {1}, Sitzung {2}) Fenster='{3}' Firma='{4}'`r`n    {5}" -f $w.Name, $w.ProcessId, $w.SessionId, $title, $company, $w.CommandLine)
        $pn = [IO.Path]::GetFileNameWithoutExtension($w.Name)
        if ($pn -match '(?i)sdv|knx|jvp|visu' -and -not ($procProposals | Where-Object { $_.ProcessName -eq $pn })) {
            $procProposals += [ordered]@{ Name = $pn; ProcessName = $pn; ExePath = $w.ExecutablePath; ConfirmDialogTexts = @('beenden', 'speichern'); ConfirmButtons = @('Ja', 'Yes', 'OK'); CloseTimeoutSeconds = 90; Restart = $true }
        }
    }

    # 3) Dienste
    Add-Rep ''; Add-Rep '--- 3. Dienste ---'
    $svcProposals = @()
    foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { "$($_.Name) $($_.DisplayName) $($_.PathName)" -match $kw })) {
        Add-Rep ("{0} [{1}] '{2}' Start={3}`r`n    {4}" -f $s.Name, $s.State, $s.DisplayName, $s.StartMode, $s.PathName)
        $svcProposals += [ordered]@{ Name = $s.Name }
    }
    foreach ($n in 'W3SVC', 'WAS') { $s = Get-Service -Name $n -ErrorAction SilentlyContinue; if ($s) { Add-Rep "IIS: $n [$($s.Status)]" } }

    # 4) IIS-Verzeichnisse (Visu)
    Add-Rep ''; Add-Rep '--- 4. IIS-Anwendungen / virtuelle Verzeichnisse ---'
    $srcProposals = @()
    $appcmd = Join-Path $env:SystemRoot 'System32\inetsrv\appcmd.exe'
    if (Test-Path -LiteralPath $appcmd) {
        foreach ($l in @(& $appcmd list vdir 2>$null)) {
            Add-Rep "  $l"
            if ($l -match 'physicalPath:([^)]+)\)') {
                $pp = Expand-PathVars $Matches[1]
                if ("$l" -match $kw -and $pp -notmatch '(?i)\\inetpub\\wwwroot\\?$') { $srcProposals += [ordered]@{ Name = ('IIS_' + (Split-Path -Leaf $pp)); Path = $pp; Optional = $true; Exclude = @('*.log', 'logs/*', 'Temp/*') } }
            }
        }
    } else { Add-Rep '  appcmd.exe nicht gefunden (IIS nicht installiert?)' }

    # 5) Ordner mit JUNG/JVP-Bezug
    Add-Rep ''; Add-Rep '--- 5. Ordner ---'
    $roots = @($env:ProgramData, $env:ProgramFiles, ${env:ProgramFiles(x86)}, "$env:SystemDrive\inetpub", $env:PUBLIC, "$env:SystemDrive\") | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    foreach ($r in $roots) {
        foreach ($d in @(Get-ChildItem -LiteralPath $r -Directory -ErrorAction SilentlyContinue)) {
            if ($d.Name -notmatch $kw) { continue }
            Add-Rep "  $($d.FullName)"
            foreach ($sd in @(Get-ChildItem -LiteralPath $d.FullName -Directory -ErrorAction SilentlyContinue)) { $rep.Add("      $($sd.Name)") }
            if ($d.FullName -like "$env:ProgramData*" -or $d.FullName -like "$env:SystemDrive\inetpub*") {
                $srcProposals += [ordered]@{ Name = (ConvertTo-SafeName $d.Name); Path = $d.FullName; Optional = $true; Exclude = @('*.log', 'Log/*', 'Logs/*', 'Temp/*') }
            }
        }
    }

    # 6) Projektdateien *.prj auf allen lokalen Laufwerken
    Add-Rep ''; Add-Rep '--- 6. Projektdateien (*.prj) ---'
    $prjExt = @('.prj') + @(@(Get-Prop $Config 'ReferenceScanExtensions' @()) | ForEach-Object { ([string]$_).ToLower() })
    $drives = @([IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady } | ForEach-Object { $_.RootDirectory.FullName })
    $skip = @('Windows', '$Recycle.Bin', 'System Volume Information', 'WinSxS', 'Microsoft.NET', 'node_modules')
    foreach ($drv in $drives) {
        Write-Log "  durchsuche $drv ..."
        foreach ($f in (Get-FilesRecursive -Root $drv -MaxDepth 12 -SkipDirNames $skip)) {
            if ($prjExt -notcontains [IO.Path]::GetExtension($f).ToLower()) { continue }
            $fi = New-Object IO.FileInfo $f
            Add-Rep ("  {0}  ({1:N0} KB, geaendert {2})" -f $f, ($fi.Length / 1KB), $fi.LastWriteTime)
            $refs = Get-ReferencedFiles -ProjectFiles @($f) -Config $Config -AlreadyIncluded @()
            foreach ($x in $refs) { $rep.Add("      verweist auf: $x") }
            $dir = $fi.DirectoryName
            if ($dir -notmatch '(?i)\\(Program Files|Windows)' -and -not ($srcProposals | Where-Object { $dir.StartsWith([string]$_.Path, [StringComparison]::OrdinalIgnoreCase) })) {
                $srcProposals += [ordered]@{ Name = ('PRJ_' + (ConvertTo-SafeName (Split-Path -Leaf $dir))); Path = $dir; Optional = $true; Exclude = @('*.log') }
            }
        }
    }

    [IO.File]::WriteAllLines($reportPath, $rep.ToArray(), (New-Object Text.UTF8Encoding($true)))
    $proposal = [ordered]@{
        ExportFolder = (Get-Prop $Config 'ExportFolder' '%PUBLIC%\Documents\JVP-Backup')
        ZipPrefix = 'JVP-Projekt'
        StopIIS = $true
        Services = $svcProposals
        Programs = $procProposals
        Sources = $srcProposals
        ScanProjectFilesForReferences = $true
        ReferenceScanExtensions = @('.prj')
        ReferenceExcludeRoots = @('%SystemRoot%', '%ProgramFiles%', '%ProgramFiles(x86)%')
        MirrorOnImport = $true
        SafetyBackupBeforeImport = $true
        KillIfNotClosed = $false
        StartProgramsUnelevated = $true
        ProgramStartDelaySeconds = 5
    }
    [IO.File]::WriteAllText($proposalPath, ($proposal | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
    Write-Log "Bericht: $reportPath" 'OK'
    Write-Log "Konfigurationsvorschlag: $proposalPath (pruefen und als JVP-ProjektBackup.config.json uebernehmen)" 'OK'
    return $reportPath
}

#endregion

#region Oberflaeche ---------------------------------------------------------------------------

function Show-Gui {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "JVP Projekt Export / Import  $script:ToolVersion"
    $form.Size = New-Object System.Drawing.Size(910, 620)
    $form.StartPosition = 'CenterScreen'

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = 'Sicherungsordner:'; $lbl.Location = '12,15'; $lbl.AutoSize = $true
    $txt = New-Object System.Windows.Forms.TextBox
    $txt.Location = '130,12'; $txt.Size = '620,24'; $txt.Anchor = 'Top,Left,Right'
    $btnBrowse = New-Object System.Windows.Forms.Button
    $btnBrowse.Text = '...'; $btnBrowse.Location = '760,10'; $btnBrowse.Size = '40,26'; $btnBrowse.Anchor = 'Top,Right'

    $btnExport = New-Object System.Windows.Forms.Button
    $btnExport.Text = 'Export erstellen'; $btnExport.Location = '12,48'; $btnExport.Size = '170,36'
    $btnImport = New-Object System.Windows.Forms.Button
    $btnImport.Text = 'Import (Zip waehlen) ...'; $btnImport.Location = '192,48'; $btnImport.Size = '190,36'
    $btnAnalyse = New-Object System.Windows.Forms.Button
    $btnAnalyse.Text = 'Analyse'; $btnAnalyse.Location = '392,48'; $btnAnalyse.Size = '120,36'
    $btnConfig = New-Object System.Windows.Forms.Button
    $btnConfig.Text = 'Konfiguration'; $btnConfig.Location = '522,48'; $btnConfig.Size = '120,36'
    $btnFolder = New-Object System.Windows.Forms.Button
    $btnFolder.Text = 'Ordner oeffnen'; $btnFolder.Location = '652,48'; $btnFolder.Size = '120,36'
    $btnZipInfo = New-Object System.Windows.Forms.Button
    $btnZipInfo.Text = 'JVP-Zip ansehen'; $btnZipInfo.Location = '782,48'; $btnZipInfo.Size = '100,36'; $btnZipInfo.Anchor = 'Top,Right'

    $log = New-Object System.Windows.Forms.TextBox
    $log.Multiline = $true; $log.ScrollBars = 'Both'; $log.WordWrap = $false; $log.ReadOnly = $true
    $log.Font = New-Object System.Drawing.Font('Consolas', 9)
    $log.Location = '12,96'; $log.Size = '860,470'; $log.Anchor = 'Top,Bottom,Left,Right'
    $script:LogBox = $log

    $form.Controls.AddRange(@($lbl, $txt, $btnBrowse, $btnExport, $btnImport, $btnAnalyse, $btnConfig, $btnFolder, $btnZipInfo, $log))

    $loadCfg = {
        try { return (Read-Config $ConfigPath) }
        catch { Write-Log $_.Exception.Message 'FEHLER'; return $null }
    }
    $cfg0 = & $loadCfg
    $txt.Text = if ($cfg0) { Expand-PathVars (Get-Prop $cfg0 'ExportFolder' '%PUBLIC%\Documents\JVP-Backup') } else { Expand-PathVars '%PUBLIC%\Documents\JVP-Backup' }
    Write-Log "Konfiguration: $ConfigPath"
    if ($NoStop) { Write-Log 'Modus -NoStop: Programme/Dienste/IIS werden NICHT angehalten.' 'WARN' }

    $setBusy = { param([bool]$b) foreach ($c in @($btnExport, $btnImport, $btnAnalyse, $btnConfig, $btnBrowse)) { $c.Enabled = -not $b }; $form.UseWaitCursor = $b; [System.Windows.Forms.Application]::DoEvents() }

    $btnBrowse.Add_Click({
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.SelectedPath = $txt.Text
        if ($dlg.ShowDialog($form) -eq 'OK') { $txt.Text = $dlg.SelectedPath }
    })
    $btnFolder.Add_Click({ if (Test-Path -LiteralPath $txt.Text) { Start-Process explorer.exe -ArgumentList ('"{0}"' -f $txt.Text) } })
    $btnConfig.Add_Click({ Start-Process notepad.exe -ArgumentList ('"{0}"' -f $ConfigPath) })

    $btnExport.Add_Click({
        $cfg = & $loadCfg; if (-not $cfg) { return }
        $msg = "Fuer den Export werden die JVP-Programme beendet (Rueckfragen werden bestaetigt), die Dienste und der IIS gestoppt und danach wieder gestartet.`r`n`r`nFortfahren?"
        if ($NoStop) { $msg = 'Export ohne Anhalten der Programme erstellen?' }
        if ([System.Windows.Forms.MessageBox]::Show($form, $msg, 'Export', 'YesNo', 'Question') -ne 'Yes') { return }
        & $setBusy $true
        try {
            $z = Invoke-Export -Config $cfg -TargetFolder $txt.Text
            [System.Windows.Forms.MessageBox]::Show($form, "Export erstellt:`r`n$z", 'Export', 'OK', 'Information') | Out-Null
        } catch {
            Write-Log $_.Exception.Message 'FEHLER'
            [System.Windows.Forms.MessageBox]::Show($form, $_.Exception.Message, 'Export fehlgeschlagen', 'OK', 'Error') | Out-Null
        } finally { & $setBusy $false }
    })

    $btnImport.Add_Click({
        $cfg = & $loadCfg; if (-not $cfg) { return }
        $dlg = New-Object System.Windows.Forms.OpenFileDialog
        $dlg.Filter = 'JVP Projekt-Zip (*.zip)|*.zip'
        if (Test-Path -LiteralPath $txt.Text) { $dlg.InitialDirectory = $txt.Text }
        if ($dlg.ShowDialog($form) -ne 'OK') { return }
        & $setBusy $true
        try {
            $confirm = {
                param($summary)
                $m = "Die aktuellen Projektdateien werden UEBERSCHRIEBEN:`r`n`r`n$summary`r`n`r`nDie Programme werden beendet, Dienste/IIS gestoppt. Vorher wird automatisch ein Sicherheits-Export des aktuellen Stands erstellt.`r`n`r`nImport jetzt ausfuehren?"
                return ([System.Windows.Forms.MessageBox]::Show($form, $m, 'Import bestaetigen', 'YesNo', 'Warning') -eq 'Yes')
            }
            Invoke-Import -Config $cfg -Zip $dlg.FileName -Confirm $confirm
        } catch {
            Write-Log $_.Exception.Message 'FEHLER'
            [System.Windows.Forms.MessageBox]::Show($form, $_.Exception.Message, 'Import fehlgeschlagen', 'OK', 'Error') | Out-Null
        } finally { & $setBusy $false }
    })

    $btnAnalyse.Add_Click({
        $cfg = & $loadCfg; if (-not $cfg) { $cfg = [pscustomobject]@{ Sources = @() } }
        & $setBusy $true
        try { $r = Invoke-Analyse -Config $cfg -TargetFolder $txt.Text; Start-Process notepad.exe -ArgumentList ('"{0}"' -f $r) }
        catch { Write-Log $_.Exception.Message 'FEHLER' }
        finally { & $setBusy $false }
    })

    $btnZipInfo.Add_Click({
        $dlg = New-Object System.Windows.Forms.OpenFileDialog
        $dlg.Filter = 'Zip (*.zip)|*.zip'; $dlg.Multiselect = $true; $dlg.Title = 'Von JVP erzeugte Projekt-Zip(s) waehlen'
        if ($dlg.ShowDialog($form) -ne 'OK') { return }
        & $setBusy $true
        try {
            $outFile = Join-Path $txt.Text ('JVP-Zip-Aufbau_{0}.txt' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
            if (-not (Test-Path -LiteralPath $txt.Text)) { New-Item -ItemType Directory -Path $txt.Text -Force | Out-Null }
            $lines = New-Object System.Collections.Generic.List[string]
            foreach ($f in $dlg.FileNames) { foreach ($l in (Get-ZipOverview $f)) { $lines.Add($l) }; $lines.Add('') }
            [IO.File]::WriteAllLines($outFile, $lines.ToArray(), (New-Object Text.UTF8Encoding($true)))
            Write-Log "Zip-Aufbau gespeichert: $outFile" 'OK'
            Start-Process notepad.exe -ArgumentList ('"{0}"' -f $outFile)
        } catch { Write-Log $_.Exception.Message 'FEHLER' }
        finally { & $setBusy $false }
    })

    [void]$form.ShowDialog()
}

#endregion

#region Hauptprogramm -------------------------------------------------------------------------

if ($script:IsWin -and -not (Test-IsAdmin)) {
    # Als Administrator neu starten (noetig fuer IIS/Dienste und das Beenden der Programme)
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $MyInvocation.MyCommand.Path), '-Mode', $Mode, '-ConfigPath', ('"{0}"' -f $ConfigPath))
    if ($OutputFolder) { $argList += @('-OutputFolder', ('"{0}"' -f $OutputFolder)) }
    if ($ZipPath) { $argList += @('-ZipPath', ('"{0}"' -f $ZipPath)) }
    if ($NoStop) { $argList += '-NoStop' }
    if ($NoSafetyBackup) { $argList += '-NoSafetyBackup' }
    if ($Force) { $argList += '-Force' }
    if ($Mode -ne 'Gui') { $argList = @('-NoExit') + $argList }
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList
    return
}

try {
    switch ($Mode) {
        'Gui' {
            Show-Gui
        }
        'Export' {
            $cfg = Read-Config $ConfigPath
            if (-not $Force -and -not $NoStop) {
                $a = Read-Host 'JVP-Programme werden beendet, Dienste und IIS gestoppt. Fortfahren? (j/n)'
                if ($a -notmatch '^(j|y)') { Write-Host 'Abgebrochen.'; return }
            }
            Invoke-Export -Config $cfg -TargetFolder $OutputFolder | Out-Null
        }
        'Import' {
            if (-not $ZipPath) { throw 'Bitte -ZipPath angeben.' }
            $cfg = Read-Config $ConfigPath
            $confirm = $null
            if (-not $Force) {
                $confirm = {
                    param($summary)
                    Write-Host "`nDie aktuellen Projektdateien werden UEBERSCHRIEBEN:`n$summary`n" -ForegroundColor Yellow
                    return ((Read-Host 'Import jetzt ausfuehren? (j/n)') -match '^(j|y)')
                }
            }
            Invoke-Import -Config $cfg -Zip $ZipPath -Confirm $confirm
        }
        'Analyse' {
            $cfg = if (Test-Path -LiteralPath $ConfigPath) { Read-Config $ConfigPath } else { [pscustomobject]@{ Sources = @() } }
            Invoke-Analyse -Config $cfg -TargetFolder $OutputFolder -ReferenceZips @($ZipPath) | Out-Null
        }
    }
} catch {
    Write-Log $_.Exception.Message 'FEHLER'
    exit 1
}

#endregion

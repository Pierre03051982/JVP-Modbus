# JVP Projekt Export / Import

Sichert alle Projektdateien des JUNG Visu Pro Servers, die zur **Visu** und zum **PRJ** gehören, in **eine Zip-Datei**
und spielt eine solche Zip wieder ein (überschreibt den aktuellen Stand).

Läuft direkt auf dem JVP-Server (Windows, PowerShell 5.1, keine Installation nötig). Startet sich selbst als Administrator.

## Dateien

| Datei | Zweck |
|---|---|
| `JVP-ProjektBackup.bat` | Grafische Oberfläche (Export, Import, Analyse, JVP-Zip ansehen) |
| `JVP-Export.bat` | Export ohne Rückfrage (z. B. für die Windows-Aufgabenplanung) |
| `JVP-Import.bat` | Zip-Datei per Drag & Drop darauf ziehen → Import |
| `JVP-Analyse.bat` | Sucht JVP-Programme, Dienste, IIS-Ordner, `*.prj` und die JUNG-Verknüpfung „Import und Export der Projektdaten“. Eine von JVP erzeugte Zip (oder ein Ordner mit solchen Zips) kann darauf gezogen werden, dann wird deren Aufbau ausgewertet. |
| `JVP-ProjektBackup.config.json` | Konfiguration (Pfade, Programme, Dienste) |
| `JVP-ProjektBackup.ps1` | Das eigentliche Programm |

## Ablauf Export

1. **Programme beenden** (`Programs`, z. B. SDV und KNX): Das Programm wird wie beim Klick auf „X“ geschlossen
   (bei Programmen im Infobereich per `WM_CLOSE`). Die Rückfrage **„Wirklich beenden?“** (und evtl. „Speichern?“)
   wird automatisch mit **Ja** bestätigt, damit das Programm seine Daten speichert.
   Beendet sich ein Programm nicht innerhalb von `CloseTimeoutSeconds`, wird **abgebrochen**
   (kein hartes Beenden, außer `KillIfNotClosed` ist `true`).
2. **Dienste stoppen** (`Services`).
3. **IIS stoppen** (`iisreset /stop`).
4. Alle `Sources` (Projekt- und Visu-Ordner) in die Zip packen. Zusätzlich werden die `*.prj`-Dateien nach
   absoluten Pfaden durchsucht; referenzierte Dateien außerhalb der Ordner (z. B. Bilder) kommen mit in die Zip.
   Jede Datei bekommt eine SHA256-Prüfsumme in `manifest.json`.
5. IIS, Dienste und Programme **wieder starten** – auch wenn unterwegs ein Fehler auftritt.

Zip-Name: `JVP-Projekt_<Rechner>_<Datum_Uhrzeit>.zip`, Logs unter `<Sicherungsordner>\Logs`.

## Ablauf Import

1. Zip prüfen (Format + SHA256 aller Dateien) – bei Fehlern wird **nichts** verändert.
2. Übersicht anzeigen und bestätigen lassen.
3. Programme / Dienste / IIS stoppen (wie beim Export).
4. **Sicherheits-Export** des aktuellen Stands (`..._vor-Import.zip`).
5. Dateien überschreiben. Mit `MirrorOnImport: true` werden Dateien, die es im Export nicht gibt, gelöscht
   (so verschwinden z. B. gelöschte Visu-Seiten). Dateien, die unter `Exclude` fallen (Logs usw.), bleiben unangetastet.
6. Alles wieder starten.

Der Zielordner wird über den `Name` der Quelle bestimmt: gibt es in der aktuellen Konfiguration eine Quelle
mit gleichem Namen, wird deren `Path` verwendet, sonst der Originalpfad aus der Zip. So kann ein Projekt auch auf
einen anderen Server mit anderen Pfaden übertragen werden.

## Einrichtung (wichtig!)

Die Pfade und Prozessnamen in `JVP-ProjektBackup.config.json` sind **Platzhalter** und müssen auf dem Server geprüft werden:

1. `JVP-Analyse.bat` auf dem JVP-Server ausführen (am besten die JVP-Zips aus dem Vorlagen-Ordner darauf ziehen).
2. Der Bericht `JVP-Analyse_<Datum>.txt` zeigt:
   - die JUNG-Verknüpfung „Import und Export der Projektdaten“ inkl. Ziel und Inhalt der Skript-/Konfigurationsdateien
     → daran sieht man, welche Ordner JUNG selbst sichert und welche Programme/Dienste JUNG stoppt,
   - die laufenden SDV-/KNX-Programme mit exaktem Prozessnamen und Pfad,
   - JVP-Dienste, IIS-Verzeichnisse der Visu, alle `*.prj`-Dateien,
   - den Aufbau der von JVP erzeugten Zips.
3. Zusätzlich wird `JVP-ProjektBackup.config.vorschlag_<Datum>.json` erzeugt. Prüfen, anpassen und als
   `JVP-ProjektBackup.config.json` speichern.
4. Einmal testweise exportieren und die Zip kontrollieren.

## Konfiguration

| Schlüssel | Bedeutung |
|---|---|
| `ExportFolder` | Standard-Sicherungsordner (Umgebungsvariablen wie `%PUBLIC%` erlaubt) |
| `StopIIS` | IIS vor dem Kopieren stoppen |
| `Services` | Windows-Dienste, die gestoppt werden (`[{ "Name": "..." }]`, Platzhalter `*` erlaubt) |
| `Programs[].ProcessName` | Prozessname ohne `.exe`, Platzhalter `*` erlaubt |
| `Programs[].ConfirmDialogTexts` | Texte, an denen die Rückfrage erkannt wird (z. B. `beenden`) |
| `Programs[].ConfirmButtons` | Schaltflächen, die geklickt werden (`Ja`, `Yes`, `OK`, evtl. `Beenden`) |
| `Programs[].CloseTimeoutSeconds` | Wartezeit fürs Speichern/Beenden |
| `Programs[].Restart` / `ExePath` / `Arguments` | Neustart nach Export/Import |
| `Sources[]` | Ordner mit `Name`, `Path`, `Include`, `Exclude`, `Optional`, `MirrorOnImport` |
| `ScanProjectFilesForReferences` | In `*.prj` referenzierte Dateien mitsichern |
| `KillIfNotClosed` | Programm nach Zeitüberschreitung hart beenden (**Datenverlust möglich**) |
| `StartProgramsUnelevated` | Programme nach dem Neustart wieder ohne Adminrechte starten |

## Kommandozeile

```powershell
.\JVP-ProjektBackup.ps1                                   # Oberfläche
.\JVP-ProjektBackup.ps1 -Mode Export -OutputFolder D:\JVP-Backup
.\JVP-ProjektBackup.ps1 -Mode Import -ZipPath D:\JVP-Backup\JVP-Projekt_SERVER_20260927_120000.zip
.\JVP-ProjektBackup.ps1 -Mode Analyse -ZipPath "C:\...\Vorlagen"
```

Weitere Schalter: `-Force` (keine Rückfragen), `-NoStop` (nichts beenden, nur kopieren – nur zum Testen),
`-NoSafetyBackup`, `-ConfigPath <Datei>`.

## Hinweise

- Das Tool muss in **derselben Windows-Sitzung** laufen wie die SDV-/KNX-Programme (z. B. per RDP als der Benutzer,
  unter dem sie laufen), sonst kann die Rückfrage nicht bestätigt werden.
- Importiert werden Zips dieses Tools (mit `manifest.json`). Die von JVP selbst erzeugten Zips können mit
  „JVP-Zip ansehen“ / `JVP-Analyse.bat` ausgewertet werden.

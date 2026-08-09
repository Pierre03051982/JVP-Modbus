# Rattenfalle 🪤 — defensive Angriffs-Falle für Webserver

Eine **rein defensive** „Rattenfalle", die Angriffe aus dem Netz auf deinen
Webserver abfängt und die Angreifer **automatisch per Firewall sperrt**.

> ⚠️ **Wichtig / rechtlicher Hinweis:** Dieses Tool **greift niemanden an** und
> „hackt nicht zurück". Ein Gegenangriff („Hack-back") ist in Deutschland
> **strafbar** (§ 202a–c, § 303b StGB) und trifft wegen gekaperter/gefälschter
> Absender-IPs fast immer Unbeteiligte. Die Rattenfalle blockiert ausschließlich
> **eingehenden** Verkehr auf deinem *eigenen* Server. Das ist erlaubt und wirksam.

Braucht **nur Python 3.7+** (Standardbibliothek, keine Fremd-Pakete).

---

## Wie es funktioniert

Die Falle kombiniert drei Mechanismen:

| Baustein | Funktion |
|----------|----------|
| **Honeypot** | Lauscht auf Köder-Ports (Standard: 8080/8443/2323). Diese Ports sind nirgends verlinkt — nur Scanner/Angreifer finden sie. **Jeder Zugriff → sofortige Sperre der Quell-IP.** |
| **Tarpit** | Statt schnell zu antworten, hält die Falle die Verbindung des Angreifers künstlich fest (langsames „Tröpfeln"). Bots/Scanner hängen fest und verschwenden Zeit — ganz ohne Gegenangriff. |
| **Log-Watcher** | *(optional)* Liest das Access-Log deines echten Webservers (nginx/Apache, „combined"-Format) und sperrt IPs, die bekannte Angriffsmuster auslösen (z. B. `/.env`, `/wp-login.php`, SQL-Injection, Scanner-User-Agents). |

Gesperrt wird **echt** über die Firewall — automatisch erkannt:

- **Linux mit `nft`** → nftables-Set mit automatischem Ablauf *(bevorzugt)*
- **Linux mit `ipset`+`iptables`** → Fallback für ältere Systeme
- **Windows** → `netsh advfirewall`
- **kein Zugriff/keine Rechte** → Modus `logonly` (protokolliert nur, sperrt nicht)

Sperren laufen nach `ban.duration_seconds` (Standard 24 h) automatisch wieder ab.

### Schutz gegen Selbst-Aussperren
Alle privaten Netze (`127.*`, `10.*`, `172.16–31.*`, `192.168.*`, IPv6-Local) stehen
auf der **Whitelist** und werden **nie** gesperrt. Passe die Liste in
`config.json` an, falls du dich aus einem festen externen Netz verbindest.

---

## Schnellstart

```bash
cd attack_trap

# 1) Umgebung prüfen (sperrt nichts):
python3 rattenfalle.py --self-test

# 2) Starten (root für echte Firewall-Sperren):
sudo python3 rattenfalle.py --config config.json
```

Auf **Windows** (Eingabeaufforderung als Administrator):
```bat
python rattenfalle.py --config config.json
```

### Windows: fest einrichten (Autostart, läuft im Hintergrund)

Damit die Rattenfalle **dauerhaft** läuft — automatisch bei jedem Windows-Start,
wie ein fest eingerichteter Dienst:

1. Ordner `attack_trap\windows\` öffnen.
2. **`4 - Einrichten (Autostart installieren).bat`** per **Rechtsklick →
   „Als Administrator ausführen"**.

Das registriert eine geplante Aufgabe `JVP-Rattenfalle` (Start beim Systemstart,
als `SYSTEM` mit den nötigen Rechten für echte Firewall-Sperren) und startet sie
sofort. Kontrolle in der **Aufgabenplanung** unter dem Namen `JVP-Rattenfalle`.

- **Status:** `python rattenfalle.py --status`
- **Entfernen:** `5 - Deinstallieren (Autostart entfernen).bat` (als Admin)

> 💡 Liegt der Ordner in OneDrive: einmal per Rechtsklick auf den Ordner
> **„Immer auf diesem Gerät behalten"** wählen, damit die Dateien lokal
> vorhanden sind (sonst findet der Hintergrunddienst sie evtl. nicht).

### Als Dienst (Linux/systemd)
```bash
sudo cp systemd/rattenfalle.service /etc/systemd/system/
# WorkingDirectory/ExecStart-Pfade in der Unit anpassen!
sudo systemctl daemon-reload
sudo systemctl enable --now rattenfalle
sudo journalctl -u rattenfalle -f
```

---

## Bedienung

```bash
python3 rattenfalle.py --status         # aktive Sperren anzeigen
python3 rattenfalle.py --unban 1.2.3.4  # IP wieder entsperren
python3 rattenfalle.py --self-test      # Test ohne zu sperren
```

---

## Konfiguration (`config.json`)

| Feld | Bedeutung |
|------|-----------|
| `honeypot.ports` | Köder-Ports. Leite hier den Angriffs-/Scan-Verkehr hin (z. B. per Router-Portweiterleitung ungenutzter Ports). |
| `honeypot.tarpit` / `tarpit_seconds` | Verbindung des Angreifers festhalten (Sekunden). |
| `log_watch.enabled` | `true` setzen und `files` auf dein echtes Access-Log zeigen lassen, um Angriffe auf den **echten** Webserver zu sperren. |
| `log_watch.strike_threshold` / `strike_window_seconds` | Ab wie vielen verdächtigen Treffern in welchem Zeitfenster gesperrt wird. |
| `ban.duration_seconds` | Sperrdauer (Standard 86400 = 24 h). |
| `whitelist` | Nie-sperren-Netze (CIDR). **Hier deine eigene feste IP eintragen!** |
| `firewall` | `auto` (empfohlen) oder fest: `nftables` / `iptables` / `windows` / `logonly`. |

Angriffsmuster stehen in **`attack_signatures.json`** und lassen sich frei
erweitern (`instant_ban_paths` = sofort sperren, `strike_paths` = erst nach
mehreren Treffern).

---

## Empfohlenes Setup für deinen Webserver

1. **Log-Watcher aktivieren** → schützt den *echten* Webserver:
   ```json
   "log_watch": { "enabled": true, "files": ["/var/log/nginx/access.log"] }
   ```
2. **Honeypot-Ports als Köder** exponieren (z. B. im Router 8080 → Server),
   damit automatisierte Scanner sofort in die Falle laufen.
3. **Eigene feste IP** in die `whitelist` eintragen, damit du dich nie selbst
   aussperrst.
4. Als **root/systemd-Dienst** laufen lassen, damit die Firewall-Sperren greifen.

---

## Selbst-Check: eigenen Anschluss prüfen (`selbst_check.py`)

Ein zweites Tool, das du **zuhause auf deinem Rechner** ausführst, um deine
eigenen Lücken zu finden. Prüft nur, greift nichts an, verändert nichts.
Nur Python 3, **kein nmap** nötig.

```bash
python selbst_check.py                 # voller Check inkl. Heimnetz-Scan
python selbst_check.py --no-netscan    # nur dieser Rechner + Exposition
python selbst_check.py --subnet 192.168.178.0/24   # Subnetz vorgeben
```

Es prüft:
1. **Offene Ports auf deinem Rechner** (riskante wie 502/23/3389/445 werden markiert).
2. **Deine öffentliche IP** + Links für einen **externen** Scan (Shodan etc.).
3. **UPnP** am Router (öffnet still Ports → Risiko).
4. **Router-Weboberfläche** erreichbar?
5. **Heimnetz-Scan**: welches Gerät hat welche riskanten Ports offen
   (z. B. Modbus 502, Telnet 23, RDP 3389, SMB 445 …).

Am Ende kommt eine **priorisierte Lücken-Liste** (kritisch → info) mit
konkreten Empfehlungen.

> ⚠️ Nur das **eigene** Netz scannen! Portscans in fremden Netzen sind in
> Deutschland unzulässig (§ 202a/c StGB). Das Skript scannt automatisch nur
> dein lokales Subnetz.

---

## Was diese Falle **nicht** tut (und warum)

- ❌ Kein „Zurückhacken", keine Gegenangriffe, kein DoS gegen Angreifer —
  das wäre illegal und würde Unbeteiligte treffen.
- ❌ Kein Ersatz für Updates, starke Passwörter, TLS und ein sauberes
  Reverse-Proxy-Setup. Die Falle ist eine **zusätzliche** Verteidigungsschicht.

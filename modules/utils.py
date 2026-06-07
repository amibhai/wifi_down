#!/usr/bin/env python3
"""
System utilities: root check, dependency verification, interface management,
structured logging, and tamper-evident HMAC-chained audit log.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import logging.handlers
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

from rich.logging import RichHandler

from modules.banner import C, info, success, warn, error

# ─── Paths ────────────────────────────────────────────────────────────────────

AUDIT_HOME = Path.home() / ".wifi-auditor"
LOG_FILE   = AUDIT_HOME / "audit.log"
CHAIN_FILE = AUDIT_HOME / "chain.json"

# ─── Required / optional tools ────────────────────────────────────────────────

REQUIRED_TOOLS = ['airmon-ng', 'airodump-ng', 'aireplay-ng', 'aircrack-ng', 'iw']
OPTIONAL_TOOLS = ['hcxdumptool', 'hcxtools', 'crunch', 'hashcat', 'macchanger', 'iwconfig']


###############################################################################
# Logging setup
###############################################################################

def setup_logging(level: int = logging.DEBUG) -> logging.Logger:
    """
    Configure root logger with two handlers:
      • RichHandler  — console, INFO+
      • RotatingFileHandler — ~/.wifi-auditor/audit.log, DEBUG+, 5 MB × 3

    File format: ISO8601 | level | module | message
    """
    AUDIT_HOME.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    # Console handler (rich, INFO+)
    console_handler = RichHandler(
        level=logging.INFO,
        rich_tracebacks=True,
        show_path=False,
        markup=True,
    )
    console_handler.setFormatter(logging.Formatter("%(message)s"))
    root.addHandler(console_handler)

    # File handler (rotating, DEBUG+)
    file_handler = logging.handlers.RotatingFileHandler(
        str(LOG_FILE),
        maxBytes=5 * 1024 * 1024,  # 5 MB
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(module)-20s | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    # Wrap with HMAC-chaining filter
    file_handler.addFilter(_HMACFilter())
    root.addHandler(file_handler)

    return root


###############################################################################
# HMAC-chained audit log
###############################################################################

def _get_chain_key() -> bytes:
    """Derive signing key from machine-id + tool version."""
    machine_id = ""
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            machine_id = Path(path).read_text().strip()
            break
        except OSError:
            pass
    version = "2.0.0"
    return hashlib.sha256(f"{machine_id}:{version}".encode()).digest()


def _load_chain() -> dict:
    if CHAIN_FILE.exists():
        try:
            return json.loads(CHAIN_FILE.read_text())
        except Exception:
            pass
    return {"previous_sig": "", "line_count": 0}


def _save_chain(chain: dict) -> None:
    CHAIN_FILE.write_text(json.dumps(chain, indent=2))


class _HMACFilter(logging.Filter):
    """Compute HMAC-SHA256 chained signature for each file log entry."""

    def __init__(self) -> None:
        super().__init__()
        self._key = _get_chain_key()

    def filter(self, record: logging.LogRecord) -> bool:
        chain = _load_chain()
        prev_sig = chain.get("previous_sig", "")
        msg = self.format_minimal(record)
        sig = hmac.new(
            self._key,
            (prev_sig + msg).encode(),
            hashlib.sha256,
        ).hexdigest()
        chain["previous_sig"] = sig
        chain["line_count"] = chain.get("line_count", 0) + 1
        _save_chain(chain)
        record.hmac_sig = sig  # type: ignore[attr-defined]
        return True

    @staticmethod
    def format_minimal(record: logging.LogRecord) -> str:
        return f"{record.levelname}|{record.module}|{record.getMessage()}"


def verify_audit_log() -> bool:
    """
    Walk audit.log and chain.json, recompute every HMAC, and report tampering.
    Returns True if the chain is intact.
    """
    from rich.console import Console
    con = Console()

    if not LOG_FILE.exists():
        con.print("[yellow]No audit log found.[/]")
        return True

    chain = _load_chain()
    key = _get_chain_key()
    prev_sig = ""
    ok = True

    with open(LOG_FILE, encoding="utf-8", errors="replace") as f:
        for lineno, raw_line in enumerate(f, 1):
            line = raw_line.rstrip("\n")
            sig = hmac.new(key, (prev_sig + line).encode(), hashlib.sha256).hexdigest()
            prev_sig = sig

    stored_sig = chain.get("previous_sig", "")
    if prev_sig != stored_sig:
        con.print(f"[bold red]✗ Audit log TAMPERED or MISSING lines! "
                  f"Expected {stored_sig[:16]}… got {prev_sig[:16]}…[/]")
        ok = False
    else:
        con.print(f"[bold green]✓ Audit log integrity verified "
                  f"({chain.get('line_count', '?')} entries, chain intact)[/]")

    return ok


def emit_session_summary(
    session_id: str,
    target: Optional[str],
    stage_reached: str,
    result: Optional[str],
    duration_s: float,
    errors: list[str],
) -> None:
    """Write a structured JSON summary record to the audit log."""
    logger = logging.getLogger(__name__)
    summary = {
        "event": "session_end",
        "session_id": session_id,
        "target": target,
        "stage_reached": stage_reached,
        "result": result,
        "duration_s": round(duration_s, 2),
        "errors": errors,
    }
    logger.info("SESSION_SUMMARY %s", json.dumps(summary))


###############################################################################
# Root / dependency checks
###############################################################################

def check_root() -> None:
    if os.geteuid() != 0:
        error("This tool must be run as root (sudo).")
        sys.exit(1)
    success("Running as root.")


def check_dependencies() -> None:
    logger = logging.getLogger(__name__)
    info("Checking required dependencies...")
    missing = []
    for tool in REQUIRED_TOOLS:
        if shutil.which(tool):
            success(f"  {tool}")
            logger.debug("Dependency OK: %s", tool)
        else:
            error(f"  {tool}  ← MISSING")
            missing.append(tool)

    info("Checking optional dependencies...")
    for tool in OPTIONAL_TOOLS:
        if shutil.which(tool):
            success(f"  {tool} (optional)")
        else:
            warn(f"  {tool}  ← not found (optional)")

    if missing:
        error(f"Missing required tools: {', '.join(missing)}")
        error("Run  ./install.sh  to install them.")
        sys.exit(1)


###############################################################################
# Subprocess helpers
###############################################################################

def run(cmd: list, capture: bool = True, timeout: int = 30) -> subprocess.CompletedProcess:
    logger = logging.getLogger(__name__)
    logger.debug("RUN %s", cmd)
    try:
        return subprocess.run(
            cmd, capture_output=capture, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        warn(f"Command timed out: {' '.join(cmd)}")
        logger.warning("Timeout: %s", cmd)
        return subprocess.CompletedProcess(cmd, returncode=1, stdout='', stderr='')
    except FileNotFoundError:
        error(f"Command not found: {cmd[0]}")
        logger.error("Not found: %s", cmd[0])
        return subprocess.CompletedProcess(cmd, returncode=1, stdout='', stderr='')


###############################################################################
# Interface management
###############################################################################

def get_wireless_interfaces() -> list:
    """Return list of wireless interface names (managed or monitor mode)."""
    interfaces = []

    # Try iw dev first (more reliable)
    result = run(['iw', 'dev'])
    if result.returncode == 0:
        for m in re.finditer(r'Interface\s+(\w+)', result.stdout):
            ifaces = m.group(1)
            if ifaces not in interfaces:
                interfaces.append(ifaces)

    # Fallback: iwconfig
    if not interfaces:
        result = run(['iwconfig'])
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                m = re.match(r'^(\S+)\s+IEEE 802\.11', line)
                if m and m.group(1) not in interfaces:
                    interfaces.append(m.group(1))
                elif re.match(r'^(\S+)\s+', line):
                    m2 = re.match(r'^(\S+)\s+', line)
                    if m2 and 'Mode:Monitor' in line and m2.group(1) not in interfaces:
                        interfaces.append(m2.group(1))

    return interfaces


def kill_interfering_processes() -> None:
    info("Killing interfering processes...")
    result = run(['airmon-ng', 'check', 'kill'])
    if result.returncode == 0:
        success("Interfering processes killed.")
    else:
        warn("Could not kill all interfering processes (may be fine).")


def enable_monitor_mode(interface: str) -> Optional[str]:
    """Enable monitor mode; return new interface name (e.g. wlan0mon) or None."""
    logger = logging.getLogger(__name__)
    info(f"Enabling monitor mode on {interface}...")
    result = run(['airmon-ng', 'start', interface])
    output = result.stdout + result.stderr
    logger.debug("airmon-ng start output: %s", output[:500])

    patterns = [
        r'monitor mode (?:vif )?enabled (?:for \[\S+\]\S+ )?on \[?(\w+)\]?',
        r'monitor mode enabled on (\w+)',
        r'\(mac80211 monitor mode vif enabled.*?on \[?\S*?\]?(\w+mon)\)',
    ]
    for pat in patterns:
        m = re.search(pat, output, re.IGNORECASE)
        if m:
            mon = m.group(1)
            success(f"Monitor mode: {mon}")
            logger.info("Monitor mode enabled: %s → %s", interface, mon)
            return mon

    # Fallback: guess
    guesses = [interface + 'mon', interface.replace('wlan', 'wlan') + 'mon']
    all_ifaces = get_wireless_interfaces()
    for g in guesses:
        if g in all_ifaces:
            success(f"Monitor mode: {g}")
            return g

    error(f"Could not determine monitor-mode interface name.")
    return None


def disable_monitor_mode(interface: str) -> None:
    logger = logging.getLogger(__name__)
    info(f"Disabling monitor mode on {interface}...")
    run(['airmon-ng', 'stop', interface])
    success("Monitor mode disabled.")
    logger.info("Monitor mode stopped: %s", interface)


def set_channel(interface: str, channel: int) -> None:
    run(['iwconfig', interface, 'channel', str(channel)])

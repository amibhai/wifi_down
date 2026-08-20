#!/usr/bin/env python3
"""
System utilities: root check, dependency verification, interface management,
and structured session logging.
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from rich.logging import RichHandler

from modules.banner import error, info, success, warn

# ─── Paths ────────────────────────────────────────────────────────────────────

AUDIT_HOME = Path.home() / ".wifi-auditor"
LOG_FILE   = AUDIT_HOME / "audit.log"

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
    root.addHandler(file_handler)

    return root


def emit_session_summary(
    session_id: str,
    target: str | None,
    stage_reached: str,
    result: str | None,
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

# Robust implementations live in modules/interface.py — re-exported here so the
# rest of the tool imports them from the utils facade. Late (post-def) import
# avoids a circular import with modules.interface, hence E402; the names are an
# intentional re-export, hence F401.
from modules.interface import (  # noqa: E402, F401
    disable_monitor_mode,
    enable_monitor_mode,
    kill_interfering_processes,
)


def get_wireless_interfaces() -> list:
    """Return list of all wireless interface names (managed and monitor mode)."""
    interfaces = []

    # Try iw dev first (more reliable)
    result = run(['iw', 'dev'])
    if result.returncode == 0:
        for m in re.finditer(r'Interface\s+(\w+)', result.stdout):
            iface = m.group(1)
            if iface not in interfaces:
                interfaces.append(iface)

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


def set_channel(interface: str, channel: int) -> None:
    run(['iwconfig', interface, 'channel', str(channel)])

#!/usr/bin/env python3
"""
Wireless interface management — compatibility facade over :mod:`modules.radio`.

The heavy lifting (rfkill, driver quirks, symmetric service save/restore, the
airmon-ng ↔ iw fallback, and process supervision) now lives in
``modules.radio``. This module preserves the exact public surface the rest of
the codebase and the test-suite depend on, so nothing downstream had to change:

    get_wireless_interfaces / get_monitor_interfaces
    kill_interfering_processes
    parse_new_interface_from_output / _interface_matches / verify_monitor_mode
    enable_monitor_mode / disable_monitor_mode
    verify_channel / check_injection_support
"""
from __future__ import annotations

import re
import shutil
import subprocess

from rich.console import Console

from modules import radio

console = Console()


# ─── Enumeration ──────────────────────────────────────────────────────────────

def get_wireless_interfaces() -> list[str]:
    """Return wireless interfaces currently in managed mode."""
    return radio.wireless_interfaces("managed")


def get_monitor_interfaces() -> list[str]:
    """Return wireless interfaces currently in monitor mode."""
    return radio.wireless_interfaces("monitor")


# ─── Interfering processes / services ─────────────────────────────────────────

def kill_interfering_processes() -> bool:
    """
    Stop the services/processes that block monitor mode.

    Unlike the old implementation this records exactly which services were
    active (via :func:`radio.stop_conflicting_services`) so they can be
    restored symmetrically — no more blindly restarting NetworkManager on an
    ``iwd`` box. Returns True.
    """
    console.print("[dim cyan]◈ Clearing interfering processes...[/]")
    radio.stop_conflicting_services()
    if shutil.which("airmon-ng"):
        try:
            subprocess.run(
                ["airmon-ng", "check", "kill"], capture_output=True, timeout=30
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
    console.print("[dim green]  ✓ Processes cleared[/]")
    return True


# ─── Parsing / verification (kept for API + test compatibility) ───────────────

def parse_new_interface_from_output(output: str, original: str) -> str | None:
    """Parse the new monitor interface name from airmon-ng start output."""
    return radio.parse_airmon_new_iface(output, original)


def verify_monitor_mode(interface: str) -> bool:
    """Return True if *interface* is confirmed in monitor mode via ``iw dev``."""
    return radio.is_monitor(interface)


def _interface_matches(monitor_iface: str, requested: str) -> bool:
    """True if a monitor interface corresponds to the requested base interface."""
    return radio.base_matches_monitor(monitor_iface, requested)


# ─── Enable / disable ─────────────────────────────────────────────────────────

def enable_monitor_mode(interface: str) -> str:
    """
    Enable monitor mode on *interface*, returning the monitor iface name.

    Raises ``RuntimeError`` with full diagnostics on failure. Now rfkill-aware,
    driver-quirk-aware, and equipped with an ``iw`` fallback when airmon-ng
    misbehaves — see :func:`radio.enable_monitor`.
    """
    return radio.enable_monitor(interface)


def disable_monitor_mode(monitor_interface: str) -> bool:
    """Restore *monitor_interface* to managed mode with symmetric service restore."""
    return radio.disable_monitor(monitor_interface)


# ─── Channel / injection ──────────────────────────────────────────────────────

def verify_channel(interface: str, expected_channel: int) -> bool:
    """Verify the interface is on the expected channel via ``iw dev info``."""
    try:
        result = subprocess.run(
            ["iw", "dev", interface, "info"],
            capture_output=True, text=True, timeout=5,
        )
        m = re.search(r"channel\s+(\d+)", result.stdout)
        if m:
            return int(m.group(1)) == expected_channel
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return False


def check_injection_support(interface: str, timeout: int = 10) -> bool:
    """Confirm packet injection via ``aireplay-ng --test`` before deauth."""
    return radio.check_injection_support(interface, timeout)

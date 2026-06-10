#!/usr/bin/env python3
"""
Robust wireless interface management: monitor mode enable/disable with full
process cleanup, airmon-ng output parsing, and iw dev verification.
"""
from __future__ import annotations

import os
import re
import subprocess
import time
from typing import Optional

from rich.console import Console

console = Console()


def get_wireless_interfaces() -> list[str]:
    """Return list of wireless interfaces currently in managed mode."""
    try:
        result = subprocess.run(
            ["iw", "dev"], capture_output=True, text=True, timeout=10
        )
        interfaces: list[str] = []
        current_iface: Optional[str] = None
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Interface "):
                current_iface = line.split("Interface ")[1].strip()
            if "type managed" in line and current_iface:
                interfaces.append(current_iface)
                current_iface = None
        return interfaces
    except Exception:
        return []


def get_monitor_interfaces() -> list[str]:
    """Return list of interfaces currently in monitor mode."""
    try:
        result = subprocess.run(
            ["iw", "dev"], capture_output=True, text=True, timeout=10
        )
        interfaces: list[str] = []
        current_iface: Optional[str] = None
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Interface "):
                current_iface = line.split("Interface ")[1].strip()
            if "type monitor" in line and current_iface:
                interfaces.append(current_iface)
                current_iface = None
        return interfaces
    except Exception:
        return []


def kill_interfering_processes() -> bool:
    """Kill all processes that block monitor mode. Returns True on success."""
    console.print("[dim cyan]◈ Checking for interfering processes...[/]")

    try:
        check = subprocess.run(
            ["airmon-ng", "check"], capture_output=True, text=True, timeout=10
        )
        if check.stdout.strip():
            console.print("[dim yellow]  Interfering processes found:[/]")
            for line in check.stdout.splitlines():
                if line.strip() and "PID" not in line and "Name" not in line:
                    console.print(f"[dim yellow]    {line.strip()}[/]")
    except Exception:
        pass

    console.print("[dim cyan]◈ Killing interfering processes...[/]")

    subprocess.run(
        ["airmon-ng", "check", "kill"], capture_output=True, text=True, timeout=30
    )

    for svc in ["NetworkManager", "wpa_supplicant"]:
        subprocess.run(["systemctl", "stop", svc], capture_output=True, timeout=10)

    for proc in ["wpa_supplicant", "dhclient", "dhcpcd"]:
        subprocess.run(["pkill", "-9", proc], capture_output=True, timeout=5)

    time.sleep(1.5)
    console.print("[dim green]  ✓ Processes cleared[/]")
    return True


def parse_new_interface_from_output(output: str, original: str) -> Optional[str]:
    """Parse the new monitor interface name from airmon-ng start output."""
    patterns = [
        r"monitor mode vif enabled for \[[\w]+\] on \[([\w]+)\]",
        r"monitor mode vif enabled on ([\w]+)",
        r"monitor mode enabled for ([\w]+)",
        r"\(mac80211 monitor mode vif enabled for \[[\w]+\] on \[([\w]+)\]\)",
        r"enabled on ([\w]+mon)",
    ]
    for pattern in patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return None


def verify_monitor_mode(interface: str) -> bool:
    """Return True if the interface is confirmed in monitor mode via iw dev."""
    try:
        result = subprocess.run(
            ["iw", "dev"], capture_output=True, text=True, timeout=10
        )
        in_iface = False
        for line in result.stdout.splitlines():
            line = line.strip()
            if line == f"Interface {interface}":
                in_iface = True
            elif line.startswith("Interface "):
                in_iface = False
            if in_iface and "type monitor" in line:
                return True
        return False
    except Exception:
        return False


def enable_monitor_mode(interface: str) -> str:
    """
    Enable monitor mode on *interface*.

    Returns the new monitor interface name (e.g. wlan0mon) on success.
    Raises RuntimeError with full diagnostic output on failure.
    """
    if os.geteuid() != 0:
        raise RuntimeError(
            "Root privileges required for monitor mode. Run: sudo wifi-auditor"
        )

    console.print(f"\n[cyan]◈ Enabling monitor mode on [bold]{interface}[/bold]...[/]")

    existing = get_monitor_interfaces()
    if existing:
        console.print(
            f"[dim green]◈ Monitor interface already active: [bold]{existing[0]}[/bold][/]"
        )
        return existing[0]

    kill_interfering_processes()

    console.print(f"[dim cyan]◈ Running: airmon-ng start {interface}...[/]")
    result = subprocess.run(
        ["airmon-ng", "start", interface],
        capture_output=True, text=True, timeout=30,
    )

    combined = result.stdout + result.stderr
    new_iface = parse_new_interface_from_output(combined, interface)

    if not new_iface:
        monitor_ifaces = get_monitor_interfaces()
        if monitor_ifaces:
            new_iface = monitor_ifaces[0]
        elif verify_monitor_mode(interface):
            new_iface = interface

    if not new_iface:
        raise RuntimeError(
            f"Failed to enable monitor mode on {interface}.\n"
            f"Command:     airmon-ng start {interface}\n"
            f"Return code: {result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}\n"
            f"Interfaces after attempt: {get_monitor_interfaces()}\n"
            f"Manual fix: sudo airmon-ng check kill && sudo airmon-ng start {interface}"
        )

    if not verify_monitor_mode(new_iface):
        raise RuntimeError(
            f"airmon-ng reported success but {new_iface} is not in monitor mode.\n"
            f"Current monitor interfaces: {get_monitor_interfaces()}\n"
            f"airmon-ng output:\n{combined}"
        )

    console.print(f"[green]◈ Monitor mode enabled: [bold]{new_iface}[/bold] ✓[/]")
    return new_iface


def disable_monitor_mode(monitor_interface: str) -> bool:
    """Restore *monitor_interface* to managed mode. Returns True on success."""
    console.print(f"[dim cyan]◈ Restoring {monitor_interface} to managed mode...[/]")
    result = subprocess.run(
        ["airmon-ng", "stop", monitor_interface],
        capture_output=True, text=True, timeout=30,
    )
    subprocess.run(["systemctl", "start", "NetworkManager"], capture_output=True, timeout=10)
    console.print("[dim green]  ✓ Interface restored[/]")
    return result.returncode == 0

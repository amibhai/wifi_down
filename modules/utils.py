#!/usr/bin/env python3
"""
System utilities: root check, dependency verification, interface management.
"""

import os
import re
import sys
import shutil
import subprocess
from modules.banner import C, info, success, warn, error

REQUIRED_TOOLS = ['airmon-ng', 'airodump-ng', 'aireplay-ng', 'aircrack-ng', 'iwconfig']
OPTIONAL_TOOLS = ['hcxdumptool', 'hcxtools', 'crunch', 'hashcat']


def check_root():
    if os.geteuid() != 0:
        error("This tool must be run as root (sudo).")
        sys.exit(1)
    success("Running as root.")


def check_dependencies():
    info("Checking required dependencies...")
    missing = []
    for tool in REQUIRED_TOOLS:
        if shutil.which(tool):
            success(f"  {tool}")
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


def run(cmd: list, capture=True, timeout=30) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=timeout
        )
    except subprocess.TimeoutExpired:
        warn(f"Command timed out: {' '.join(cmd)}")
        return subprocess.CompletedProcess(cmd, returncode=1, stdout='', stderr='')
    except FileNotFoundError:
        error(f"Command not found: {cmd[0]}")
        return subprocess.CompletedProcess(cmd, returncode=1, stdout='', stderr='')


def get_wireless_interfaces() -> list:
    """Return list of wireless interface names (managed or monitor mode)."""
    interfaces = []
    result = run(['iwconfig'])
    if result.returncode != 0:
        return interfaces
    for line in result.stdout.splitlines():
        # iwconfig lists interface names at the start of non-indented lines
        match = re.match(r'^(\S+)\s+IEEE 802\.11', line)
        if match:
            interfaces.append(match.group(1))
    # Also include monitor-mode interfaces not showing IEEE header
    result2 = run(['iwconfig'])
    for line in result2.stdout.splitlines():
        match = re.match(r'^(\S+)\s+', line)
        if match:
            iface = match.group(1)
            if 'Mode:Monitor' in line and iface not in interfaces:
                interfaces.append(iface)
    return interfaces


def kill_interfering_processes():
    """Kill NetworkManager, wpa_supplicant, etc. that interfere with monitor mode."""
    info("Killing interfering processes...")
    result = run(['airmon-ng', 'check', 'kill'])
    if result.returncode == 0:
        success("Interfering processes killed.")
    else:
        warn("Could not kill all interfering processes (may be fine).")


def enable_monitor_mode(interface: str) -> str | None:
    """
    Enable monitor mode on the given interface.
    Returns the monitor-mode interface name (e.g. wlan0mon) or None.
    """
    info(f"Enabling monitor mode on {interface}...")
    result = run(['airmon-ng', 'start', interface])
    output = result.stdout + result.stderr

    # Parse the new interface name from airmon-ng output
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
            return mon

    # Fallback: guess wlan0mon / phyXmon
    guesses = [interface + 'mon', interface.replace('wlan', 'wlan') + 'mon']
    all_ifaces = get_wireless_interfaces()
    for g in guesses:
        if g in all_ifaces:
            success(f"Monitor mode: {g}")
            return g

    error(f"Could not determine monitor-mode interface name. Raw output:\n{output}")
    return None


def disable_monitor_mode(interface: str):
    """Stop monitor mode and restore managed mode."""
    info(f"Disabling monitor mode on {interface}...")
    run(['airmon-ng', 'stop', interface])
    success("Monitor mode disabled.")


def set_channel(interface: str, channel: int):
    """Set wireless interface to a specific channel."""
    run(['iwconfig', interface, 'channel', str(channel)])

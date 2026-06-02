#!/usr/bin/env python3
"""
Network scanner: wraps airodump-ng, parses CSV output, displays network table.
"""

import os
import re
import csv
import time
import tempfile
import subprocess
from modules.banner import C, info, success, warn, error, print_section

DEFAULT_SCAN_TIME = 20   # seconds


def scan_networks(interface: str, duration: int = DEFAULT_SCAN_TIME) -> list[dict]:
    """
    Run airodump-ng for `duration` seconds and return a list of AP dicts.
    """
    print_section("Network Scanner")
    info(f"Scanning on {interface} for {duration}s  (Ctrl+C to stop early)...")

    tmp_dir  = tempfile.mkdtemp(prefix='wifiaudit_')
    out_base = os.path.join(tmp_dir, 'scan')

    proc = subprocess.Popen(
        ['airodump-ng', '--write', out_base, '--output-format', 'csv', '--write-interval', '2', interface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Live countdown
    try:
        for remaining in range(duration, 0, -1):
            networks = _parse_csv(out_base + '-01.csv')
            _print_network_table(networks, f"Scanning... {remaining}s remaining")
            time.sleep(1)
    except KeyboardInterrupt:
        warn("Scan interrupted by user.")
    finally:
        proc.terminate()
        proc.wait()

    networks = _parse_csv(out_base + '-01.csv')
    _print_network_table(networks, f"Scan complete — {len(networks)} network(s) found")
    return networks


def _parse_csv(filepath: str) -> list[dict]:
    """
    Parse airodump-ng CSV output (two sections: APs, then Stations).
    Returns list of AP dicts.
    """
    if not os.path.exists(filepath):
        return []

    networks = []
    in_ap_section = False

    try:
        with open(filepath, 'r', errors='replace') as f:
            content = f.read()
    except OSError:
        return []

    # Split into lines; the two sections are separated by a blank line
    lines = content.splitlines()
    ap_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('BSSID') and 'First time' in stripped:
            in_ap_section = True
            continue
        if stripped.startswith('Station MAC'):
            break       # Start of client section
        if in_ap_section and stripped:
            ap_lines.append(line)

    for line in ap_lines:
        parts = [p.strip() for p in line.split(',')]
        if len(parts) < 15:
            continue
        bssid      = parts[0]
        channel    = parts[3].strip()
        privacy    = parts[5].strip()   # WPA2, WPA, OPN, WEP …
        cipher     = parts[6].strip()
        auth       = parts[7].strip()
        power      = parts[8].strip()
        essid      = parts[13].strip()

        if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', bssid):
            continue

        try:
            ch = int(channel)
        except ValueError:
            ch = 0

        networks.append({
            'bssid':   bssid,
            'essid':   essid if essid else '<hidden>',
            'channel': ch,
            'privacy': privacy,
            'cipher':  cipher,
            'auth':    auth,
            'power':   power,
        })

    return networks


def _print_network_table(networks: list[dict], caption: str = ''):
    os.system('clear')
    if caption:
        print(f"\n  {C.CYAN}{caption}{C.RESET}\n")

    if not networks:
        warn("No networks found yet...")
        return

    # Header
    fmt = "  {:<4} {:<20} {:<19} {:<5} {:<12} {:<8}"
    print(C.BOLD + fmt.format('#', 'SSID', 'BSSID', 'CH', 'ENCRYPTION', 'PWR') + C.RESET)
    print(f"  {'─'*70}")

    for idx, net in enumerate(networks, 1):
        enc = net['privacy']
        # Color-code encryption type
        if 'WPA3' in enc:
            enc_colored = f"{C.GREEN}{enc}{C.RESET}"
        elif 'WPA2' in enc:
            enc_colored = f"{C.YELLOW}{enc}{C.RESET}"
        elif 'WPA' in enc:
            enc_colored = f"{C.YELLOW}{enc}{C.RESET}"
        elif 'OPN' in enc or enc == '':
            enc_colored = f"{C.RED}OPEN{C.RESET}"
        else:
            enc_colored = enc

        ssid_disp = net['essid'][:19]
        print(fmt.format(
            f"{C.WHITE}{idx}{C.RESET}",
            ssid_disp,
            net['bssid'],
            net['channel'],
            enc_colored,
            net['power'],
        ))


def select_network(networks: list[dict]) -> dict | None:
    """Prompt user to select a network from the scanned list."""
    if not networks:
        error("No networks to select from.")
        return None

    while True:
        try:
            raw = input(f"\n  {C.YELLOW}Select target [1-{len(networks)}] or 0 to cancel: {C.RESET}")
            choice = int(raw.strip())
            if choice == 0:
                return None
            if 1 <= choice <= len(networks):
                target = networks[choice - 1]
                # Normalize key used throughout the rest of the tool
                target['ssid'] = target['essid']
                success(f"Target: {target['ssid']}  [{target['bssid']}]  CH{target['channel']}")
                return target
            warn(f"Enter a number between 1 and {len(networks)}.")
        except ValueError:
            warn("Please enter a valid number.")
        except KeyboardInterrupt:
            return None

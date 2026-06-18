"""
modules/client_scanner.py

Dedicated client detection via airodump-ng CSV parsing.
Isolated from handshake.py to allow independent testing.
"""
from __future__ import annotations

import csv
import os
import shutil
import signal
import tempfile
import time
from dataclasses import dataclass
from subprocess import DEVNULL, Popen
from typing import List, Optional


@dataclass
class WifiClient:
    """A client station associated with an AP."""
    mac: str
    bssid: str
    power: int
    packets: int
    first_seen: str
    last_seen: str

    @property
    def signal_display(self) -> str:
        """Human-readable signal strength."""
        if self.power >= -50:
            return f"{self.power} dBm (excellent)"
        elif self.power >= -65:
            return f"{self.power} dBm (good)"
        elif self.power >= -75:
            return f"{self.power} dBm (fair)"
        else:
            return f"{self.power} dBm (weak)"


def scan_clients(
    bssid: str,
    channel: int,
    monitor_interface: str,
    duration: int = 12,
    verbose: bool = True,
) -> List[WifiClient]:
    """
    Discover clients associated with bssid on given channel.

    Uses airodump-ng with:
      -c CHANNEL          lock to target channel
      --bssid BSSID       filter output to target AP only
      -a                  only show ASSOCIATED clients (Bug 3 fix)
      --write-interval 1  flush CSV every second (Bug 2 fix)
      --output-format csv only write CSV
      -w PREFIX           output file prefix

    Returns list of WifiClient sorted by signal (strongest first).
    Returns empty list (not exception) if no clients found.
    """
    tmpdir = tempfile.mkdtemp(prefix='wd_clients_')
    prefix = os.path.join(tmpdir, 'scan')
    csv_path = prefix + '-01.csv'   # airodump ALWAYS appends -01

    cmd = [
        'airodump-ng',
        '-c', str(channel),
        '--bssid', bssid.upper(),
        '-a',                        # ONLY associated clients — Bug 3 fix
        '--write-interval', '1',     # flush CSV every second — Bug 2 fix
        '--output-format', 'csv',    # only CSV, no cap/netxml
        '-w', prefix,
        monitor_interface,
    ]

    try:
        proc = Popen(cmd, stdout=DEVNULL, stderr=DEVNULL)

        deadline = time.time() + duration
        while time.time() < deadline:
            time.sleep(1.0)
            if os.path.exists(csv_path) and os.path.getsize(csv_path) > 10:
                break   # file exists and has content; keep waiting for more data

        remaining = deadline - time.time()
        if remaining > 0:
            time.sleep(remaining)

        try:
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=3)
        except Exception:
            proc.kill()

        return _parse_airodump_csv(csv_path, bssid)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _parse_airodump_csv(csv_path: str, target_bssid: str) -> List[WifiClient]:
    """Parse airodump-ng CSV. Returns clients for target_bssid only."""
    if not os.path.exists(csv_path):
        return []

    clients: List[WifiClient] = []
    hit_clients = False     # Bug 5 fix: flag set BEFORE skipping the header row

    try:
        with open(csv_path, 'r', errors='replace') as f:
            # Bug 4 fix: strip null bytes before passing to csv.reader
            lines = [line.replace('\0', '') for line in f]

        reader = csv.reader(lines)
        for row in reader:
            # Bug 5 fix: detect section boundary FIRST, then skip headers
            if not row:
                continue
            first = row[0].strip()

            if first == 'Station MAC':
                hit_clients = True
                continue    # skip this header row

            if first in ('BSSID', '') or first.startswith('Station MAC'):
                continue    # skip AP header and blank lines

            if not hit_clients:
                continue    # still in AP section

            # We are in the Station section
            if len(row) < 6:
                continue

            # Bug 6 fix: strip ALL fields
            station_mac = row[0].strip().upper()
            first_seen  = row[1].strip()
            last_seen   = row[2].strip()
            power_str   = row[3].strip()
            packets_str = row[4].strip()
            assoc_bssid = row[5].strip().upper()

            # Skip unassociated clients
            if assoc_bssid in ('(NOT ASSOCIATED)', '', 'BSSID'):
                continue

            # Filter to target AP only — Bug 6 fix: compare stripped values
            if assoc_bssid != target_bssid.upper():
                continue

            # Skip invalid MACs
            if len(station_mac) != 17 or station_mac.count(':') != 5:
                continue

            try:
                power = int(power_str)
            except ValueError:
                power = -100

            try:
                packets = int(packets_str)
            except ValueError:
                packets = 0

            clients.append(WifiClient(
                mac=station_mac,
                bssid=assoc_bssid,
                power=power,
                packets=packets,
                first_seen=first_seen,
                last_seen=last_seen,
            ))

    except Exception:
        pass    # Never crash — just return what we have

    # Sort by signal strength (higher dBm = stronger signal)
    clients.sort(key=lambda c: c.power, reverse=True)

    # Remove duplicates (same MAC seen twice due to CSV re-writes)
    seen_macs: set = set()
    unique: List[WifiClient] = []
    for c in clients:
        if c.mac not in seen_macs:
            seen_macs.add(c.mac)
            unique.append(c)

    return unique


def display_clients(clients: List[WifiClient], bssid: str) -> None:
    """Print a table of discovered clients."""
    if not clients:
        print(f"  [!] No associated clients found for {bssid}")
        print(f"      Broadcast deauth will be used instead.")
        return

    print(f"\n  [+] Found {len(clients)} client(s) for {bssid}:\n")
    print(f"  {'#':<4} {'MAC':<19} {'Signal':<25} {'Packets'}")
    print(f"  {'─'*4} {'─'*19} {'─'*25} {'─'*7}")
    for i, c in enumerate(clients, 1):
        print(f"  {i:<4} {c.mac:<19} {c.signal_display:<25} {c.packets}")
    print()

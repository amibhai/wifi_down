#!/usr/bin/env python3
"""
wifi_down — CLI entry point.

Usage (interactive):
  sudo wifi-auditor
  sudo python3 -m wifi_auditor.cli

Usage (headless/automated):
  sudo wifi-auditor --headless --scope scope.yaml --target AA:BB:CC:DD:EE:FF --auto

Special commands:
  wifi-auditor --preflight              Run pre-flight dependency checker
  wifi-auditor --scope-wizard           Interactive scope.yaml builder
  wifi-auditor --report SESSION_ID      Generate pentest report (Markdown + JSON)
  wifi-auditor --report SESSION_ID --pdf  Generate PDF report alongside Markdown
  wifi-auditor --verify-log             Verify HMAC-chained audit log integrity
  wifi-auditor --refresh-oui            Re-download IEEE OUI database
  wifi-auditor --prism                  Launch PRISM rich TUI (experimental)
  wifi-auditor --lang LANG              Override UI language (en/es/fr/ar/hi/zh)
  wifi-auditor --neural-model MODEL     Override OpenAI model (default: gpt-4o-mini)
"""
from __future__ import annotations

import argparse
import logging
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.utils import (
    check_root, check_dependencies, setup_logging,
    get_wireless_interfaces, enable_monitor_mode, disable_monitor_mode,
    verify_audit_log, emit_session_summary,
)
from modules.banner import C, print_banner, print_menu, info, success, warn, error
from modules.scanner import scan_networks, select_network
from modules.handshake import capture_handshake
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
from modules.i18n import init as i18n_init, t

logger = logging.getLogger(__name__)

# ─── Session state ────────────────────────────────────────────────────────────

state: dict = {
    "interface":         None,
    "monitor_interface": None,
    "target":            None,
    "capture_file":      None,
    "wordlist_file":     None,
    "result":            None,
    "scan_results":      [],        # last scan result list (for Neural Pathfinder)
    "phantom_active":    False,     # set when Phantom AP is running
    "session_id":        None,      # active session ID
}

_scope:     ScopeManager = ScopeManager()
_sm:        StateManager  = StateManager()
_sequencer  = AttackSequencer()
_FAST_MODE: bool          = False
_NEURAL_MODEL: str        = "gpt-4o-mini"


def _cleanup() -> None:
    if state["monitor_interface"]:
        try:
            disable_monitor_mode(state["monitor_interface"])
        except Exception:
            pass


def _action_check_interface() -> None:
    """Print a full diagnostic of wireless interface status."""
    import shutil
    import subprocess as _sp
    from rich.console import Console as _Con
    from modules.interface import (
        get_wireless_interfaces as _get_managed,
        get_monitor_interfaces as _get_mon,
    )
    con = _Con()

    con.print("\n[bold cyan]━━━ wifi_down interface diagnostic ━━━[/]")

    iw_out = _sp.run(["iw", "dev"], capture_output=True, text=True)
    con.print("\n[bold cyan]◈ System interfaces (iw dev):[/]")
    con.print(iw_out.stdout.strip() or "(no output)")

    managed = _get_managed()
    con.print(f"\n[bold cyan]◈ Managed wireless interfaces:[/] {managed or 'none'}")

    mon = _get_mon()
    con.print(f"[bold cyan]◈ Monitor interfaces:[/] {mon or 'none'}")

    airmon_check = _sp.run(["airmon-ng", "check"], capture_output=True, text=True)
    con.print("\n[bold cyan]◈ Interfering processes (airmon-ng check):[/]")
    con.print(airmon_check.stdout.strip() or "(none)")

    airmon_avail = bool(shutil.which("airmon-ng"))
    con.print(
        f"\n[bold cyan]◈ airmon-ng available:[/] "
        f"{'[green]yes[/]' if airmon_avail else '[red]no — install aircrack-ng[/]'}"
    )

    is_root = os.geteuid() == 0
    con.print(
        f"[bold cyan]◈ Running as root:[/] "
        f"{'[green]yes[/]' if is_root else '[red]no — run: sudo wifi-auditor[/]'}"
    )

    if managed:
        con.print(f"\n[bold cyan]◈ Recommended interface:[/] [bold]{managed[0]}[/]")
    elif mon:
        con.print(f"\n[bold cyan]◈ Active monitor interface:[/] [bold]{mon[0]}[/]")
    else:
        con.print("\n[bold red]◈ No wireless interfaces found.[/]")
    con.print()


def _check_first_run() -> None:
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
        error(t("error.no_interface"))
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

    try:
        mon = enable_monitor_mode(iface)
        state["monitor_interface"] = mon
        _sm.transition(Stage.INTERFACE, monitor_interface=mon)
        success(f"Ready on {mon}")
    except RuntimeError as exc:
        error(str(exc))


def action_scan() -> None:
    if not state["monitor_interface"]:
        error(t("error.no_interface"))
        return
    try:
        secs = int(input(f"  {C.YELLOW}Scan duration [20]: {C.RESET}").strip() or "20")
    except (ValueError, KeyboardInterrupt):
        secs = 20

    _sm.transition(Stage.SCANNING)
    networks = scan_networks(state["monitor_interface"], secs)
    state["scan_results"] = networks

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
        _sequencer.score_target(target)


def action_capture() -> None:
    if not state["monitor_interface"]:
        error(t("error.no_interface"))
        return
    if not state["target"]:
        error(t("error.no_target"))
        return
    _sm.transition(Stage.CAPTURING)
    cap = capture_handshake(
        bssid=state["target"]["bssid"],
        ssid=state["target"]["ssid"],
        channel=state["target"]["channel"],
        monitor_interface=state["monitor_interface"],
    )
    if cap:
        state["capture_file"] = cap
        _sm.transition(Stage.CAPTURING, capture_file=cap)


def action_wordlist() -> None:
    ssid  = state["target"]["ssid"]  if state["target"] else None
    _sm.transition(Stage.WORDLIST)
    wl = wordlist_menu(ssid)
    if wl:
        state["wordlist_file"] = wl
        _sm.transition(Stage.WORDLIST, wordlist_file=wl)


def action_crack() -> None:
    if not state["capture_file"]:
        error(t("error.no_capture"))
        return
    if not state["wordlist_file"]:
        error(t("error.no_wordlist"))
        return
    _sm.transition(Stage.CRACKING)
    ssid = state["target"].get("ssid", "") if state.get("target") else ""
    cracker_menu(state["capture_file"], state["wordlist_file"], ssid=ssid)


def action_wps() -> None:
    if not state["monitor_interface"]:
        error(t("error.no_interface"))
        return
    wps_menu(state["monitor_interface"], state.get("target"),
             scope=_scope, fast=_FAST_MODE)


def action_full_auto() -> None:
    print(f"\n  {C.BOLD}{C.CYAN}═══ FULL AUTO MODE ═══{C.RESET}\n")

    if not state["monitor_interface"]:
        info("Step 1: Setting up interface...")
        action_set_interface()
        if not state["monitor_interface"]:
            error("Aborting — no monitor interface.")
            return
    else:
        success(f"Step 1: Interface → {state['monitor_interface']}")

    info("Step 2: Scanning for networks...")
    try:
        secs = int(input(f"  {C.YELLOW}Scan seconds [20]: {C.RESET}").strip() or "20")
    except (ValueError, KeyboardInterrupt):
        secs = 20

    networks = scan_networks(state["monitor_interface"], secs)
    state["scan_results"] = networks
    if not networks:
        error("No networks found.")
        return
    target = select_network(networks)
    if not target:
        return
    state["target"] = target

    info("Step 3: Probing WPS capability (6 s)...")
    wps = detect_wps_capability(
        state["monitor_interface"], target["bssid"], target.get("channel", 6)
    )
    target["wps_enabled"] = wps["enabled"]
    target["wps_locked"]  = wps["locked"]
    target["wps_version"] = wps["version"]
    _sequencer.score_target(target)

    if wps["enabled"] and not wps["locked"]:
        ver_tag = f" v{wps['version']}" if wps["version"] else ""
        success(f"WPS{ver_tag} enabled and unlocked → taking WPS attack path")
        wps_menu(state["monitor_interface"], target, scope=_scope, fast=_FAST_MODE)
        return

    if wps["enabled"] and wps["locked"]:
        warn(f"WPS detected but AP-Lock is set — falling back to handshake path.")

    info("Step 4: Capturing handshake...")
    cap = capture_handshake(
        bssid=target["bssid"],
        ssid=target["ssid"],
        channel=target["channel"],
        monitor_interface=state["monitor_interface"],
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
        error(t("error.no_interface"))
        return
    if not state["target"]:
        error(t("error.no_target"))
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
        error(t("error.no_interface"))
        return
    deauth_menu(state["monitor_interface"], state.get("target"),
                scope=_scope, fast=_FAST_MODE)


def action_ghost() -> None:
    """Ghost Signal Tracker — CVE + firmware intelligence."""
    from modules.ghost import ghost_menu
    ghost_menu(state.get("target"))


def action_neural() -> None:
    """Neural Pathfinder — AI-powered attack brief."""
    from modules.neural import neural_menu
    if not state.get("scan_results"):
        warn("No scan results yet. Running a scan first is recommended.")
    neural_menu(state.get("scan_results") or [], openai_model=_NEURAL_MODEL)


def action_historian() -> None:
    """Beacon Historian — passive AP behavioral profiling."""
    from modules.historian import historian_menu
    if not state["monitor_interface"]:
        error(t("error.no_interface"))
        return
    historian_menu(state["monitor_interface"], state.get("target"))


def action_phantom() -> None:
    """Phantom AP — Signal Shadowing rogue access point."""
    from modules.phantom import phantom_menu
    if not state["monitor_interface"]:
        error(t("error.no_interface"))
        return
    phantom_menu(
        interface=state["monitor_interface"],
        target=state.get("target"),
        scope=_scope,
        fast=_FAST_MODE,
    )
    state["phantom_active"] = True


def action_temporal() -> None:
    """Temporal Attack Engine — time-based PSK prediction."""
    from modules.temporal import temporal_menu
    wl = temporal_menu(target=state.get("target"))
    if wl:
        state["wordlist_file"] = str(wl)
        info(f"Temporal wordlist set as active wordlist: {wl}")


def action_intercept() -> None:
    """Signal Intercept — post-Phantom AP protocol fingerprinting."""
    from modules.intercept import intercept_menu
    if not state["monitor_interface"]:
        error(t("error.no_interface"))
        return
    sid = _sm.state.session_id if hasattr(_sm, "state") else "unknown"
    intercept_menu(
        interface=state["monitor_interface"],
        session_id=sid,
        phantom_active=state.get("phantom_active", False),
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
        "phantom_active":    "Phantom AP active",
    }
    for k, label in labels.items():
        v = state.get(k)
        if k == "target" and isinstance(v, dict):
            v = f"{v.get('ssid')}  [{v.get('bssid')}]  CH{v.get('channel')}"
        colour = C.GREEN if v else C.DIM
        print(f"    {label:<22} : {colour}{v or 'not set'}{C.RESET}")
    print()


def action_report(session_id: str, generate_pdf: bool = False) -> None:
    """Generate Markdown + optional PDF report."""
    from modules.report import generate_report as gen_md
    try:
        md, js = gen_md(session_id)
        print(f"  {C.GREEN}[+]{C.RESET} Markdown: {md}")
        print(f"  {C.GREEN}[+]{C.RESET} Findings: {js}")
    except FileNotFoundError as exc:
        error(str(exc))
        return

    if generate_pdf:
        from modules.report_pdf import generate_pdf_report
        pdf = generate_pdf_report(session_id)
        if pdf:
            print(f"  {C.GREEN}[+]{C.RESET} PDF report: {pdf}")
        else:
            warn("PDF engine unavailable. Install reportlab or weasyprint.")


###############################################################################
# Headless / automated mode
###############################################################################

def run_headless(
    scope_file: str,
    target_bssid: str,
    iface: str = "",
    deauth_limit: int = DEFAULT_MAX_BURSTS_PER_MIN,
) -> int:
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

    if not iface:
        ifaces = get_wireless_interfaces()
        if not ifaces:
            logger.error("No wireless interfaces found")
            return 1
        iface = ifaces[0]

    try:
        mon = enable_monitor_mode(iface)
    except RuntimeError as exc:
        logger.error("Could not enable monitor mode on %s: %s", iface, exc)
        return 1
    sm.transition(Stage.INTERFACE, interface=iface, monitor_interface=mon)

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
    _sequencer.score_target(target)

    logger.info("Capturing handshake for %s ...", target_bssid)
    sm.transition(Stage.CAPTURING)
    cap = capture_handshake(
        bssid=target["bssid"],
        ssid=target.get("ssid", target["bssid"]),
        channel=target["channel"],
        monitor_interface=mon,
    )
    if not cap:
        logger.error("Handshake capture failed")
        disable_monitor_mode(mon)
        sm.transition(Stage.FAILED)
        return 1
    sm.transition(Stage.CAPTURING, capture_file=cap)

    logger.info("Generating wordlist ...")
    sm.transition(Stage.WORDLIST)
    wl = wordlist_menu(target.get("ssid", ""), auto=True)
    if not wl:
        logger.error("Wordlist generation failed")
        sm.transition(Stage.FAILED)
        return 1
    sm.transition(Stage.WORDLIST, wordlist_file=wl)

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
# PRISM TUI (Leapfrog 3) — launched via --prism
###############################################################################

def launch_prism() -> None:
    """Launch the PRISM rich TUI interface (opt-in, requires textual)."""
    try:
        from textual.app import App, ComposeResult
        from textual.widgets import Header, Footer, Static, DataTable, Log
        from textual.containers import Horizontal, Vertical
    except ImportError:
        error("PRISM TUI requires textual. Install: pip install textual")
        info("Falling back to standard menu. Use --no-tui to suppress this message.")
        return

    from rich.text import Text
    import textwrap

    class PRISMApp(App):
        CSS = textwrap.dedent("""
            Screen { background: #0d0d0d; }
            Header { background: #001a14; color: #00D4AA; }
            Footer { background: #001a14; color: #00D4AA; }
            #left  { width: 30%; border: solid #00D4AA; padding: 1; }
            #center{ width: 50%; border: solid #00D4AA; padding: 1; }
            #right { width: 20%; border: solid #00D4AA; padding: 1; }
            .title { color: #00D4AA; text-style: bold; }
            DataTable { height: 100%; }
        """)

        BINDINGS = [
            ("s", "scan",      t("menu.scan")),
            ("w", "wps",       t("menu.wps")),
            ("h", "handshake", t("menu.handshake")),
            ("c", "crack",     t("menu.crack")),
            ("p", "phantom",   t("menu.phantom")),
            ("g", "ghost",     t("menu.ghost")),
            ("n", "neural",    t("menu.neural")),
            ("r", "report",    t("menu.report")),
            ("?", "help",      "Help"),
            ("q", "quit",      t("menu.exit")),
        ]

        def compose(self) -> ComposeResult:
            yield Header()
            with Horizontal():
                with Vertical(id="left"):
                    yield Static("[bold #00D4AA]TARGET LIST[/bold #00D4AA]", classes="title")
                    yield DataTable(id="target_table")
                with Vertical(id="center"):
                    yield Static("[bold #00D4AA]ACTIVE OPERATION[/bold #00D4AA]", classes="title")
                    yield Log(id="operation_log", auto_scroll=True)
                with Vertical(id="right"):
                    yield Static("[bold #00D4AA]SESSION INTEL[/bold #00D4AA]", classes="title")
                    yield Static(id="intel_panel")
            yield Footer()

        def on_mount(self) -> None:
            t_table = self.query_one("#target_table", DataTable)
            t_table.add_columns("SSID", "BSSID", "Sec", "CH", "GHOST")
            for net in state.get("scan_results", []):
                t_table.add_row(
                    net.get("ssid", "–"),
                    net.get("bssid", "–"),
                    net.get("privacy", "–"),
                    str(net.get("channel", "–")),
                    "❓",
                )

        def action_quit(self) -> None:
            self.exit()

    try:
        app = PRISMApp(title="wifi_down — PRISM")
        app.run()
    except Exception as exc:
        error(f"PRISM TUI error: {exc}")
        logger.exception("PRISM TUI error")


###############################################################################
# Argument parser
###############################################################################

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wifi-auditor",
        description="wifi_down — WiFi Security Auditing Framework — authorized use only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo wifi-auditor                                   # interactive menu
  sudo wifi-auditor --preflight                       # pre-flight check
  sudo wifi-auditor --scope-wizard                    # build scope.yaml
  sudo wifi-auditor --headless --scope scope.yaml \\
       --target AA:BB:CC:DD:EE:FF --auto             # headless scan
  wifi-auditor --report 20260604_120000               # generate report
  wifi-auditor --report 20260604_120000 --pdf         # report + PDF
  wifi-auditor --verify-log                           # verify audit log
  sudo wifi-auditor --prism                           # PRISM TUI (experimental)
""",
    )
    p.add_argument("--preflight",    action="store_true",
                   help="Run pre-flight checker and exit")
    p.add_argument("--scope-wizard", action="store_true",
                   help="Run interactive scope.yaml wizard")
    p.add_argument("--scope",        metavar="FILE",
                   help="Path to scope.yaml (default: ./scope.yaml)")
    p.add_argument("--headless",     action="store_true",
                   help="Non-interactive automated mode")
    p.add_argument("--target",       metavar="BSSID",
                   help="Target BSSID for headless mode")
    p.add_argument("--auto",         action="store_true",
                   help="Alias for --headless")
    p.add_argument("--interface",    metavar="IFACE",
                   help="Wireless interface for headless mode")
    p.add_argument("--deauth-limit", type=int, default=DEFAULT_MAX_BURSTS_PER_MIN,
                   metavar="N",
                   help=f"Max deauth bursts/min (default {DEFAULT_MAX_BURSTS_PER_MIN}, max 20)")
    p.add_argument("--report",       metavar="SESSION_ID",
                   help="Generate pentest report for session")
    p.add_argument("--pdf",          action="store_true",
                   help="Include PDF output with --report")
    p.add_argument("--verify-log",   action="store_true",
                   help="Verify HMAC-chained audit log")
    p.add_argument("--refresh-oui",  action="store_true",
                   help="Re-download IEEE OUI database")
    p.add_argument("--prism",        action="store_true",
                   help="Launch PRISM rich TUI interface (requires textual)")
    p.add_argument("--no-tui",       action="store_true",
                   help="Force classic text menu even if --prism was set")
    p.add_argument("--lang",         metavar="LANG",
                   help="UI language override (en/es/fr/ar/hi/zh)")
    p.add_argument("--neural-model", metavar="MODEL", default="gpt-4o-mini",
                   help="OpenAI model for Neural Pathfinder (default: gpt-4o-mini)")
    p.add_argument("--check-interface", action="store_true",
                   help="Diagnose wireless interface and monitor mode status, then exit")
    p.add_argument("--debug",        action="store_true",
                   help="Enable DEBUG logging")
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
    "g": action_ghost,
    "G": action_ghost,
    "N": action_neural,
    "h": action_historian,
    "H": action_historian,
    "p": action_phantom,
    "P": action_phantom,
    "t": action_temporal,
    "T": action_temporal,
    "I": action_intercept,
    "r": lambda: action_report(
        _sm.state.session_id if hasattr(_sm, "state") else "unknown"
    ),
}


def main() -> None:
    global _scope, _FAST_MODE, _NEURAL_MODEL

    parser = _build_parser()
    args   = parser.parse_args()

    # ── i18n init ──────────────────────────────────────────────────────────────
    i18n_init(args.lang if args.lang else None)

    log_level = logging.DEBUG if args.debug else logging.INFO
    setup_logging(log_level)

    _NEURAL_MODEL = args.neural_model

    if getattr(args, "fast", False):
        _FAST_MODE = True
        from rich.console import Console
        from rich import box as rbox
        from rich.panel import Panel
        Console().print(Panel(
            "[bold red]⚡  FAST / LAB MODE  ⚡[/]\n\n"
            "Scope enforcement and consent prompts are DISABLED.\n"
            "[bold yellow]Only use this on networks you own or have written authorization to test.[/]\n"
            "Unauthorized use is illegal under CFAA / CMA / IT Act 2000.",
            title="[bold red]Warning — Reduced Safeguards[/]",
            box=rbox.DOUBLE,
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
        action_report(args.report, generate_pdf=args.pdf)
        return

    if getattr(args, "check_interface", False):
        _action_check_interface()
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

    # ── PRISM TUI (opt-in) ────────────────────────────────────────────────────
    if args.prism and not args.no_tui:
        check_root()
        _check_first_run()
        check_dependencies()
        launch_prism()
        return

    # ── Interactive menu ──────────────────────────────────────────────────────
    check_root()
    _check_first_run()
    check_dependencies()
    scope_label = str(scope_path) if scope_path.exists() else None
    print_banner(
        interface=state.get("monitor_interface") or "not set",
        targets=len(state.get("scan_results") or []),
        scope_file=scope_label,
    )

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

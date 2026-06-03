#!/usr/bin/env python3
"""
WiFi Auditor — Automated WPA2/WPA3 Security Testing Framework
──────────────────────────────────────────────────────────────
For AUTHORIZED penetration testing only.
Requires: root, Kali/Parrot Linux, aircrack-ng suite.

Usage:
  sudo python3 wifi_auditor.py
"""

import os
import sys
import signal

# Ensure we can import modules from the repo root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.banner import C, print_banner, print_menu, info, success, warn, error
from modules.utils  import check_root, check_dependencies, get_wireless_interfaces, \
                           enable_monitor_mode, disable_monitor_mode, kill_interfering_processes
from modules.scanner    import scan_networks, display_networks, select_network
from modules.handshake  import capture_handshake_menu
from modules.wordlist   import wordlist_menu
from modules.cracker    import cracker_menu
from modules.wep        import wep_crack_menu

# ─── Session state ───────────────────────────────────────────────────────────
state = {
    'interface':         None,   # original managed interface (e.g. wlan0)
    'monitor_interface': None,   # monitor-mode interface (e.g. wlan0mon)
    'target':            None,   # dict from scanner
    'capture_file':      None,   # path to .cap file
    'wordlist_file':     None,   # path to wordlist
    'result':            None,   # cracked key if found
}


# ─── Signal / cleanup ────────────────────────────────────────────────────────

def _cleanup():
    if state['monitor_interface']:
        try:
            disable_monitor_mode(state['monitor_interface'])
        except Exception:
            pass

def _signal_handler(sig, frame):
    print(f"\n\n{C.YELLOW}[!] Caught signal {sig}. Cleaning up...{C.RESET}")
    _cleanup()
    sys.exit(0)

signal.signal(signal.SIGINT,  _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


# ─── Menu actions ─────────────────────────────────────────────────────────────

def action_set_interface():
    interfaces = get_wireless_interfaces()
    if not interfaces:
        error("No wireless interfaces found. Check your adapter.")
        return

    print(f"\n  {C.CYAN}Available Wireless Interfaces:{C.RESET}")
    for i, iface in enumerate(interfaces, 1):
        indicator = ''
        if 'mon' in iface.lower():
            indicator = f" {C.DIM}(already monitor){C.RESET}"
        print(f"    {C.WHITE}[{i}]{C.RESET} {iface}{indicator}")

    try:
        raw = input(f"\n  {C.YELLOW}Select interface [1-{len(interfaces)}]: {C.RESET}").strip()
        choice = int(raw) - 1
        if not (0 <= choice < len(interfaces)):
            raise ValueError
    except (ValueError, KeyboardInterrupt):
        warn("Selection cancelled.")
        return

    iface = interfaces[choice]
    state['interface'] = iface

    kill_interfering_processes()
    mon = enable_monitor_mode(iface)
    if mon:
        state['monitor_interface'] = mon
        success(f"Ready on {mon}")
    else:
        error("Could not enable monitor mode.")
        state['monitor_interface'] = None


def action_scan():
    if not state['monitor_interface']:
        error("Set interface first (Option 1).")
        return

    try:
        secs = int(input(f"  {C.YELLOW}Scan duration in seconds [20]: {C.RESET}").strip() or '20')
    except (ValueError, KeyboardInterrupt):
        secs = 20

    networks = scan_networks(state['monitor_interface'], secs)
    if not networks:
        warn("No networks discovered.")
        return

    target = select_network(networks)
    if target:
        state['target'] = target


def action_capture():
    if not state['monitor_interface']:
        error("Set interface first (Option 1).")
        return
    if not state['target']:
        error("Scan and select a target first (Option 2).")
        return

    cap = capture_handshake_menu(state['monitor_interface'], state['target'])
    if cap:
        state['capture_file'] = cap


def action_wordlist():
    ssid = state['target']['ssid'] if state['target'] else None
    wl = wordlist_menu(ssid)
    if wl:
        state['wordlist_file'] = wl


def action_crack():
    if not state['capture_file']:
        error("Capture a handshake first (Option 3).")
        return
    if not state['wordlist_file']:
        error("Generate a wordlist first (Option 4).")
        return
    cracker_menu(state['capture_file'], state['wordlist_file'])


def action_full_auto():
    """End-to-end automated attack pipeline."""
    print(f"\n  {C.BOLD}{C.CYAN}═══ FULL AUTO MODE ═══{C.RESET}\n")

    # Step 1: Interface
    if not state['monitor_interface']:
        info("Step 1/5: Setting up interface...")
        action_set_interface()
        if not state['monitor_interface']:
            error("Aborting — no monitor interface.")
            return
    else:
        success(f"Step 1/5: Interface already set → {state['monitor_interface']}")

    # Step 2: Scan
    info("Step 2/5: Scanning for networks...")
    try:
        secs = int(input(f"  {C.YELLOW}Scan seconds [20]: {C.RESET}").strip() or '20')
    except (ValueError, KeyboardInterrupt):
        secs = 20
    networks = scan_networks(state['monitor_interface'], secs)
    if not networks:
        error("No networks found.")
        return
    target = select_network(networks)
    if not target:
        return
    state['target'] = target

    # Step 3: Capture
    info("Step 3/5: Capturing handshake...")
    cap = capture_handshake_menu(state['monitor_interface'], state['target'], auto=True)
    if not cap:
        error("Handshake capture failed.")
        return
    state['capture_file'] = cap

    # Step 4: Wordlist
    info("Step 4/5: Generating wordlist...")
    wl = wordlist_menu(state['target']['ssid'], auto=True)
    if not wl:
        error("Wordlist generation failed.")
        return
    state['wordlist_file'] = wl

    # Step 5: Crack
    info("Step 5/5: Cracking...")
    cracker_menu(state['capture_file'], state['wordlist_file'])


def action_wep():
    """WEP cracking — IV capture + crack pipeline."""
    if not state['monitor_interface']:
        error("Set interface first (Option 1).")
        return
    if not state['target']:
        error("Scan and select a target first (Option 2).")
        return

    enc = state['target'].get('privacy', '')
    if 'WEP' not in enc.upper():
        warn(f"Target encryption is '{enc}', not WEP.")
        c = input(f"  {C.YELLOW}Continue anyway? [y/N]: {C.RESET}").strip().lower()
        if c != 'y':
            return

    key = wep_crack_menu(state['monitor_interface'], state['target'])
    if key:
        state['result'] = key


def action_show_state():
    print(f"\n  {C.CYAN}Session State:{C.RESET}")
    labels = {
        'interface':         'Base interface',
        'monitor_interface': 'Monitor interface',
        'target':            'Target',
        'capture_file':      'Capture file',
        'wordlist_file':     'Wordlist',
        'result':            'Cracked key',
    }
    for k, label in labels.items():
        v = state[k]
        if k == 'target' and isinstance(v, dict):
            v = f"{v.get('ssid')}  [{v.get('bssid')}]  CH{v.get('channel')}"
        colour = C.GREEN if v else C.DIM
        print(f"    {label:<20} : {colour}{v or 'not set'}{C.RESET}")
    print()


# ─── Main loop ───────────────────────────────────────────────────────────────

ACTIONS = {
    '1': action_set_interface,
    '2': action_scan,
    '3': action_capture,
    '4': action_wordlist,
    '5': action_crack,
    '6': action_full_auto,
    '7': action_wep,
    '8': action_show_state,
}

def main():
    check_root()
    check_dependencies()
    print_banner()

    while True:
        try:
            print_menu(state)
            choice = input(f"\n  {C.YELLOW}[>] {C.RESET}").strip()

            if choice == '0':
                warn("Exiting...")
                _cleanup()
                sys.exit(0)

            action = ACTIONS.get(choice)
            if action:
                action()
            else:
                error(f"Unknown option: {choice}")

        except KeyboardInterrupt:
            print()
            warn("Use [0] to exit cleanly.")
        except Exception as exc:
            error(f"Unexpected error: {exc}")
            import traceback
            traceback.print_exc()


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
Banner, colors, and display helpers for WiFi Auditor.
"""

import os
import shutil

# ANSI color codes
class Colors:
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    RESET   = '\033[0m'

C = Colors  # short alias

BANNER = f"""{C.RED}{C.BOLD}
 ██╗    ██╗██╗███████╗██╗      █████╗ ██╗   ██╗██████╗ ██╗████████╗ ██████╗ ██████╗
 ██║    ██║██║██╔════╝██║     ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝██╔═══██╗██╔══██╗
 ██║ █╗ ██║██║█████╗  ██║     ███████║██║   ██║██║  ██║██║   ██║   ██║   ██║██████╔╝
 ██║███╗██║██║██╔══╝  ██║     ██╔══██║██║   ██║██║  ██║██║   ██║   ██║   ██║██╔══██╗
 ╚███╔███╔╝██║██║     ╚══════╝██║  ██║╚██████╔╝██████╔╝██║   ██║   ╚██████╔╝██║  ██║
  ╚══╝╚══╝ ╚═╝╚═╝             ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝{C.RESET}
{C.CYAN}       WEP / WPA2 / WPA3 Automated Security Auditing Framework{C.RESET}
{C.DIM}          For authorized penetration testing ONLY. v1.1{C.RESET}
"""

DISCLAIMER = f"""
{C.YELLOW}{'═'*70}
  LEGAL DISCLAIMER
{'═'*70}{C.RESET}
  This tool is intended ONLY for:
    • Authorized penetration testing on networks you own
    • Networks you have explicit written permission to test
    • Educational / lab environments you control

  Unauthorized use against networks you do not own or have
  permission to test is ILLEGAL under the Computer Fraud and
  Abuse Act (CFAA), UK Computer Misuse Act, and equivalent
  laws worldwide.  The author accepts NO liability for misuse.
{C.YELLOW}{'═'*70}{C.RESET}
"""

MENU_TEMPLATE = f"""
{C.CYAN}{'─'*60}{C.RESET}
  {C.BOLD}{C.WHITE}MAIN MENU{C.RESET}
{C.CYAN}{'─'*60}{C.RESET}
  {C.BOLD}{C.DIM}── WPA2 / WPA3 ───────────────────────────────────────{C.RESET}
  {C.GREEN}[1]{C.RESET} Select / Set Interface (monitor mode)
  {C.GREEN}[2]{C.RESET} Scan Nearby Networks
  {C.GREEN}[3]{C.RESET} Capture Handshake  (passive / deauth / PMKID)
  {C.GREEN}[4]{C.RESET} Generate Wordlist
  {C.GREEN}[5]{C.RESET} Crack WPA2/WPA3 Handshake
  {C.GREEN}[6]{C.RESET} {C.BOLD}Full Auto Mode{C.RESET} WPA2/WPA3  (1→2→3→4→5)
  {C.BOLD}{C.DIM}── WEP ───────────────────────────────────────────────{C.RESET}
  {C.MAGENTA}[7]{C.RESET} {C.BOLD}WEP Crack{C.RESET}  (ARP replay / fragmentation / ChopChop)
  {C.BOLD}{C.DIM}── Misc ──────────────────────────────────────────────{C.RESET}
  {C.CYAN}[8]{C.RESET} Show Session State
  {C.RED}[0]{C.RESET} Exit
{C.CYAN}{'─'*60}{C.RESET}"""


def print_banner():
    os.system('clear')
    print(BANNER)
    print(DISCLAIMER)
    input(f"{C.YELLOW}  Press ENTER to continue...{C.RESET} ")
    os.system('clear')
    print(BANNER)


def print_menu(state: dict):
    print(MENU_TEMPLATE)
    # Status bar
    iface  = state.get('monitor_interface') or f"{C.DIM}not set{C.RESET}"
    target = state['target']['ssid'] if state.get('target') else f"{C.DIM}not set{C.RESET}"
    cap    = state.get('capture_file') or f"{C.DIM}none{C.RESET}"
    wl     = state.get('wordlist_file') or f"{C.DIM}none{C.RESET}"
    print(f"  {C.DIM}iface={C.RESET}{C.CYAN}{iface}{C.RESET}  "
          f"{C.DIM}target={C.RESET}{C.CYAN}{target}{C.RESET}  "
          f"{C.DIM}cap={C.RESET}{C.CYAN}{os.path.basename(str(cap))}{C.RESET}  "
          f"{C.DIM}wordlist={C.RESET}{C.CYAN}{os.path.basename(str(wl))}{C.RESET}")


def print_section(title: str):
    w = shutil.get_terminal_size((80, 24)).columns
    print(f"\n{C.BOLD}{C.CYAN}{'═'*w}")
    print(f"  {title}")
    print(f"{'═'*w}{C.RESET}")


def info(msg: str):   print(f"  {C.CYAN}[*]{C.RESET} {msg}")
def success(msg: str): print(f"  {C.GREEN}[+]{C.RESET} {msg}")
def warn(msg: str):   print(f"  {C.YELLOW}[!]{C.RESET} {msg}")
def error(msg: str):  print(f"  {C.RED}[-]{C.RESET} {msg}")
def found(msg: str):  print(f"\n  {C.BOLD}{C.GREEN}[★]{C.RESET} {C.BOLD}{msg}{C.RESET}\n")

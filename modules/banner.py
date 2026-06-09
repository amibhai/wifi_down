#!/usr/bin/env python3
"""
wifi_down — Terminal Identity Module
Animated block-letter banner, status bar, and display helpers.
"""
from __future__ import annotations

import os
import random
import shutil
import time
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.style import Style
from rich.text import Text
from rich import box
from rich.panel import Panel

# ─── ANSI compatibility shim (used by legacy modules) ────────────────────────

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

C = Colors
_con = Console()

# ─── Color palette ────────────────────────────────────────────────────────────
_TEAL     = "#00D4AA"
_DIM_CYAN = "dim cyan"

# ─── Block letter art: 5 rows × fixed width using box-drawing characters ──────
_LETTERS: dict[str, list[str]] = {
    'w': [
        "╷   ╷",
        "╷   ╷",
        "╷ ╷ ╷",
        "╷╷ ╷╷",
        "╯   ╯",
    ],
    'i': [
        " ─ ",
        "   ",
        " ╷ ",
        " ╷ ",
        " ╵ ",
    ],
    'f': [
        "╭──",
        "├─ ",
        "╷  ",
        "╷  ",
        "╵  ",
    ],
    '_': [
        "    ",
        "    ",
        "    ",
        "    ",
        "────",
    ],
    'd': [
        " ─╮",
        "  ╷",
        "  ╷",
        "  ╷",
        " ─╯",
    ],
    'o': [
        "╭─╮",
        "╷ ╷",
        "╷ ╷",
        "╷ ╷",
        "╰─╯",
    ],
    'n': [
        "╭─╮",
        "╷╷╷",
        "╷ ╷",
        "╷ ╷",
        "╵ ╵",
    ],
}

_WORD = "wifi_down"

_TAGLINES = [
    "silence is not security.",
    "every network has a story.",
    "the quietest signal is the loudest warning.",
    "authorized eyes only.",
    "packets don't lie.",
    "trust nothing. verify everything.",
]

# ─── Banner construction ──────────────────────────────────────────────────────

def _build_art_rows() -> list[str]:
    """Combine letter blocks side-by-side with 2-space gaps."""
    rows = [""] * 5
    sep = "  "
    for idx, ch in enumerate(_WORD):
        block = _LETTERS.get(ch, ["   "] * 5)
        for row_i in range(5):
            rows[row_i] += (sep if idx > 0 else "") + block[row_i]
    return rows


def _render_glow_line(width: int) -> str:
    return "  " + "╌" * min(width, 60)


def print_banner(
    interface: str = "not set",
    targets: int = 0,
    scope_file: Optional[str] = None,
    animate: bool = True,
) -> None:
    """
    Display the animated wifi_down banner.
    Characters stream left-to-right at 0.003s/char; then tagline + status bar.
    Keeps backward compatibility — called with no args from cli.py.
    """
    os.system("clear" if os.name == "posix" else "cls")

    rows = _build_art_rows()
    tagline  = random.choice(_TAGLINES)
    ts       = datetime.now().strftime("%Y-%m-%d %H:%M")
    art_text = "\n".join(f"  {r}" for r in rows)
    glow     = _render_glow_line(len(rows[0]))

    if animate:
        displayed = ""
        with Live("", refresh_per_second=400, console=_con, transient=False) as live:
            # Glow line before art
            for ch in (glow + "\n"):
                displayed += ch
                live.update(Text(displayed, style=Style(color=_DIM_CYAN)))
                time.sleep(0.003)
            # Main art in teal
            art_displayed = displayed
            for ch in art_text:
                art_displayed += ch
                live.update(
                    Text(displayed, style=Style(color=_DIM_CYAN))
                    + Text(art_displayed[len(displayed):], style=Style(color=_TEAL, bold=True))
                )
                time.sleep(0.003)
            displayed = art_displayed
            # Glow line after art
            for ch in ("\n" + glow):
                displayed += ch
                live.update(Text(displayed, style=Style(color=_DIM_CYAN)))
                time.sleep(0.003)
    else:
        _con.print(glow, style=_DIM_CYAN)
        _con.print(art_text, style=Style(color=_TEAL, bold=True))
        _con.print(glow, style=_DIM_CYAN)

    _con.print()
    _con.print("  [dim]made by Ami[/dim]")
    _con.print(f"  [dim cyan italic]{tagline}[/dim cyan italic]")
    _con.print()

    # Status bar
    scope_color = "cyan" if scope_file else "yellow"
    scope_label = scope_file or "none"
    tgt_color   = "green" if targets > 0 else "dim"
    _con.print(
        f"  [dim][[/dim][cyan]interface: {interface}[/cyan][dim]][/dim]  "
        f"[dim][[/dim][{tgt_color}]targets: {targets}[/{tgt_color}][dim]][/dim]  "
        f"[dim][[/dim][white]session: {ts}[/white][dim]][/dim]  "
        f"[dim][[/dim][{scope_color}]scope: {scope_label}[/{scope_color}][dim]][/dim]"
    )
    _con.print()


# ─── Menu and section helpers ─────────────────────────────────────────────────

MENU_TEMPLATE = f"""
{C.CYAN}{'─'*60}{C.RESET}
  {C.BOLD}{C.WHITE}MAIN MENU{C.RESET}
{C.CYAN}{'─'*60}{C.RESET}
  {C.BOLD}{C.DIM}── WPA2 / WPA3 ───────────────────────────────────────{C.RESET}
  {C.GREEN}[1]{C.RESET} Select / Set Interface (monitor mode)
  {C.GREEN}[2]{C.RESET} Scan Nearby Networks
  {C.GREEN}[3]{C.RESET} Capture Handshake  (passive / deauth / PMKID)
  {C.GREEN}[4]{C.RESET} Generate Wordlist
  {C.GREEN}[5]{C.RESET} Crack  (aircrack / cowpatty / hashcat dict+rules)
  {C.GREEN}[6]{C.RESET} {C.BOLD}Full Auto Mode{C.RESET} WPA2/WPA3  (1→2→3→4→5)
  {C.BOLD}{C.DIM}── WPS ───────────────────────────────────────────────{C.RESET}
  {C.CYAN}[w]{C.RESET} {C.BOLD}WPS Attack{C.RESET}  (Pixie-Dust / PIN spray / brute-force)
  {C.BOLD}{C.DIM}── WEP ───────────────────────────────────────────────{C.RESET}
  {C.MAGENTA}[7]{C.RESET} {C.BOLD}WEP Crack{C.RESET}  (ARP replay / fragmentation / ChopChop)
  {C.BOLD}{C.DIM}── Intelligence ──────────────────────────────────────{C.RESET}
  {C.CYAN}[g]{C.RESET} {C.BOLD}Ghost Signal Tracker{C.RESET}  (CVE / firmware intelligence)
  {C.CYAN}[N]{C.RESET} {C.BOLD}Neural Pathfinder{C.RESET}  (AI-powered attack brief)
  {C.CYAN}[h]{C.RESET} {C.BOLD}Beacon Historian{C.RESET}  (passive AP behavioral profile)
  {C.BOLD}{C.DIM}── Advanced Attacks ──────────────────────────────────{C.RESET}
  {C.YELLOW}[p]{C.RESET} {C.BOLD}Phantom AP{C.RESET}  (Signal Shadowing / captive portal)
  {C.YELLOW}[t]{C.RESET} {C.BOLD}Temporal Attack{C.RESET}  (time-based PSK prediction)
  {C.YELLOW}[I]{C.RESET} {C.BOLD}Signal Intercept{C.RESET}  (post-Phantom protocol fingerprint)
  {C.BOLD}{C.DIM}── Standalone Attacks ────────────────────────────────{C.RESET}
  {C.RED}[9]{C.RESET} {C.BOLD}Deauth Attack{C.RESET}  (spoof AP MAC → disconnect clients)
  {C.BOLD}{C.DIM}── Misc ──────────────────────────────────────────────{C.RESET}
  {C.CYAN}[8]{C.RESET} Show Session State
  {C.CYAN}[r]{C.RESET} Generate Report  [--pdf for PDF output]
  {C.RED}[0]{C.RESET} Exit
{C.CYAN}{'─'*60}{C.RESET}"""


def print_menu(state: dict) -> None:
    print(MENU_TEMPLATE)
    iface  = state.get("monitor_interface") or f"{C.DIM}not set{C.RESET}"
    target = state["target"]["ssid"] if state.get("target") else f"{C.DIM}not set{C.RESET}"
    cap    = state.get("capture_file") or f"{C.DIM}none{C.RESET}"
    wl     = state.get("wordlist_file") or f"{C.DIM}none{C.RESET}"
    print(
        f"  {C.DIM}iface={C.RESET}{C.CYAN}{iface}{C.RESET}  "
        f"{C.DIM}target={C.RESET}{C.CYAN}{target}{C.RESET}  "
        f"{C.DIM}cap={C.RESET}{C.CYAN}{os.path.basename(str(cap))}{C.RESET}  "
        f"{C.DIM}wordlist={C.RESET}{C.CYAN}{os.path.basename(str(wl))}{C.RESET}"
    )


def print_section(title: str) -> None:
    w = shutil.get_terminal_size((80, 24)).columns
    print(f"\n{C.BOLD}{C.CYAN}{'═'*w}")
    print(f"  {title}")
    print(f"{'═'*w}{C.RESET}")


def info(msg: str)    -> None: print(f"  {C.CYAN}[*]{C.RESET} {msg}")
def success(msg: str) -> None: print(f"  {C.GREEN}[+]{C.RESET} {msg}")
def warn(msg: str)    -> None: print(f"  {C.YELLOW}[!]{C.RESET} {msg}")
def error(msg: str)   -> None: print(f"  {C.RED}[-]{C.RESET} {msg}")
def found(msg: str)   -> None: print(f"\n  {C.BOLD}{C.GREEN}[★]{C.RESET} {C.BOLD}{msg}{C.RESET}\n")

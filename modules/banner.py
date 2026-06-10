#!/usr/bin/env python3
"""wifi_down — Terminal Identity Module"""
from __future__ import annotations

import os
import random
import shutil
import subprocess
import sys
import textwrap
import time
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.style import Style
from rich.text import Text

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


def _make_console() -> Console:
    import io
    if hasattr(sys.stdout, "buffer"):
        utf8_out = io.TextIOWrapper(
            sys.stdout.buffer, encoding="utf-8", errors="replace",
            newline="", line_buffering=True,
        )
        return Console(file=utf8_out, force_terminal=True, legacy_windows=False)
    return Console(force_terminal=True, legacy_windows=False)


console = _make_console()

# ─── ASCII art constant ───────────────────────────────────────────────────────

WIFI_DOWN_ART = """\
██╗    ██╗██╗███████╗██╗    ██████╗  ██████╗ ██╗    ██╗███╗  ██╗
██║    ██║██║██╔════╝██║    ██╔══██╗██╔═══██╗██║    ██║████╗ ██║
██║ █╗ ██║██║█████╗  ██║    ██║  ██║██║   ██║██║ █╗ ██║██╔██╗██║
██║███╗██║██║██╔══╝  ██║    ██║  ██║██║   ██║██║███╗██║██║╚████║
╚███╔███╔╝██║██║     ██║    ██████╔╝╚██████╔╝╚███╔███╔╝██║ ╚███║
 ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝    ╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚══╝"""

# ─── Quotes ───────────────────────────────────────────────────────────────────

QUOTES = [
    ("Kevin Mitnick",
     "The human side of computer security is easily exploited "
     "and we still don't take it seriously enough."),
    ("Bruce Schneier",
     "Security is not a product, but a process."),
    ("Bruce Schneier",
     "Amateurs hack systems, professionals hack people."),
    ("Dan Kaminsky",
     "We keep saying the internet isn't a safe place. "
     "But we built it as if it was."),
    ("Mikko Hyppönen",
     "If it's smart, it's vulnerable."),
    ("Edward Snowden",
     "Arguing that you don't care about privacy because you have "
     "nothing to hide is no different from saying you don't care "
     "about free speech because you have nothing to say."),
    ("Anonymous",
     "We are legion. We do not forgive. "
     "We do not forget. Expect us."),
    ("Richard Stallman",
     "Free software is a matter of liberty, not price."),
    ("Tsutomu Shimomura",
     "The key to security is knowing what you are protecting "
     "and who you are protecting it from."),
    ("Gene Spafford",
     "The only truly secure system is one that is powered off, "
     "cast in a block of concrete and sealed in a lead-lined room "
     "with armed guards."),
    ("Kevin Poulsen",
     "Hackers are breaking the systems for profit. "
     "Before, it was about intellectual curiosity and "
     "there was an understanding that you don't do damage."),
    ("Parisa Tabriz",
     "I think of hacking as an intellectual challenge — "
     "a puzzle waiting to be solved."),
]

_CORNER_CHARS = frozenset("╗╔╝╚╣╠╦╩╬")

# ─── Styles ───────────────────────────────────────────────────────────────────

_S_LEFT   = Style(color="color(51)")
_S_MID    = Style(color="color(87)", bold=True)
_S_RIGHT  = Style(color="color(50)")
_S_CORNER = Style(color="color(45)", bold=True)

_RESET = "\033[0m"

# ─── Core primitives ──────────────────────────────────────────────────────────

def _ansi(style_str: str) -> str:
    """Convert a space-separated Rich-style string to an ANSI escape sequence.

    Supported tokens: bold, dim, italic, color(N)
    Example: _ansi("color(213) bold") → "\\033[1;38;5;213m"
    """
    codes: list[str] = []
    for token in style_str.split():
        if token == "bold":
            codes.append("1")
        elif token == "dim":
            codes.append("2")
        elif token == "italic":
            codes.append("3")
        elif token.startswith("color(") and token.endswith(")"):
            n = token[6:-1]
            codes.append(f"38;5;{n}")
    return f"\033[{';'.join(codes)}m" if codes else ""


def typewrite(
    text: str,
    style: str = "",
    delay: float = 0.018,
    newline: bool = True,
) -> None:
    """Print text character-by-character with optional ANSI style and delay."""
    esc = _ansi(style) if style else ""
    for char in text:
        sys.stdout.write(f"{esc}{char}{_RESET}" if esc else char)
        sys.stdout.flush()
        time.sleep(delay)
    if newline:
        sys.stdout.write("\n")
        sys.stdout.flush()


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _get_interface() -> str:
    try:
        out = subprocess.check_output(
            ["iw", "dev"], stderr=subprocess.DEVNULL, timeout=2
        ).decode()
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Interface"):
                return line.split()[-1]
    except Exception:
        pass
    return "not set"


def _get_scope() -> str:
    for candidate in ("scope.yaml", "scope.yml", "config/scope.yaml"):
        if os.path.exists(candidate):
            return "loaded"
    return "none"


# ─── Banner sections ──────────────────────────────────────────────────────────

def _color_row(row: str) -> Text:
    """Apply tri-zone color gradient to a single art row."""
    n  = len(row)
    t1 = row[:n // 3]
    t2 = row[n // 3 : 2 * n // 3]
    t3 = row[2 * n // 3:]

    def _section(s: str, base: Style) -> list:
        return [(ch, _S_CORNER if ch in _CORNER_CHARS else base) for ch in s]

    return Text.assemble(
        *_section(t1, _S_LEFT),
        *_section(t2, _S_MID),
        *_section(t3, _S_RIGHT),
    )


def _print_art() -> None:
    """Scan-line reveal — prints each art row with a 0.04 s delay."""
    for row in WIFI_DOWN_ART.splitlines():
        if not row.strip():
            continue
        console.print(_color_row(row))
        time.sleep(0.04)


def _print_made_by() -> None:
    """Centered 'made by अमी' printed char-by-char at 0.04 s/char."""
    parts_normal = [
        ("── made by ",  "color(240) italic"),
        ("अमी",          "color(213) bold"),
        (" ──",          "color(240) italic"),
    ]
    parts_fallback = [
        ("── made by ",  "color(240) italic"),
        ("Ami",          "color(213) bold"),
        (" ──",          "color(240) italic"),
    ]

    try:
        full = "".join(p[0] for p in parts_normal)
        full.encode("utf-8")
        parts = parts_normal
    except (UnicodeEncodeError, UnicodeDecodeError):
        full  = "".join(p[0] for p in parts_fallback)
        parts = parts_fallback

    width   = console.width
    padding = max(0, (width - len(full)) // 2)
    sys.stdout.write(" " * padding)
    sys.stdout.flush()

    for text, style_str in parts:
        esc = _ansi(style_str)
        for char in text:
            sys.stdout.write(f"{esc}{char}{_RESET}")
            sys.stdout.flush()
            time.sleep(0.04)

    sys.stdout.write("\n")
    sys.stdout.flush()


def _print_quote(author: str, quote: str) -> None:
    """Single quote with separator/❝❞ formatting, typewriter output."""
    sep = "  ─────────────────────────────────────────────────"
    typewrite(sep, style="color(238) dim", delay=0.005)
    console.print()

    wrapped_lines = textwrap.fill(quote, width=65).splitlines()
    for i, ln in enumerate(wrapped_lines):
        prefix = "   ❝  " if i == 0 else "      "
        suffix = "  ❞" if i == len(wrapped_lines) - 1 else ""
        typewrite(prefix + ln + suffix, style="color(252) italic", delay=0.022)

    console.print()
    typewrite(f"        — {author}", style="color(87) bold", delay=0.035)
    console.print()
    typewrite(sep, style="color(238) dim", delay=0.005)


def _print_disclaimer() -> None:
    """Plain typewriter legal notice — no Rich Panel."""
    sep = "  ─────────────────────────────────────────────────"
    console.print()
    typewrite(sep, style="color(238) dim", delay=0.005)
    console.print()
    typewrite("  ⚠  LEGAL NOTICE", style="color(196) bold", delay=0.03)
    console.print()
    typewrite("  Use only on networks you own or have written",     style="color(252)", delay=0.015)
    typewrite("  permission to test. Unauthorized access is a",     style="color(252)", delay=0.015)
    typewrite("  criminal offence under CFAA, IT Act 2000 and",     style="color(252)", delay=0.015)
    typewrite("  similar laws worldwide. No liability accepted.",    style="color(252)", delay=0.015)
    console.print()
    typewrite(sep, style="color(238) dim", delay=0.005)


def _print_status(iface: str, scope: str, ts: str) -> None:
    """Segment-by-segment ANSI typewriter status line."""
    console.print()
    segments = [
        ("  ◈ ",        "color(51)"),
        ("interface: ",  "color(240) dim"),
        (iface,          "color(87) bold"),
        ("   ◈ ",        "color(51)"),
        ("scope: ",      "color(240) dim"),
        (scope,          "color(87) bold"),
        ("   ◈ ",        "color(51)"),
        (ts,             "color(87) bold"),
    ]
    for text, style_str in segments:
        esc = _ansi(style_str)
        for char in text:
            sys.stdout.write(f"{esc}{char}{_RESET}")
            sys.stdout.flush()
            time.sleep(0.012)
    sys.stdout.write("\n")
    sys.stdout.flush()


def _print_enter_prompt() -> None:
    """Typewriter prompt → 3-color pulse (51→87→123→87→51) → wait → clear."""
    prompt = "           [ Press ENTER to launch wifi_down ]"
    console.print()
    typewrite(prompt, style="color(51) bold", delay=0.045)

    pulse_colors = ["color(51)", "color(87)", "color(123)", "color(87)", "color(51)"]
    for cycle in range(3):
        for c in pulse_colors:
            esc = _ansi(c + " bold")
            sys.stdout.write(f"\r{esc}{prompt}{_RESET}   ")
            sys.stdout.flush()
            time.sleep(0.15)

    sys.stdout.write("\r" + " " * (len(prompt) + 3) + "\r")
    sys.stdout.flush()

    try:
        input("")
    except (EOFError, KeyboardInterrupt):
        pass

    console.clear()


# ─── Public API ───────────────────────────────────────────────────────────────

def print_banner() -> None:
    """Full launch banner — called once at startup.

    Flow:
        1. clear screen
        2. scan-line art reveal (_print_art)
        3. right-aligned 'made by अ म ी' (_print_made_by)
        4. one random hacker quote (_print_quote)
        5. plain typewriter disclaimer (_print_disclaimer)
        6. segment typewriter status bar (_print_status)
        7. typewriter + pulsing Enter prompt (_print_enter_prompt)
           → console.clear() after Enter
    """
    os.system("clear" if os.name == "posix" else "cls")

    iface = _get_interface()
    scope = _get_scope()
    ts    = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")

    _print_art()
    _print_made_by()

    author, quote = random.choice(QUOTES)
    console.print()
    _print_quote(author, quote)
    _print_disclaimer()
    _print_status(iface, scope, ts)
    _print_enter_prompt()


def print_compact_header(interface: Optional[str] = None) -> None:
    """One-line header — called at top of every menu loop iteration.

    Shows:  wifi_down  ◈  YYYY-MM-DD  HH:MM:SS  ◈  <iface>
    Does NOT clear the screen.
    """
    ts    = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    iface = interface or _get_interface()
    t = Text.assemble(
        ("  wifi_down",  Style(color="color(51)", bold=True)),
        ("  ◈  ",        Style(color="color(238)")),
        (ts,             Style(color="color(240)", dim=True)),
        ("  ◈  ",        Style(color="color(238)")),
        (iface,          Style(color="color(87)")),
    )
    console.print(t)
    console.print()


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

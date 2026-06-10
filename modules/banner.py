#!/usr/bin/env python3
"""
wifi_down — Terminal Identity Module
God-level animated banner with column-sweep reveal and noise border.
"""
from __future__ import annotations

import os
import random
import shutil
import subprocess
import time
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.live import Live
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
    import sys, io
    if hasattr(sys.stdout, "buffer"):
        utf8_out = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", newline="", line_buffering=True)
        return Console(file=utf8_out, force_terminal=True, legacy_windows=False)
    return Console(force_terminal=True, legacy_windows=False)

console = _make_console()

# ─── ASCII art constant ───────────────────────────────────────────────────────

WIFI_DOWN_ART = [
    "██╗    ██╗██╗███████╗██╗    ██████╗  ██████╗ ██╗    ██╗███╗  ██╗",
    "██║    ██║██║██╔════╝██║    ██╔══██╗██╔═══██╗██║    ██║████╗ ██║",
    "██║ █╗ ██║██║█████╗  ██║    ██║  ██║██║   ██║██║ █╗ ██║██╔██╗██║",
    "██║███╗██║██║██╔══╝  ██║    ██║  ██║██║   ██║██║███╗██║██║╚████║",
    "╚███╔███╔╝██║██║     ██║    ██████╔╝╚██████╔╝╚███╔███╔╝██║ ╚███║",
    " ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝    ╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚══╝",
]

_TAGLINES = [
    "silence is not security.",
    "every network has a story.",
    "the quietest signal is the loudest warning.",
    "authorized eyes only.",
    "packets don't lie.",
    "trust nothing. verify everything.",
    "you cannot defend what you cannot see.",
    "signal found. identity unknown.",
]

_S_OUTER   = Style(color="color(23)", dim=True)
_S_NOISE_A = Style(color="color(23)", dim=True)
_S_NOISE_B = Style(color="color(30)", dim=True)
_S_LEFT    = Style(color="color(51)")
_S_MID     = Style(color="color(87)", bold=True)
_S_RIGHT   = Style(color="color(50)")
_S_CORNER  = Style(color="color(45)", bold=True)
_S_BRIDGE  = Style(color="color(51)", bold=True)
_S_CREDIT_PRE = Style(color="color(240)", italic=True)
_S_CREDIT_NAME = Style(color="color(213)", bold=True)
_S_DIAMOND = Style(color="color(51)")
_S_SEP_DASH = Style(color="color(23)", dim=True)
_S_TAG_TEXT = Style(color="color(240)", italic=True)
_S_TAG_TRI  = Style(color="color(51)")
_S_STATUS_SYM = Style(color="color(51)")
_S_STATUS_KEY = Style(color="color(240)", dim=True)
_S_STATUS_VAL = Style(color="color(87)", bold=True)

_CORNER_CHARS = frozenset("╗╔╝╚╣╠╦╩╬")


def _noise_char(col: int) -> Style:
    return _S_NOISE_A if col % 2 == 0 else _S_NOISE_B


def _color_art_row(row: str) -> Text:
    """Split row into three zones and apply gradient + corner accent."""
    n = len(row)
    third = n // 3
    left   = row[:third]
    middle = row[third:2*third]
    right  = row[2*third:]

    def _assemble_section(s: str, base: Style) -> list[tuple[str, Style]]:
        parts = []
        for ch in s:
            if ch in _CORNER_CHARS:
                parts.append((ch, _S_CORNER))
            else:
                parts.append((ch, base))
        return parts

    pieces = (
        _assemble_section(left,   _S_LEFT) +
        _assemble_section(middle, _S_MID)  +
        _assemble_section(right,  _S_RIGHT)
    )
    return Text.assemble(*pieces)


def _get_interface() -> str:
    try:
        out = subprocess.check_output(["iw", "dev"], stderr=subprocess.DEVNULL, timeout=2).decode()
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


def _credit_text(fallback: bool = False) -> Text:
    name = "Ami" if fallback else "अमी"
    return Text.assemble(
        ("made by ", _S_CREDIT_PRE),
        (name,       _S_CREDIT_NAME),
    )


def _build_static_banner(width: int) -> list[Text]:
    """Build full banner as list of Text lines (no animation)."""
    inner_w = width - 2  # inside │ │
    art_w = len(WIFI_DOWN_ART[0])
    pad_total = inner_w - art_w - 4  # 4 = two ░ each side
    pad_l = pad_total // 2
    pad_r = pad_total - pad_l

    noise_w = inner_w  # ░ row spans full inner width

    lines: list[Text] = []

    # Top border
    top = Text()
    top.append("┌" + "─" * inner_w + "┐", style=_S_OUTER)
    lines.append(top)

    # Empty inner line
    def _empty_inner() -> Text:
        t = Text()
        t.append("│" + " " * inner_w + "│", style=_S_OUTER)
        return t

    lines.append(_empty_inner())
    lines.append(_empty_inner())

    # Top noise row
    def _noise_row() -> Text:
        t = Text()
        t.append("│", style=_S_OUTER)
        t.append(" ", style=_S_OUTER)
        for i in range(noise_w - 2):
            t.append("░", style=_noise_char(i))
        t.append(" ", style=_S_OUTER)
        t.append("│", style=_S_OUTER)
        return t

    lines.append(_noise_row())

    # Empty noise-bordered lines (2 blank lines inside noise)
    def _noise_border_empty() -> Text:
        t = Text()
        t.append("│", style=_S_OUTER)
        t.append(" ", style=_S_OUTER)
        t.append("░", style=_S_NOISE_A)
        t.append(" " * (inner_w - 4), style=_S_OUTER)
        t.append("░", style=_S_NOISE_B)
        t.append(" ", style=_S_OUTER)
        t.append("│", style=_S_OUTER)
        return t

    lines.append(_noise_border_empty())

    # ASCII art rows
    for row in WIFI_DOWN_ART:
        t = Text()
        t.append("│", style=_S_OUTER)
        t.append(" ", style=_S_OUTER)
        t.append("░", style=_S_NOISE_A)
        t.append(" " * (pad_l + 1), style=_S_OUTER)
        t.append_text(_color_art_row(row))
        t.append(" " * (pad_r + 1), style=_S_OUTER)
        t.append("░", style=_S_NOISE_B)
        t.append(" ", style=_S_OUTER)
        t.append("│", style=_S_OUTER)
        lines.append(t)

    # Credit line (right-aligned inside noise border)
    try:
        credit = _credit_text(fallback=False)
    except Exception:
        credit = _credit_text(fallback=True)

    credit_len = len("made by ") + len("अमी")
    credit_pad = inner_w - 4 - credit_len - 2  # 4=noise borders, 2=spaces around

    credit_line = Text()
    credit_line.append("│", style=_S_OUTER)
    credit_line.append(" ", style=_S_OUTER)
    credit_line.append("░", style=_S_NOISE_A)
    credit_line.append(" " * max(credit_pad, 1), style=_S_OUTER)
    credit_line.append_text(credit)
    credit_line.append("  ", style=_S_OUTER)
    credit_line.append("░", style=_S_NOISE_B)
    credit_line.append(" ", style=_S_OUTER)
    credit_line.append("│", style=_S_OUTER)
    lines.append(credit_line)

    # Bottom noise row
    lines.append(_noise_row())

    # Two empty lines
    lines.append(_empty_inner())
    lines.append(_empty_inner())

    # Bottom border
    bot = Text()
    bot.append("└" + "─" * inner_w + "┘", style=_S_OUTER)
    lines.append(bot)

    return lines


def _build_separator(width: int) -> Text:
    sym = "◈"
    dash_total = width - len(sym) - 2
    left_d  = dash_total // 2
    right_d = dash_total - left_d
    t = Text()
    t.append("─" * left_d, style=_S_SEP_DASH)
    t.append(f" {sym} ", style=_S_DIAMOND)
    t.append("─" * right_d, style=_S_SEP_DASH)
    return t


def _build_tagline(tagline: str) -> Text:
    t = Text()
    t.append("◤  ", style=_S_TAG_TRI)
    t.append(tagline, style=_S_TAG_TEXT)
    t.append("  ◥", style=_S_TAG_TRI)
    return t


def _build_status(iface: str, scope: str, ts: str) -> Text:
    t = Text()
    t.append("◈ ", style=_S_STATUS_SYM)
    t.append("interface: ", style=_S_STATUS_KEY)
    t.append(iface, style=_S_STATUS_VAL)
    t.append("   ◈ ", style=_S_STATUS_SYM)
    t.append("scope: ", style=_S_STATUS_KEY)
    t.append(scope, style=_S_STATUS_VAL)
    t.append("   ◈ ", style=_S_STATUS_SYM)
    t.append("session: ", style=_S_STATUS_KEY)
    t.append(ts, style=_S_STATUS_VAL)
    t.append("   ◈", style=_S_STATUS_SYM)
    return t


def _render_frame(lines: list[Text]) -> Text:
    result = Text()
    for i, line in enumerate(lines):
        if i > 0:
            result.append("\n")
        result.append_text(line)
    return result


def _compact_banner() -> None:
    """Fallback for narrow terminals."""
    try:
        name = "अमी"
        name.encode(console.encoding or "utf-8")
    except (UnicodeEncodeError, LookupError):
        name = "Ami"

    console.print("┌─────────────────────────┐", style=_S_OUTER)
    t = Text()
    t.append("│  ", style=_S_OUTER)
    t.append("wifi_down", style=_S_MID)
    t.append("              │", style=_S_OUTER)
    console.print(t)
    c2 = Text()
    c2.append("│  ", style=_S_OUTER)
    c2.append("made by ", style=_S_CREDIT_PRE)
    c2.append(name, style=_S_CREDIT_NAME)
    c2.append("            │", style=_S_OUTER)
    console.print(c2)
    console.print("└─────────────────────────┘", style=_S_OUTER)


def print_banner(
    interface: Optional[str] = None,
    targets: int = 0,
    scope_file: Optional[str] = None,
    animate: bool = True,
) -> None:
    os.system("clear" if os.name == "posix" else "cls")

    width = min(console.width, 100)

    if width < 90:
        _compact_banner()
        return

    iface = interface or _get_interface()
    scope = _get_scope()
    ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tagline = random.choice(_TAGLINES)

    inner_w = width - 2
    art_w   = len(WIFI_DOWN_ART[0])
    # inner_w = 1(sp) + 1(░) + (pad_l+1) + art_w + (pad_r+1) + 1(░) + 1(sp)  → offset is 6
    pad_total = inner_w - art_w - 6
    pad_l = max(pad_total // 2, 0)
    pad_r = max(pad_total - pad_l, 0)
    noise_w = inner_w

    # ── helpers ──────────────────────────────────────────────────────────────

    def _empty_inner() -> Text:
        t = Text()
        t.append("│" + " " * inner_w + "│", style=_S_OUTER)
        return t

    def _noise_row_text(flicker: bool = False) -> Text:
        t = Text()
        t.append("│", style=_S_OUTER)
        t.append(" ", style=_S_OUTER)
        for i in range(noise_w - 2):
            ch = "▒" if (flicker and random.random() < 0.4) else "░"
            t.append(ch, style=_noise_char(i))
        t.append(" ", style=_S_OUTER)
        t.append("│", style=_S_OUTER)
        return t

    def _noise_border_empty() -> Text:
        t = Text()
        t.append("│", style=_S_OUTER)
        t.append(" ", style=_S_OUTER)
        t.append("░", style=_S_NOISE_A)
        t.append(" " * (inner_w - 4), style=_S_OUTER)
        t.append("░", style=_S_NOISE_B)
        t.append(" ", style=_S_OUTER)
        t.append("│", style=_S_OUTER)
        return t

    def _art_row_text(row: str) -> Text:
        t = Text()
        t.append("│", style=_S_OUTER)
        t.append(" ", style=_S_OUTER)
        t.append("░", style=_S_NOISE_A)
        t.append(" " * (pad_l + 1), style=_S_OUTER)
        t.append_text(_color_art_row(row))
        t.append(" " * (pad_r + 1), style=_S_OUTER)
        t.append("░", style=_S_NOISE_B)
        t.append(" ", style=_S_OUTER)
        t.append("│", style=_S_OUTER)
        return t

    def _art_row_partial(row: str, col_limit: int) -> Text:
        """Render art row up to col_limit characters wide (column sweep)."""
        partial = row[:col_limit]
        # pad to full width with spaces to keep layout stable
        padding = " " * (len(row) - len(partial))
        t = Text()
        t.append("│", style=_S_OUTER)
        t.append(" ", style=_S_OUTER)
        t.append("░", style=_S_NOISE_A)
        t.append(" " * (pad_l + 1), style=_S_OUTER)
        n = len(partial)
        third = len(row) // 3
        left_p   = partial[:third]
        mid_p    = partial[third:2*third]
        right_p  = partial[2*third:]
        def _section(s: str, base: Style) -> list[tuple[str, Style]]:
            return [(ch, _S_CORNER if ch in _CORNER_CHARS else base) for ch in s]
        pieces = _section(left_p, _S_LEFT) + _section(mid_p, _S_MID) + _section(right_p, _S_RIGHT)
        if pieces:
            t.append_text(Text.assemble(*pieces))
        t.append(padding, style=_S_OUTER)
        t.append(" " * (pad_r + 1), style=_S_OUTER)
        t.append("░", style=_S_NOISE_B)
        t.append(" ", style=_S_OUTER)
        t.append("│", style=_S_OUTER)
        return t

    try:
        _credit_text(fallback=False)
        use_fallback = False
    except Exception:
        use_fallback = True

    def _credit_line_text() -> Text:
        credit = _credit_text(fallback=use_fallback)
        credit_rendered = "made by " + ("Ami" if use_fallback else "अमी")
        credit_len = len(credit_rendered)
        credit_pad = inner_w - 4 - credit_len - 2
        t = Text()
        t.append("│", style=_S_OUTER)
        t.append(" ", style=_S_OUTER)
        t.append("░", style=_S_NOISE_A)
        t.append(" " * max(credit_pad, 1), style=_S_OUTER)
        t.append_text(credit)
        t.append("  ", style=_S_OUTER)
        t.append("░", style=_S_NOISE_B)
        t.append(" ", style=_S_OUTER)
        t.append("│", style=_S_OUTER)
        return t

    # ── PHASE 1: draw outer border box ───────────────────────────────────────
    # Build line index layout:
    # 0: top border
    # 1,2: empty inner
    # 3: top noise row
    # 4: empty noise border
    # 5-10: art rows (6 rows)
    # 11: credit line
    # 12: bottom noise row
    # 13,14: empty inner
    # 15: bottom border

    TOTAL_LINES = 16
    ART_START   = 5
    ART_END     = 11  # exclusive
    CREDIT_LINE = 11
    BOT_NOISE   = 12
    BOT_INNER1  = 13
    BOT_INNER2  = 14
    BOT_BORDER  = 15

    # Initialize all lines as empty Text
    frame: list[Text] = [Text(" ") for _ in range(TOTAL_LINES)]

    def _push(live: Live) -> None:
        live.update(_render_frame(frame))

    if not animate:
        # Static render
        frame[0] = Text("┌" + "─" * inner_w + "┐", style=_S_OUTER)
        frame[1] = _empty_inner()
        frame[2] = _empty_inner()
        frame[3] = _noise_row_text()
        frame[4] = _noise_border_empty()
        for i, row in enumerate(WIFI_DOWN_ART):
            frame[ART_START + i] = _art_row_text(row)
        frame[CREDIT_LINE] = _credit_line_text()
        frame[BOT_NOISE]   = _noise_row_text()
        frame[BOT_INNER1]  = _empty_inner()
        frame[BOT_INNER2]  = _empty_inner()
        frame[BOT_BORDER]  = Text("└" + "─" * inner_w + "┘", style=_S_OUTER)
        for line in frame:
            console.print(line)
    else:
        with Live(console=console, refresh_per_second=120, transient=False) as live:

            # PHASE 1 — outer border
            top_chars = "┌" + "─" * inner_w + "┐"
            top_built = ""
            for ch in top_chars:
                top_built += ch
                frame[0] = Text(top_built, style=_S_OUTER)
                _push(live)
                time.sleep(0.003)

            # Side bars top-to-bottom (lines 1–14)
            for row_idx in range(1, BOT_BORDER):
                frame[row_idx] = Text("│" + " " * inner_w + "│", style=_S_OUTER)
                _push(live)
                time.sleep(0.003)

            # Bottom border left-to-right
            bot_chars = "└" + "─" * inner_w + "┘"
            bot_built = ""
            for ch in bot_chars:
                bot_built += ch
                frame[BOT_BORDER] = Text(bot_built, style=_S_OUTER)
                _push(live)
                time.sleep(0.003)

            # PHASE 2 — noise border fill with flicker
            # Top noise row
            noise_built_top = ["░"] * (noise_w - 2)
            for i in range(noise_w - 2):
                noise_built_top[i] = "▒"
                t = Text()
                t.append("│", style=_S_OUTER)
                t.append(" ", style=_S_OUTER)
                for j, c in enumerate(noise_built_top):
                    t.append(c, style=_noise_char(j))
                t.append(" ", style=_S_OUTER)
                t.append("│", style=_S_OUTER)
                frame[3] = t
                _push(live)
                time.sleep(0.001)
                noise_built_top[i] = "░"
                t2 = Text()
                t2.append("│", style=_S_OUTER)
                t2.append(" ", style=_S_OUTER)
                for j, c in enumerate(noise_built_top):
                    t2.append(c, style=_noise_char(j))
                t2.append(" ", style=_S_OUTER)
                t2.append("│", style=_S_OUTER)
                frame[3] = t2
                _push(live)
                time.sleep(0.002)

            frame[4] = _noise_border_empty()
            _push(live)

            # Art row noise borders (left ░ only for now)
            for i in range(6):
                frame[ART_START + i] = _noise_border_empty()
            _push(live)

            # Bottom noise row flicker
            noise_built_bot = ["░"] * (noise_w - 2)
            for i in range(noise_w - 2):
                noise_built_bot[i] = "▒"
                t = Text()
                t.append("│", style=_S_OUTER)
                t.append(" ", style=_S_OUTER)
                for j, c in enumerate(noise_built_bot):
                    t.append(c, style=_noise_char(j))
                t.append(" ", style=_S_OUTER)
                t.append("│", style=_S_OUTER)
                frame[BOT_NOISE] = t
                _push(live)
                time.sleep(0.001)
                noise_built_bot[i] = "░"
                t2 = Text()
                t2.append("│", style=_S_OUTER)
                t2.append(" ", style=_S_OUTER)
                for j, c in enumerate(noise_built_bot):
                    t2.append(c, style=_noise_char(j))
                t2.append(" ", style=_S_OUTER)
                t2.append("│", style=_S_OUTER)
                frame[BOT_NOISE] = t2
                _push(live)
                time.sleep(0.002)

            # PHASE 3 — column sweep across all 6 art rows simultaneously
            max_cols = len(WIFI_DOWN_ART[0])
            for col in range(0, max_cols + 1):
                for i, row in enumerate(WIFI_DOWN_ART):
                    frame[ART_START + i] = _art_row_partial(row, col)
                _push(live)
                time.sleep(0.008)

            # PHASE 4 — credit line typing right-to-left
            frame[CREDIT_LINE] = _credit_line_text()
            _push(live)
            time.sleep(0.04)

            # PHASE 5 — snap in separator, tagline, status
            # (these print after Live exits)

        # PHASE 5 & 6 — outside Live so they persist cleanly
        time.sleep(0.05)

    # Below-box elements (always printed, outside Live)
    sep    = _build_separator(width)
    tag    = _build_tagline(tagline)
    status = _build_status(iface, scope, ts)

    console.print(sep)
    console.print(tag, justify="center")
    console.print(status, justify="center")
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

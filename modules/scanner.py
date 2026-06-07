#!/usr/bin/env python3
"""
Network scanner: wraps airodump-ng, parses CSV output, displays network table,
computes SSID entropy / character-class tags, and integrates device fingerprints.
"""
from __future__ import annotations

import logging
import math
import os
import re
import subprocess
import tempfile
import time
from typing import Optional

from modules.banner import C, info, success, warn, error, print_section

logger = logging.getLogger(__name__)

DEFAULT_SCAN_TIME = 20   # seconds

# ─── SSID tag constants ───────────────────────────────────────────────────────
TAG_DEFAULT_SSID = "DEFAULT_SSID"
TAG_PERSONAL     = "PERSONAL_NAME"
TAG_RANDOM_HEX   = "RANDOM_HEX"
TAG_ISP_FORMAT   = "ISP_FORMAT"
TAG_NUMERIC      = "NUMERIC"
TAG_CUSTOM       = "CUSTOM"

# Security tier constants
SEC_WPA3_SAE   = "WPA3_SAE"        # pure WPA3 — SAE only
SEC_WPA3_TRANS = "WPA3_TRANS"      # transition mode — WPA3 + WPA2 (downgrade risk)
SEC_WPA2       = "WPA2"
SEC_WPA        = "WPA"
SEC_WEP        = "WEP"
SEC_OPEN       = "OPEN"

_DEFAULT_SSID_PATTERNS = re.compile(
    r"^(NETGEAR|TP-Link|Linksys|dlink|ASUS_|xfinity|Verizon"
    r"|Spectrum|AT&T|SKY_|BT-|Virgin|DIRECT-|FRITZ|Eir|Vodafone"
    r"|SFR_|Orange|Bbox)",
    re.IGNORECASE,
)
_ISP_PATTERNS = re.compile(
    r"^([A-Z]{2,6}[0-9]{4,}|[A-Z]+-[0-9A-F]{4,})",
    re.IGNORECASE,
)


###############################################################################
# SSID analysis
###############################################################################

def ssid_entropy(ssid: str) -> float:
    """Shannon entropy of the SSID character distribution."""
    if not ssid or ssid == "<hidden>":
        return 0.0
    freq = {}
    for c in ssid:
        freq[c] = freq.get(c, 0) + 1
    n = len(ssid)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def ssid_char_classes(ssid: str) -> dict[str, float]:
    """Return ratios of alpha / digit / symbol characters."""
    if not ssid:
        return {"alpha": 0.0, "digit": 0.0, "symbol": 0.0}
    n = len(ssid)
    alpha  = sum(1 for c in ssid if c.isalpha()) / n
    digit  = sum(1 for c in ssid if c.isdigit()) / n
    symbol = 1.0 - alpha - digit
    return {"alpha": alpha, "digit": digit, "symbol": symbol}


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein distance between two strings."""
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1,
                            prev[j] + (0 if ca == cb else 1)))
        prev = curr
    return prev[-1]


_COMMON_DEFAULT_SSIDS = [
    "linksys", "netgear", "dlink", "default", "home", "wifi", "wireless",
    "network", "internet", "router", "tp-link", "asus", "belkin",
]


def classify_ssid(ssid: str) -> str:
    """Return one of the TAG_* constants based on the SSID characteristics."""
    if not ssid or ssid == "<hidden>":
        return TAG_CUSTOM

    if _DEFAULT_SSID_PATTERNS.match(ssid):
        return TAG_DEFAULT_SSID

    clean = ssid.replace(" ", "").replace("-", "").replace("_", "")
    if clean and all(c in "0123456789abcdefABCDEF" for c in clean) and len(clean) >= 6:
        return TAG_RANDOM_HEX

    if ssid.replace(" ", "").isdigit():
        return TAG_NUMERIC

    if _ISP_PATTERNS.match(ssid):
        return TAG_ISP_FORMAT

    lower = ssid.lower()
    for default in _COMMON_DEFAULT_SSIDS:
        if _edit_distance(lower, default) <= 2:
            return TAG_DEFAULT_SSID

    return TAG_CUSTOM


def classify_security(net: dict) -> dict:
    """
    Return security_tier and wpa3_downgrade_risk for a network dict.

    Downgrade risk is flagged when an AP advertises both WPA3 and WPA2
    (transition mode).  A client that supports WPA3 may be forced by an
    attacker to associate using WPA2 instead — this is the WPA3 SAE
    downgrade attack surface.
    """
    privacy = net.get("privacy", "").upper()
    auth    = net.get("auth",    "").upper()

    has_wpa3 = "WPA3" in privacy or "SAE" in auth
    has_wpa2 = "WPA2" in privacy or "PSK" in auth

    if has_wpa3 and has_wpa2:
        tier     = SEC_WPA3_TRANS
        downgrade = True
    elif has_wpa3:
        tier     = SEC_WPA3_SAE
        downgrade = False
    elif has_wpa2:
        tier     = SEC_WPA2
        downgrade = False
    elif "WPA" in privacy:
        tier     = SEC_WPA
        downgrade = False
    elif "WEP" in privacy:
        tier     = SEC_WEP
        downgrade = False
    else:
        tier     = SEC_OPEN
        downgrade = False

    return {"security_tier": tier, "wpa3_downgrade_risk": downgrade}


def enrich_network(net: dict) -> dict:
    """Add entropy, char classes, ssid_tag, security tier, and vendor to a network dict."""
    ssid = net.get("ssid", net.get("essid", ""))
    net["ssid_entropy"] = round(ssid_entropy(ssid), 2)
    net["ssid_chars"]   = ssid_char_classes(ssid)
    net["ssid_tag"]     = classify_ssid(ssid)
    net.update(classify_security(net))

    # OUI vendor lookup (graceful fallback if network unavailable)
    try:
        from modules.oui import get_vendor
        net["vendor"] = get_vendor(net.get("bssid", ""))
    except Exception:
        net["vendor"] = None

    return net


###############################################################################
# Scanner
###############################################################################

def scan_networks(interface: str, duration: int = DEFAULT_SCAN_TIME) -> list[dict]:
    """Run airodump-ng for *duration* seconds and return a list of enriched AP dicts."""
    print_section("Network Scanner")
    info(f"Scanning on {interface} for {duration}s  (Ctrl+C to stop early)...")
    logger.info("Starting scan on %s for %ds", interface, duration)

    tmp_dir  = tempfile.mkdtemp(prefix="wifiaudit_")
    out_base = os.path.join(tmp_dir, "scan")

    proc = subprocess.Popen(
        ["airodump-ng", "--write", out_base, "--output-format", "csv",
         "--write-interval", "2", interface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        for remaining in range(duration, 0, -1):
            networks = _parse_csv(out_base + "-01.csv")
            _print_network_table(networks, f"Scanning... {remaining}s remaining")
            time.sleep(1)
    except KeyboardInterrupt:
        warn("Scan interrupted by user.")
    finally:
        proc.terminate()
        proc.wait()

    networks = _parse_csv(out_base + "-01.csv")
    for net in networks:
        enrich_network(net)

    logger.info("Scan complete: %d network(s) found", len(networks))
    _print_network_table(networks, f"Scan complete — {len(networks)} network(s) found")
    return networks


def display_networks(networks: list[dict]) -> None:
    _print_network_table(networks, f"{len(networks)} network(s)")


###############################################################################
# CSV parser
###############################################################################

def _parse_csv(filepath: str) -> list[dict]:
    if not os.path.exists(filepath):
        return []

    try:
        with open(filepath, "r", errors="replace") as f:
            content = f.read()
    except OSError:
        return []

    networks: list[dict] = []
    in_ap_section = False

    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("BSSID") and "First time" in stripped:
            in_ap_section = True
            continue
        if stripped.startswith("Station MAC"):
            break
        if not in_ap_section or not stripped:
            continue

        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 15:
            continue

        bssid   = parts[0]
        channel = parts[3].strip()
        privacy = parts[5].strip()
        cipher  = parts[6].strip()
        auth    = parts[7].strip()
        power   = parts[8].strip()
        essid   = parts[13].strip()

        if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
            continue

        try:
            ch = int(channel)
        except ValueError:
            ch = 0

        networks.append({
            "bssid":   bssid,
            "essid":   essid if essid else "<hidden>",
            "ssid":    essid if essid else "<hidden>",
            "channel": ch,
            "privacy": privacy,
            "cipher":  cipher,
            "auth":    auth,
            "power":   power,
        })

    return networks


###############################################################################
# Display
###############################################################################

_TAG_COLORS = {
    TAG_DEFAULT_SSID: C.YELLOW,
    TAG_RANDOM_HEX:   C.CYAN,
    TAG_ISP_FORMAT:   C.BLUE,
    TAG_NUMERIC:      C.MAGENTA,
    TAG_PERSONAL:     C.GREEN,
    TAG_CUSTOM:       C.RESET,
}


def _print_network_table(networks: list[dict], caption: str = "") -> None:
    os.system("clear")
    if caption:
        print(f"\n  {C.CYAN}{caption}{C.RESET}\n")

    if not networks:
        warn("No networks found yet...")
        return

    fmt = "  {:<4} {:<20} {:<19} {:<4} {:<14} {:<6} {:<5} {:<14}"
    print(
        C.BOLD
        + fmt.format("#", "SSID", "BSSID", "CH", "SECURITY", "PWR", "H", "FLAGS/VENDOR")
        + C.RESET
    )
    print(f"  {'─' * 94}")

    wep_found        = any("WEP"  in n.get("privacy", "").upper() for n in networks)
    downgrade_found  = any(n.get("wpa3_downgrade_risk") for n in networks)

    for idx, net in enumerate(networks, 1):
        enc      = net.get("privacy", "")
        enc_up   = enc.upper()
        tier     = net.get("security_tier", "")
        downgrade = net.get("wpa3_downgrade_risk", False)
        vendor   = net.get("vendor") or ""
        tag      = net.get("ssid_tag", "")
        entropy  = net.get("ssid_entropy", 0.0)

        # Encryption column
        if tier == SEC_WPA3_TRANS:
            enc_col = f"{C.YELLOW}WPA3/WPA2{C.RESET}"      # transition = yellow (risk)
        elif tier == SEC_WPA3_SAE:
            enc_col = f"{C.GREEN}WPA3-SAE{C.RESET}"
        elif "WPA2" in enc_up:
            enc_col = f"{C.YELLOW}{enc}{C.RESET}"
        elif "WPA" in enc_up:
            enc_col = f"{C.YELLOW}{enc}{C.RESET}"
        elif "WEP" in enc_up:
            enc_col = f"{C.BOLD}{C.MAGENTA}WEP ★{C.RESET}"
        elif "OPN" in enc_up or enc == "":
            enc_col = f"{C.RED}OPEN{C.RESET}"
        else:
            enc_col = enc

        # Flags / vendor column
        flags: list[str] = []
        if downgrade:
            flags.append(f"{C.RED}↓SAE{C.RESET}")          # downgrade risk marker
        tag_abbrev = {
            TAG_DEFAULT_SSID: "DEF",
            TAG_RANDOM_HEX:   "HEX",
            TAG_ISP_FORMAT:   "ISP",
            TAG_NUMERIC:      "NUM",
            TAG_PERSONAL:     "PER",
        }.get(tag, "")
        if tag_abbrev:
            tag_col = _TAG_COLORS.get(tag, C.RESET)
            flags.append(f"{tag_col}{tag_abbrev}{C.RESET}")

        meta = vendor[:8] if vendor else " ".join(flags) if flags else "   "

        ssid_disp = net["ssid"][:19]
        print(fmt.format(
            f"{C.WHITE}{idx}{C.RESET}",
            ssid_disp,
            net["bssid"],
            net["channel"],
            enc_col,
            net["power"],
            f"{entropy:.1f}",
            meta,
        ))

    if wep_found:
        print(f"\n  {C.MAGENTA}★  WEP network detected — use [7] for fast WEP cracking{C.RESET}")
    if downgrade_found:
        print(f"\n  {C.RED}↓SAE  WPA3 transition mode — clients may be downgraded to WPA2 by an attacker{C.RESET}")

    print(
        f"\n  {C.DIM}H = SSID entropy  "
        f"DEF=default  HEX=random-hex  ISP=ISP-format  NUM=numeric  "
        f"↓SAE=WPA3→WPA2 downgrade risk{C.RESET}"
    )


###############################################################################
# Network selection
###############################################################################

def select_network(networks: list[dict]) -> Optional[dict]:
    """Prompt the user to select a target AP from the scanned list."""
    if not networks:
        error("No networks to select from.")
        return None

    while True:
        try:
            raw = input(
                f"\n  {C.YELLOW}Select target [1-{len(networks)}] or 0 to cancel: {C.RESET}"
            )
            choice = int(raw.strip())
            if choice == 0:
                return None
            if 1 <= choice <= len(networks):
                target = networks[choice - 1]
                target["ssid"] = target.get("ssid") or target.get("essid", "")
                success(
                    f"Target: {target['ssid']}  [{target['bssid']}]  CH{target['channel']}"
                )
                logger.info(
                    "Target selected: %s [%s] CH%s enc=%s",
                    target["ssid"], target["bssid"],
                    target["channel"], target["privacy"],
                )
                return target
            warn(f"Enter a number between 1 and {len(networks)}.")
        except ValueError:
            warn("Please enter a valid number.")
        except KeyboardInterrupt:
            return None

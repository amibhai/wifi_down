#!/usr/bin/env python3
"""
modules/wpacrypto.py — offline WPA/WPA2 verification crypto (pure Python)
─────────────────────────────────────────────────────────────────────────
The mathematical heart of WPA. Given a candidate passphrase and the fields of a
captured PMKID or 4-way handshake, this module derives the keys and confirms —
in microseconds, with **no external tools** — whether the passphrase is correct.

What it unlocks:
  • **Instant verification** — an evil-twin captive portal (or a manual check)
    can confirm an entered password against the captured handshake immediately,
    rather than shelling out to aircrack-ng.
  • **A dependency-free cracker** — `crack_pmkid()` runs a wordlist against a
    captured PMKID with zero reliance on aircrack-ng / hashcat / cowpatty, so
    the tool still recovers keys on a stripped-down box.
  • **Capture confidence** — a recovered key can be re-verified end to end.

Everything here is standards crypto (IEEE 802.11i): PMK = PBKDF2-HMAC-SHA1,
PTK = PRF-512, MIC = HMAC-SHA1/MD5, PMKID = HMAC-SHA1(PMK, "PMK Name"|AA|SPA).
It is deterministic and unit-tested against the published IEEE PMK vectors.
"""
from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterable

BytesLike = bytes | str

# EAPOL key-descriptor MIC field: 16 bytes at offset 81 of the 802.1X frame.
MIC_OFFSET = 81
MIC_LEN = 16


def _b(x: BytesLike) -> bytes:
    """Accept bytes directly or a hex string (colons/spaces tolerated)."""
    if isinstance(x, bytes):
        return x
    s = x.strip().replace(":", "").replace(" ", "").replace("-", "")
    return bytes.fromhex(s)


# ══════════════════════════════════════════════════════════════════════════════
# Key derivation
# ══════════════════════════════════════════════════════════════════════════════

def pmk(passphrase: str, ssid: str) -> bytes:
    """Pairwise Master Key = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32 bytes)."""
    return hashlib.pbkdf2_hmac(
        "sha1", passphrase.encode("utf-8"), ssid.encode("utf-8"), 4096, 32
    )


def _prf(key: bytes, label: bytes, data: bytes, nbytes: int) -> bytes:
    """802.11i PRF-n: concatenate HMAC-SHA1(key, label || 0x00 || data || i)."""
    out = b""
    i = 0
    while len(out) < nbytes:
        out += hmac.new(key, label + b"\x00" + data + bytes([i]), hashlib.sha1).digest()
        i += 1
    return out[:nbytes]


def ptk(pmk_bytes: bytes, ap_mac: BytesLike, sta_mac: BytesLike,
        anonce: BytesLike, snonce: BytesLike) -> bytes:
    """
    Pairwise Transient Key (64 bytes) via PRF-512.

    B = min(AA,SPA) || max(AA,SPA) || min(ANonce,SNonce) || max(ANonce,SNonce).
    """
    aa, spa = _b(ap_mac), _b(sta_mac)
    an, sn = _b(anonce), _b(snonce)
    b = (min(aa, spa) + max(aa, spa) + min(an, sn) + max(an, sn))
    return _prf(pmk_bytes, b"Pairwise key expansion", b, 64)


def kck(ptk_bytes: bytes) -> bytes:
    """Key Confirmation Key = first 16 bytes of the PTK (what signs the MIC)."""
    return ptk_bytes[:16]


# ══════════════════════════════════════════════════════════════════════════════
# MIC (4-way handshake message integrity)
# ══════════════════════════════════════════════════════════════════════════════

def compute_mic(kck_bytes: bytes, eapol_frame: bytes, key_version: int = 2) -> bytes:
    """
    Compute the EAPOL-Key MIC over *eapol_frame* (which must already have its MIC
    field zeroed). key_version: 1 = WPA/TKIP (HMAC-MD5), 2 = WPA2/CCMP
    (HMAC-SHA1, truncated to 16), 3 = AES-128-CMAC (needs `cryptography`).
    """
    if key_version == 1:
        return hmac.new(kck_bytes, eapol_frame, hashlib.md5).digest()[:MIC_LEN]
    if key_version == 2:
        return hmac.new(kck_bytes, eapol_frame, hashlib.sha1).digest()[:MIC_LEN]
    if key_version == 3:
        return _aes_cmac(kck_bytes, eapol_frame)[:MIC_LEN]
    raise ValueError(f"unsupported EAPOL key_version: {key_version}")


def _aes_cmac(key: bytes, data: bytes) -> bytes:  # pragma: no cover - optional dep
    from cryptography.hazmat.primitives.ciphers import algorithms
    from cryptography.hazmat.primitives.cmac import CMAC
    c = CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()


def zero_mic(eapol_frame: bytes, offset: int = MIC_OFFSET) -> bytes:
    """Return *eapol_frame* with the 16-byte MIC field zeroed for recomputation."""
    if len(eapol_frame) < offset + MIC_LEN:
        return eapol_frame
    return eapol_frame[:offset] + b"\x00" * MIC_LEN + eapol_frame[offset + MIC_LEN:]


# EAPOL-Key frame layout (802.1X header + key descriptor):
#   [5:7]   Key Information   [17:49] Key Nonce (SNonce in M2)   [81:97] Key MIC
_SNONCE_OFFSET = 17
_SNONCE_LEN = 32
_KEYINFO_OFFSET = 5


def snonce_from_eapol(eapol_frame: bytes) -> bytes:
    """Supplicant nonce (SNonce) — 32 bytes at offset 17 of the EAPOL-Key frame."""
    return eapol_frame[_SNONCE_OFFSET:_SNONCE_OFFSET + _SNONCE_LEN]


def key_version_from_eapol(eapol_frame: bytes) -> int:
    """
    EAPOL-Key descriptor version (1 = WPA/TKIP-HMAC-MD5, 2 = WPA2/CCMP-HMAC-SHA1,
    3 = AES-128-CMAC), read from the low 3 bits of the Key Information field.
    Defaults to 2 (the overwhelmingly common case) if the frame is too short.
    """
    if len(eapol_frame) < _KEYINFO_OFFSET + 2:
        return 2
    key_info = int.from_bytes(eapol_frame[_KEYINFO_OFFSET:_KEYINFO_OFFSET + 2], "big")
    return key_info & 0x07


def verify_eapol(passphrase: str, ssid: str, ap_mac: BytesLike, sta_mac: BytesLike,
                 anonce: BytesLike, snonce: BytesLike, eapol_frame_mic_zeroed: bytes,
                 expected_mic: BytesLike, key_version: int = 2) -> bool:
    """
    True iff *passphrase* reproduces *expected_mic* for this captured 4-way
    message. ``eapol_frame_mic_zeroed`` is the EAPOL-Key frame with its MIC
    field already zeroed (see :func:`zero_mic`).
    """
    try:
        p = ptk(pmk(passphrase, ssid), ap_mac, sta_mac, anonce, snonce)
        mic = compute_mic(kck(p), eapol_frame_mic_zeroed, key_version)
        return hmac.compare_digest(mic, _b(expected_mic))
    except (ValueError, TypeError):
        return False


# ══════════════════════════════════════════════════════════════════════════════
# PMKID
# ══════════════════════════════════════════════════════════════════════════════

def compute_pmkid(pmk_bytes: bytes, ap_mac: BytesLike, sta_mac: BytesLike) -> bytes:
    """PMKID = HMAC-SHA1(PMK, "PMK Name" || AA || SPA), truncated to 16 bytes."""
    return hmac.new(
        pmk_bytes, b"PMK Name" + _b(ap_mac) + _b(sta_mac), hashlib.sha1
    ).digest()[:16]


def verify_pmkid(passphrase: str, ssid: str, ap_mac: BytesLike, sta_mac: BytesLike,
                 expected_pmkid: BytesLike) -> bool:
    """True iff *passphrase* reproduces the captured PMKID for this AP/STA/ESSID."""
    try:
        got = compute_pmkid(pmk(passphrase, ssid), ap_mac, sta_mac)
        return hmac.compare_digest(got, _b(expected_pmkid))
    except (ValueError, TypeError):
        return False


# ══════════════════════════════════════════════════════════════════════════════
# Pure-Python cracker  (no aircrack-ng / hashcat / cowpatty required)
# ══════════════════════════════════════════════════════════════════════════════

def crack_pmkid(ssid: str, ap_mac: BytesLike, sta_mac: BytesLike,
                expected_pmkid: BytesLike, wordlist: Iterable[str],
                progress: callable | None = None) -> str | None:
    """
    Run *wordlist* against a captured PMKID entirely in Python. Returns the
    passphrase on success, else ``None``. ``progress(n)`` is called every 1000
    candidates if supplied. WPA rejects PSKs outside 8–63 chars, so those are
    skipped for free.
    """
    n = 0
    for candidate in wordlist:
        candidate = candidate.rstrip("\r\n")
        if not (8 <= len(candidate) <= 63):
            continue
        n += 1
        if progress and n % 1000 == 0:
            progress(n)
        if verify_pmkid(candidate, ssid, ap_mac, sta_mac, expected_pmkid):
            return candidate
    return None


def crack_eapol(ssid: str, ap_mac: BytesLike, sta_mac: BytesLike,
                anonce: BytesLike, snonce: BytesLike, eapol_frame_mic_zeroed: bytes,
                expected_mic: BytesLike, wordlist: Iterable[str],
                key_version: int = 2, progress: callable | None = None) -> str | None:
    """Run *wordlist* against a captured 4-way MIC in pure Python."""
    n = 0
    for candidate in wordlist:
        candidate = candidate.rstrip("\r\n")
        if not (8 <= len(candidate) <= 63):
            continue
        n += 1
        if progress and n % 1000 == 0:
            progress(n)
        if verify_eapol(candidate, ssid, ap_mac, sta_mac, anonce, snonce,
                        eapol_frame_mic_zeroed, expected_mic, key_version):
            return candidate
    return None

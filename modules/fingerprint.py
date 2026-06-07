"""Passive 802.11 device fingerprinter using scapy beacon/probe frames."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from scapy.all import (  # type: ignore[import]
        Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, sniff,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("scapy not installed — passive fingerprinting disabled")


# IEEE vendor-specific IE OUI prefixes
_VENDOR_IE_MAP: dict[bytes, str] = {
    b"\x00\x50\xf2\x01": "Microsoft WMM/WME",
    b"\x00\x50\xf2\x04": "Microsoft WPS",
    b"\x00\x17\xf2":     "Apple",
    b"\x00\x10\x18":     "Broadcom",
    b"\x00\x90\x4c":     "Broadcom HT (Epigram)",
    b"\x00\x03\x7f":     "Atheros",
    b"\x00\x17\xf2":     "Apple HomeKit",
    b"\x50\x6f\x9a\x09": "Wi-Fi Alliance P2P",
    b"\x50\x6f\x9a\x1c": "Wi-Fi Alliance FILS",
}

_DEVICE_SIGNATURES: list[tuple[str, str]] = [
    ("Apple HomeKit",      "Apple smart-home device (likely static key)"),
    ("Apple",              "Apple device (Mac / iPhone / iPad)"),
    ("Microsoft WPS",      "WPS-enabled router"),
    ("Microsoft WMM",      "QoS-capable device"),
    ("Broadcom HT",        "Broadcom 802.11n chipset (router/laptop)"),
    ("Broadcom",           "Broadcom-based device"),
    ("Wi-Fi Alliance P2P", "Wi-Fi Direct capable device"),
    ("Atheros",            "Atheros/Qualcomm chipset"),
]


@dataclass
class DeviceFingerprint:
    bssid: str
    ssid: str = ""
    vendor_ies: list[str] = field(default_factory=list)
    supported_rates: list[float] = field(default_factory=list)
    ht_capable: bool = False
    vht_capable: bool = False
    he_capable: bool = False
    country_code: Optional[str] = None
    device_type: str = "Unknown"
    frame_count: int = 0


def _parse_rates(data: bytes) -> list[float]:
    return [(b & 0x7F) * 0.5 for b in data]


def _identify_device(fp: DeviceFingerprint) -> str:
    for ie_substr, label in _DEVICE_SIGNATURES:
        if any(ie_substr in v for v in fp.vendor_ies):
            return label
    if fp.he_capable:
        return "WiFi 6 (802.11ax) device"
    if fp.vht_capable:
        return "WiFi 5 (802.11ac) device"
    if fp.ht_capable:
        return "WiFi 4 (802.11n) device"
    return "Legacy 802.11a/b/g"


def _process_frame(pkt: object, results: dict[str, DeviceFingerprint]) -> None:
    if not SCAPY_AVAILABLE:
        return
    try:
        if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):  # type: ignore
            return
        dot11 = pkt.getlayer(Dot11)  # type: ignore
        if not dot11:
            return
        bssid = (dot11.addr3 or dot11.addr2 or "").upper()
        if not bssid:
            return

        fp = results.setdefault(bssid, DeviceFingerprint(bssid=bssid))
        fp.frame_count += 1

        elt = pkt.getlayer(Dot11Elt)  # type: ignore
        while elt:
            eid  = elt.ID
            info = elt.info if isinstance(elt.info, bytes) else b""

            if eid == 0:      # SSID
                try:
                    fp.ssid = info.decode("utf-8", errors="replace")
                except Exception:
                    pass
            elif eid == 1:    # Supported Rates
                fp.supported_rates = _parse_rates(info)
            elif eid == 7:    # Country
                if len(info) >= 2:
                    fp.country_code = info[:2].decode("ascii", errors="replace")
            elif eid == 45:   # HT Capabilities
                fp.ht_capable = True
            elif eid == 191:  # VHT Capabilities
                fp.vht_capable = True
            elif eid == 255:  # Extension — may contain HE
                if info and info[0] == 0x23:
                    fp.he_capable = True
            elif eid == 221:  # Vendor Specific
                for prefix, name in _VENDOR_IE_MAP.items():
                    if info.startswith(prefix) and name not in fp.vendor_ies:
                        fp.vendor_ies.append(name)
                        break

            elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None  # type: ignore

        fp.device_type = _identify_device(fp)

    except Exception as exc:
        logger.debug("Frame parse error: %s", exc)


def fingerprint_networks(interface: str, duration: int = 15) -> dict[str, DeviceFingerprint]:
    """
    Sniff beacon/probe frames on *interface* for *duration* seconds and
    return a dict mapping BSSID → DeviceFingerprint.
    Requires the interface to already be in monitor mode.
    """
    if not SCAPY_AVAILABLE:
        logger.warning("scapy unavailable — returning empty fingerprint dict")
        return {}

    results: dict[str, DeviceFingerprint] = {}
    logger.info("Fingerprinting on %s for %ds...", interface, duration)

    try:
        sniff(
            iface=interface,
            prn=lambda p: _process_frame(p, results),
            timeout=duration,
            store=False,
        )
    except PermissionError:
        logger.error("Root privileges required for passive capture")
    except Exception as exc:
        logger.error("Sniff error: %s", exc)

    logger.info("Fingerprinted %d unique BSSIDs", len(results))
    return results

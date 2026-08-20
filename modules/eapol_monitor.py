"""
modules/eapol_monitor.py — real-time WPA 4-way / PMKID detector + client discovery.

The handshake engine used to "detect" a handshake by shelling out to aircrack-ng
against the growing .cap file once per second — slow, and heavy enough to starve
the very airodump-ng process recording the frames.  This module replaces that
with an event-driven scapy sniffer that classifies EAPOL-Key messages the instant
they hit the air, and learns active clients continuously from data frames instead
of a single 15-second CSV snapshot.

Design notes
────────────
• The sniffer and airodump-ng both read the same monitor interface passively;
  each opens its own PF_PACKET socket and receives its own copy of every frame,
  so they coexist without contention.
• EAPOL-Key frames are parsed from raw bytes (fixed IEEE-802.11 offsets) rather
  than scapy's version-dependent key dissection, so the classifier is stable
  across scapy releases.
• All the parsing logic (`classify_eapol`, `is_crackable`, `pmkid_from_m1`,
  `client_from_data_frame`) is pure and unit-tested — no RF needed.
• The on-disk `.cap` remains the authoritative artifact; this monitor is the
  *trigger*, and the caller confirms with aircrack-ng/tshark/hcxpcapngtool before
  declaring success.  So a parser quirk can never produce a false positive.
"""
from __future__ import annotations

import logging
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from modules import radio

logger = logging.getLogger(__name__)

# ─── Optional scapy import (required dep, but degrade gracefully) ─────────────
try:
    from scapy.sendrecv import AsyncSniffer
    from scapy.layers.dot11 import Dot11, RadioTap
    from scapy.layers.eap import EAPOL
    _SCAPY_OK = True
except Exception as _exc:  # pragma: no cover - only when scapy truly absent
    AsyncSniffer = None  # type: ignore
    Dot11 = RadioTap = EAPOL = None  # type: ignore
    _SCAPY_OK = False
    logger.debug("scapy unavailable — LiveMonitor disabled: %s", _exc)


# ─── EAPOL Key Information bit flags (IEEE 802.11-2016 §12.7.2) ───────────────
KI_INSTALL = 0x0040
KI_ACK     = 0x0080
KI_MIC     = 0x0100
KI_SECURE  = 0x0200
KI_PAIRWISE = 0x0008

# Fixed offsets into the 802.1X/EAPOL-Key frame (after the 4-byte EAPOL header)
_OFF_KEY_INFO   = 5    # 2 bytes, big-endian
_OFF_REPLAY     = 9    # 8 bytes
_OFF_KEY_DATALEN = 97  # 2 bytes
_OFF_KEY_DATA   = 99
_MIN_EAPOL_KEY_LEN = 99


# ═════════════════════════════════════════════════════════════════════════════
# Pure parsing helpers (unit-tested)
# ═════════════════════════════════════════════════════════════════════════════

def classify_eapol(key_info: int, from_ds: bool = False, key_data_len: int = 0) -> int:
    """Classify a pairwise 4-way handshake message from its Key Information field.

    Returns 1/2/3/4 for M1/M2/M3/M4, or 0 for group-key / unrecognised frames.
    """
    ack     = bool(key_info & KI_ACK)
    mic     = bool(key_info & KI_MIC)
    install = bool(key_info & KI_INSTALL)
    secure  = bool(key_info & KI_SECURE)

    if ack and not mic:
        return 1                         # M1: ANonce, no MIC, AP → STA
    if mic and ack and install:
        return 3                         # M3: MIC + ACK + Install, AP → STA
    if mic and not ack and secure:
        return 4                         # M4: MIC, Secure set, STA → AP
    if mic and not ack and not secure:
        return 2                         # M2: SNonce + MIC, STA → AP
    return 0


def is_crackable(msgs_by_replay: Dict[int, Set[int]]) -> bool:
    """True if the captured EAPOL messages form a crackable pair.

    Aircrack-ng / hashcat need either M1+M2 (ANonce from M1, SNonce+MIC from M2,
    same replay counter) or M2+M3 (M3 uses replay counter M2+1).  We also accept
    both messages landing under one replay bucket, which happens with real-world
    captures where retransmits reuse counters.
    """
    for _rc, msgs in msgs_by_replay.items():
        if 1 in msgs and 2 in msgs:
            return True
        if 2 in msgs and 3 in msgs:
            return True
    for rc, msgs in msgs_by_replay.items():
        nxt = msgs_by_replay.get(rc + 1, set())
        if 2 in msgs and 3 in nxt:
            return True
        if 1 in msgs and 2 in nxt:
            return True
    return False


def pmkid_from_m1(key_data: bytes) -> Optional[str]:
    """Extract the RSN PMKID (16-byte) from an M1 frame's key-data KDEs.

    KDE layout: 0xDD | len | OUI(00-0F-AC) | data-type | data.
    The PMKID KDE is data-type 0x04.  M1 key-data is never encrypted, so this
    works on the plaintext frame.
    """
    i, n = 0, len(key_data)
    while i + 2 <= n:
        if key_data[i] != 0xDD:
            break
        length = key_data[i + 1]
        kde = key_data[i + 2 : i + 2 + length]
        if len(kde) >= 20 and kde[0:3] == b"\x00\x0f\xac" and kde[3] == 0x04:
            pmkid = kde[4:20]
            if any(pmkid):                       # ignore all-zero placeholder
                return pmkid.hex()
        i += 2 + length
    return None


def _is_station_mac(mac: Optional[str], bssid: str) -> bool:
    """True if *mac* looks like an individual client (not the AP, not group/mcast)."""
    if not mac:
        return False
    mac = mac.upper()
    if mac == bssid.upper() or mac == "FF:FF:FF:FF:FF:FF":
        return False
    try:
        first = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return not (first & 0x01)                    # group/multicast bit clear


def client_from_data_frame(
    to_ds: bool, from_ds: bool,
    addr1: Optional[str], addr2: Optional[str], addr3: Optional[str],
    bssid: str,
) -> Optional[str]:
    """Resolve the client STA MAC from a data frame's ToDS/FromDS direction."""
    if to_ds and not from_ds:
        cand = addr2                             # addr1=BSSID, addr2=SA(client)
    elif from_ds and not to_ds:
        cand = addr1                             # addr1=DA(client), addr2=BSSID
    else:
        return None                              # WDS / IBSS — skip
    return cand.upper() if _is_station_mac(cand, bssid) else None


# ═════════════════════════════════════════════════════════════════════════════
# Snapshot types
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class SnapClient:
    mac: str
    rssi: int
    packets: int


@dataclass
class MonitorSnapshot:
    clients: List[SnapClient] = field(default_factory=list)
    handshake_client: Optional[str] = None
    pmkid_present: bool = False
    pmkid_hashes: Dict[str, str] = field(default_factory=dict)
    ap_seen: bool = False


# ═════════════════════════════════════════════════════════════════════════════
# LiveMonitor
# ═════════════════════════════════════════════════════════════════════════════

class LiveMonitor:
    """Real-time EAPOL / PMKID / client tracker over a monitor interface."""

    def __init__(self, interface: str, target_bssid: str) -> None:
        self.interface = interface
        self.target_bssid = target_bssid.upper()
        self.available = _SCAPY_OK
        self.error: Optional[str] = None

        self._lock = threading.Lock()
        self._clients: Dict[str, dict] = {}
        self._hs: Dict[str, Dict[int, Set[int]]] = {}
        self._pmkid_present = False
        self._pmkid_hashes: Dict[str, str] = {}
        self._ap_seen = False
        self._sniffer = None

    # ── lifecycle ────────────────────────────────────────────────────────────
    def start(self) -> bool:
        if not self.available:
            return False
        try:
            self._sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._handle,
                lfilter=self._lfilter,
                store=False,
            )
            self._sniffer.start()
            logger.debug("LiveMonitor started on %s for %s", self.interface, self.target_bssid)
            return True
        except Exception as exc:                 # pragma: no cover - RF/socket only
            self.available = False
            self.error = str(exc)
            logger.warning("LiveMonitor failed to start: %s", exc)
            return False

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:                    # pragma: no cover
                pass
            self._sniffer = None

    # ── sniff callbacks ──────────────────────────────────────────────────────
    def _lfilter(self, pkt) -> bool:
        try:
            if not pkt.haslayer(Dot11):
                return False
            if pkt.haslayer(EAPOL):
                return True
            d = pkt.getlayer(Dot11)
            t = self.target_bssid
            return any(a and a.upper() == t for a in (d.addr1, d.addr2, d.addr3))
        except Exception:                        # pragma: no cover
            return False

    def _rssi(self, pkt) -> Optional[int]:
        try:
            if RadioTap is not None and pkt.haslayer(RadioTap):
                val = getattr(pkt[RadioTap], "dBm_AntSignal", None)
                if val is not None:
                    return int(val)
        except Exception:                        # pragma: no cover
            pass
        return None

    def _handle(self, pkt) -> None:
        try:
            d = pkt.getlayer(Dot11)
            if d is None:
                return
            rssi = self._rssi(pkt)

            if pkt.haslayer(EAPOL):
                self._handle_eapol(pkt, d, rssi)
                return

            if d.type == 2:                      # data frame → client discovery
                fc = int(d.FCfield)
                client = client_from_data_frame(
                    bool(fc & 0x01), bool(fc & 0x02),
                    d.addr1, d.addr2, d.addr3, self.target_bssid,
                )
                if client:
                    self._touch(client, rssi)
            elif d.type == 0:                    # mgmt (beacon / probe-resp)
                self._ap_seen = True
        except Exception:                        # pragma: no cover
            pass

    def _handle_eapol(self, pkt, d, rssi) -> None:
        raw = bytes(pkt[EAPOL])
        if len(raw) < _MIN_EAPOL_KEY_LEN:
            return
        key_info = int.from_bytes(raw[_OFF_KEY_INFO:_OFF_KEY_INFO + 2], "big")
        replay   = int.from_bytes(raw[_OFF_REPLAY:_OFF_REPLAY + 8], "big")
        kdl      = int.from_bytes(raw[_OFF_KEY_DATALEN:_OFF_KEY_DATALEN + 2], "big")
        key_data = raw[_OFF_KEY_DATA:_OFF_KEY_DATA + kdl] if kdl else b""

        fc = int(d.FCfield)
        from_ds = bool(fc & 0x02)
        msg = classify_eapol(key_info, from_ds, kdl)
        if msg == 0:
            return

        client = d.addr1 if from_ds else d.addr2   # STA is the non-AP side
        if not client:
            return
        client = client.upper()
        if client == self.target_bssid:
            return

        with self._lock:
            self._touch_locked(client, rssi)
            self._hs.setdefault(client, {}).setdefault(replay, set()).add(msg)
            if msg == 1 and key_data:
                pmkid = pmkid_from_m1(key_data)
                if pmkid:
                    self._pmkid_present = True
                    self._pmkid_hashes[client] = pmkid
        logger.debug("EAPOL M%d  client=%s  replay=%d", msg, client, replay)

    # ── client bookkeeping ───────────────────────────────────────────────────
    def _touch(self, mac: str, rssi: Optional[int]) -> None:
        with self._lock:
            self._touch_locked(mac, rssi)

    def _touch_locked(self, mac: str, rssi: Optional[int]) -> None:
        c = self._clients.get(mac)
        if c is None:
            c = {"rssi": rssi if rssi is not None else -100, "packets": 0, "last": 0.0}
            self._clients[mac] = c
        if rssi is not None:
            c["rssi"] = rssi
        c["packets"] += 1
        c["last"] = time.time()

    # ── public read ──────────────────────────────────────────────────────────
    def snapshot(self) -> MonitorSnapshot:
        with self._lock:
            clients = [
                SnapClient(mac=m, rssi=c["rssi"], packets=c["packets"])
                for m, c in self._clients.items()
            ]
            clients.sort(key=lambda sc: sc.rssi, reverse=True)
            hs_client = next(
                (c for c, buckets in self._hs.items() if is_crackable(buckets)),
                None,
            )
            return MonitorSnapshot(
                clients=clients,
                handshake_client=hs_client,
                pmkid_present=self._pmkid_present,
                pmkid_hashes=dict(self._pmkid_hashes),
                ap_seen=self._ap_seen,
            )


# ═════════════════════════════════════════════════════════════════════════════
# Shared client discovery (used by handshake engine and deauth module)
# ═════════════════════════════════════════════════════════════════════════════

def _parse_station_csv(csv_path: str, bssid: str) -> Dict[str, dict]:
    """Minimal airodump-ng station-section parser: {mac: {power, packets}}."""
    out: Dict[str, dict] = {}
    if not csv_path or not os.path.exists(csv_path):
        return out
    try:
        with open(csv_path, "r", errors="replace") as fh:
            lines = [ln.replace("\0", "") for ln in fh]
    except OSError:
        return out

    target = bssid.upper()
    in_stations = False
    for line in lines:
        cell0 = line.split(",", 1)[0].strip()
        if cell0 == "Station MAC":
            in_stations = True
            continue
        if not in_stations or not line.strip():
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 6:
            continue
        mac, assoc = parts[0].upper(), parts[5].upper()
        if assoc != target or len(mac) != 17:
            continue
        try:
            pwr = int(parts[3])
        except ValueError:
            pwr = -100
        try:
            pkts = int(parts[4])
        except ValueError:
            pkts = 0
        out[mac] = {"power": pwr if pwr not in (0, -1) else -100, "packets": pkts}
    return out


def discover_clients(
    interface: str,
    bssid: str,
    channel: int,
    duration: int = 10,
) -> List[dict]:
    """Passively discover active clients of *bssid* on *channel*.

    Runs a channel-locked airodump-ng (for the CSV + to hold the channel) and a
    LiveMonitor in parallel, then merges: monitor-observed data-frame clients
    (reliable for active stations) unioned with the airodump station table.
    Returns ``[{"mac", "power", "packets"}]`` sorted by signal strength.
    """
    import glob
    import shutil
    import tempfile

    tmpdir = tempfile.mkdtemp(prefix="wd_disc_")
    prefix = os.path.join(tmpdir, "disc")
    proc = None
    monitor = LiveMonitor(interface, bssid)
    try:
        try:
            proc = radio.spawn(
                ["airodump-ng", "-c", str(channel), "-w", prefix, interface],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                preexec_fn=getattr(os, "setsid", None),
            )
        except Exception as exc:                 # pragma: no cover
            logger.debug("discover_clients airodump failed: %s", exc)

        monitor.start()
        time.sleep(max(3, duration))

        merged: Dict[str, dict] = {
            sc.mac: {"power": sc.rssi, "packets": sc.packets}
            for sc in monitor.snapshot().clients
        }

        csv_hits = glob.glob(prefix + "-*.csv")
        if csv_hits:
            newest = max(csv_hits, key=os.path.getmtime)
            for mac, c in _parse_station_csv(newest, bssid).items():
                if mac in merged:
                    merged[mac]["packets"] = max(merged[mac]["packets"], c["packets"])
                    if merged[mac]["power"] in (-100, None):
                        merged[mac]["power"] = c["power"]
                else:
                    merged[mac] = c

        result = [
            {"mac": m, "power": c.get("power", -100), "packets": c.get("packets", 0)}
            for m, c in merged.items()
        ]
        result.sort(key=lambda d: d["power"] if d["power"] is not None else -100, reverse=True)
        return result
    finally:
        monitor.stop()
        if proc is not None:
            try:
                if hasattr(os, "killpg"):
                    os.killpg(os.getpgid(proc.pid), 15)
                else:                            # pragma: no cover
                    proc.terminate()
                proc.wait(timeout=3)
            except Exception:                    # pragma: no cover
                try:
                    proc.kill()
                except Exception:
                    pass
        shutil.rmtree(tmpdir, ignore_errors=True)

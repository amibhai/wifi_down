"""
BEACON HISTORIAN — Passive long-term AP behavioral profiling.

Entirely passive (no frame injection). Runs as a background thread.
No scope authorization required.

Tracks:
  - Beacon interval drift (reboot / firmware change indicator)
  - RSSI variance (AP movement / interference)
  - IE (Information Element) changes between beacons (firmware updates)
  - Client probe requests (devices that trust this SSID)

Outputs a NetworkBehavioralProfile dict and feeds probe OUIs
into wordlist Strategy 11 (vendor default passwords).
"""
from __future__ import annotations

import json
import logging
import statistics
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()

RESULTS_DIR = Path("results")


# ─── Data structures ──────────────────────────────────────────────────────────

@dataclass
class BeaconSample:
    timestamp: float
    rssi: int
    beacon_interval: int         # in TUs (1 TU = 1.024 ms)
    ie_fingerprint: str          # SHA256 of IEs blob
    channel: int


@dataclass
class ProbeRequest:
    timestamp: float
    src_mac: str
    ssid: str
    vendor: str = ""


@dataclass
class Anomaly:
    timestamp_offset: float      # seconds from session start
    kind: str                    # "ie_change", "interval_spike", "rssi_jump"
    description: str


@dataclass
class NetworkBehavioralProfile:
    ssid: str
    bssid: str
    duration_s: float
    beacon_count: int
    stability_score: int         # 0–100
    anomalies: list[Anomaly]     = field(default_factory=list)
    probe_devices: list[ProbeRequest] = field(default_factory=list)
    rssi_mean: float             = 0.0
    rssi_stddev: float           = 0.0
    interval_mean: float         = 0.0
    interval_stddev: float       = 0.0
    wordlist_seeds: list[str]    = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ssid":            self.ssid,
            "bssid":           self.bssid,
            "duration_s":      round(self.duration_s, 1),
            "beacon_count":    self.beacon_count,
            "stability_score": self.stability_score,
            "rssi_mean":       round(self.rssi_mean, 1),
            "rssi_stddev":     round(self.rssi_stddev, 2),
            "interval_mean":   round(self.interval_mean, 2),
            "interval_stddev": round(self.interval_stddev, 2),
            "anomalies": [
                {"offset_s": round(a.timestamp_offset, 1),
                 "kind": a.kind, "description": a.description}
                for a in self.anomalies
            ],
            "probe_devices": [
                {"mac": p.src_mac, "vendor": p.vendor, "ssid": p.ssid}
                for p in self.probe_devices
            ],
            "wordlist_seeds":  self.wordlist_seeds,
        }


# ─── OUI lookup helper (uses existing oui.py if available) ───────────────────

def _oui_lookup(mac: str) -> str:
    try:
        from .oui import lookup_vendor
        return lookup_vendor(mac) or ""
    except Exception:
        return ""


# ─── Scapy-based beacon collector ─────────────────────────────────────────────

class BeaconHistorian:
    """
    Passive beacon frame collector using Scapy.
    Can run as a blocking call or in a background daemon thread.
    """

    def __init__(
        self,
        interface: str,
        target_ssid: str,
        target_bssid: str,
        duration: int = 60,
        on_beacon: Optional[Callable[[BeaconSample], None]] = None,
        on_probe:  Optional[Callable[[ProbeRequest], None]] = None,
    ) -> None:
        self.interface    = interface
        self.target_ssid  = target_ssid.lower()
        self.target_bssid = target_bssid.upper()
        self.duration     = duration
        self.on_beacon    = on_beacon
        self.on_probe     = on_probe

        self._samples: list[BeaconSample]  = []
        self._probes:  list[ProbeRequest]  = []
        self._start:   float               = 0.0
        self._stop_event                   = threading.Event()

    # ── Scapy packet callback ─────────────────────────────────────────────

    def _handle_packet(self, pkt: object) -> None:
        try:
            from scapy.layers.dot11 import (
                Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Elt, RadioTap
            )
            import hashlib

            if not pkt.haslayer(Dot11):
                return

            ts = time.monotonic()

            # ── Beacon frames ──────────────────────────────────────────────
            if pkt.haslayer(Dot11Beacon):
                bssid = pkt[Dot11].addr3.upper() if pkt[Dot11].addr3 else ""
                if bssid != self.target_bssid:
                    return

                ssid = ""
                beacon_interval = 100
                ies_raw = b""
                channel = 0

                elt = pkt.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 0 and isinstance(elt.info, (bytes, bytearray)):
                        ssid = elt.info.decode(errors="replace")
                    ies_raw += bytes(elt)
                    elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

                if hasattr(pkt[Dot11Beacon], "beacon_interval"):
                    beacon_interval = pkt[Dot11Beacon].beacon_interval

                rssi = -100
                if pkt.haslayer(RadioTap):
                    rt = pkt[RadioTap]
                    if hasattr(rt, "dBm_AntSignal"):
                        rssi = rt.dBm_AntSignal

                ie_fp = hashlib.sha256(ies_raw).hexdigest()[:16]
                sample = BeaconSample(
                    timestamp=ts,
                    rssi=rssi,
                    beacon_interval=beacon_interval,
                    ie_fingerprint=ie_fp,
                    channel=channel,
                )
                self._samples.append(sample)
                if self.on_beacon:
                    self.on_beacon(sample)

            # ── Probe requests ─────────────────────────────────────────────
            elif pkt.haslayer(Dot11ProbeReq):
                src_mac = pkt[Dot11].addr2.upper() if pkt[Dot11].addr2 else ""
                probe_ssid = ""
                elt = pkt.getlayer(Dot11Elt)
                if elt and elt.ID == 0 and isinstance(elt.info, (bytes, bytearray)):
                    probe_ssid = elt.info.decode(errors="replace")

                if probe_ssid.lower() == self.target_ssid or probe_ssid == "":
                    vendor = _oui_lookup(src_mac)
                    probe = ProbeRequest(
                        timestamp=ts,
                        src_mac=src_mac,
                        ssid=probe_ssid,
                        vendor=vendor,
                    )
                    # Deduplicate by MAC
                    known = {p.src_mac for p in self._probes}
                    if src_mac not in known:
                        self._probes.append(probe)
                        if self.on_probe:
                            self.on_probe(probe)

        except Exception as exc:
            logger.debug("historian packet handler: %s", exc)

    def collect(self) -> NetworkBehavioralProfile:
        """Block for *duration* seconds collecting beacons, then return profile."""
        try:
            from scapy.all import sniff
        except ImportError:
            logger.warning("scapy not installed — Beacon Historian unavailable")
            return self._empty_profile()

        self._start = time.monotonic()
        logger.info("Beacon Historian: collecting %ds from %s (%s)",
                    self.duration, self.target_ssid, self.target_bssid)

        sniff(
            iface=self.interface,
            prn=self._handle_packet,
            store=False,
            timeout=self.duration,
            stop_filter=lambda _: self._stop_event.is_set(),
        )

        return self._build_profile()

    def start_background(self) -> threading.Thread:
        """Start collection in a daemon thread. Call .stop() to end early."""
        t = threading.Thread(target=self.collect, daemon=True, name="BeaconHistorian")
        t.start()
        return t

    def stop(self) -> None:
        self._stop_event.set()

    # ── Profile construction ──────────────────────────────────────────────

    def _empty_profile(self) -> NetworkBehavioralProfile:
        return NetworkBehavioralProfile(
            ssid=self.target_ssid,
            bssid=self.target_bssid,
            duration_s=0,
            beacon_count=0,
            stability_score=0,
        )

    def _build_profile(self) -> NetworkBehavioralProfile:
        duration = time.monotonic() - self._start
        samples  = self._samples

        if not samples:
            return self._empty_profile()

        rssies     = [s.rssi for s in samples]
        intervals  = [s.beacon_interval for s in samples]
        rssi_mean  = statistics.mean(rssies)
        rssi_std   = statistics.stdev(rssies) if len(rssies) > 1 else 0.0
        int_mean   = statistics.mean(intervals)
        int_std    = statistics.stdev(intervals) if len(intervals) > 1 else 0.0

        anomalies: list[Anomaly] = []

        # IE change detection
        prev_fp = samples[0].ie_fingerprint
        for s in samples[1:]:
            if s.ie_fingerprint != prev_fp:
                offset = s.timestamp - self._start
                anomalies.append(Anomaly(
                    timestamp_offset=offset,
                    kind="ie_change",
                    description=f"IE mismatch at T+{offset:.0f}s — possible firmware update or config change detected",
                ))
                prev_fp = s.ie_fingerprint

        # Beacon interval spikes (> 2 std dev from mean)
        if int_std > 0:
            for s in samples:
                if abs(s.beacon_interval - int_mean) > 2 * int_std:
                    offset = s.timestamp - self._start
                    anomalies.append(Anomaly(
                        timestamp_offset=offset,
                        kind="interval_spike",
                        description=f"Beacon interval spike at T+{offset:.0f}s "
                                    f"({s.beacon_interval} TU, mean={int_mean:.0f})",
                    ))

        # RSSI jump (> 3 std dev)
        if rssi_std > 0 and len(rssies) > 5:
            for s in samples:
                if abs(s.rssi - rssi_mean) > 3 * rssi_std:
                    offset = s.timestamp - self._start
                    anomalies.append(Anomaly(
                        timestamp_offset=offset,
                        kind="rssi_jump",
                        description=f"RSSI anomaly at T+{offset:.0f}s "
                                    f"({s.rssi} dBm, mean={rssi_mean:.0f})",
                    ))

        # Deduplicate anomalies (keep unique kind + round offset)
        seen: set[tuple[str, int]] = set()
        unique_anomalies: list[Anomaly] = []
        for a in anomalies:
            key = (a.kind, int(a.timestamp_offset // 5))
            if key not in seen:
                seen.add(key)
                unique_anomalies.append(a)

        # Stability score: 100 minus penalties
        score = 100
        score -= len(unique_anomalies) * 15
        score -= min(40, int(rssi_std * 2))
        score -= min(20, int(int_std))
        score = max(0, min(100, score))

        # Wordlist seeds from probe vendor names
        seeds: list[str] = []
        for p in self._probes:
            if p.vendor:
                # Extract model hints from vendor string for Strategy 11
                parts = p.vendor.lower().split()
                seeds.extend(parts[:2])  # first two words of vendor name

        return NetworkBehavioralProfile(
            ssid=self.target_ssid,
            bssid=self.target_bssid,
            duration_s=duration,
            beacon_count=len(samples),
            stability_score=score,
            anomalies=unique_anomalies,
            probe_devices=self._probes,
            rssi_mean=rssi_mean,
            rssi_stddev=rssi_std,
            interval_mean=int_mean,
            interval_stddev=int_std,
            wordlist_seeds=list(set(seeds)),
        )


# ─── Rich display ─────────────────────────────────────────────────────────────

def display_profile(profile: NetworkBehavioralProfile) -> None:
    score = profile.stability_score
    score_color = "green" if score >= 70 else ("yellow" if score >= 40 else "red")

    console.print()
    console.print(Panel(
        f"[bold #00D4AA]BEACON HISTORIAN — Network Behavioral Profile[/bold #00D4AA]\n\n"
        f"  SSID:            [cyan]{profile.ssid}[/cyan]\n"
        f"  BSSID:           [dim]{profile.bssid}[/dim]\n"
        f"  Collection:      {profile.duration_s:.0f}s  "
        f"({profile.beacon_count} beacons)\n"
        f"  Stability score: [{score_color}]{score}/100[/{score_color}]\n"
        f"  RSSI:            mean={profile.rssi_mean:.1f} dBm  "
        f"σ={profile.rssi_stddev:.1f}\n"
        f"  Interval:        mean={profile.interval_mean:.0f} TU  "
        f"σ={profile.interval_stddev:.1f}",
        border_style="#00D4AA",
    ))

    if profile.anomalies:
        console.print(f"\n  [bold yellow]Anomalies detected ({len(profile.anomalies)}):[/bold yellow]")
        for a in profile.anomalies:
            icon = {"ie_change": "⚡", "interval_spike": "⚠", "rssi_jump": "📡"}.get(a.kind, "•")
            console.print(f"  {icon} [dim]{a.description}[/dim]")

    if profile.probe_devices:
        console.print(f"\n  [bold]Nearby devices probing for this SSID ({len(profile.probe_devices)}):[/bold]")
        for p in profile.probe_devices:
            vendor_tag = f"  [dim]({p.vendor})[/dim]" if p.vendor else ""
            console.print(f"  • [cyan]{p.src_mac}[/cyan]{vendor_tag}")

    if profile.wordlist_seeds:
        console.print(f"\n  [dim]Vendor seeds added to wordlist strategy 11:[/dim]")
        console.print(f"  [dim]{', '.join(profile.wordlist_seeds)}[/dim]")

    console.print()


# ─── CLI entry point ──────────────────────────────────────────────────────────

def historian_menu(
    interface: str,
    target: Optional[dict],
) -> Optional[NetworkBehavioralProfile]:
    """
    Interactive Beacon Historian launcher.
    Passive — no scope check required.
    """
    console.print()
    console.print(Panel(
        "[bold #00D4AA]BEACON HISTORIAN[/bold #00D4AA]\n\n"
        "[dim]Passive behavioral profiling of a target AP.\n"
        "No frame injection. No scope authorization required.\n"
        "Runs as a background thread alongside other modules.[/dim]",
        border_style="#00D4AA",
    ))
    console.print()

    if not target:
        console.print("[red]  No target selected. Scan first.[/red]")
        return None

    bssid   = target.get("bssid", "")
    ssid    = target.get("ssid", "UNKNOWN")

    try:
        dur_str = input("  Collection window in seconds [60, max 86400]: ").strip() or "60"
        duration = max(10, min(86400, int(dur_str)))
    except (ValueError, KeyboardInterrupt):
        duration = 60

    console.print(f"\n  [cyan][*][/cyan] Collecting from [white]{ssid}[/white] for {duration}s...")
    console.print("  [dim]Press Ctrl+C to stop early and generate partial profile.[/dim]\n")

    historian = BeaconHistorian(
        interface=interface,
        target_ssid=ssid,
        target_bssid=bssid,
        duration=duration,
        on_beacon=lambda s: None,
        on_probe=lambda p: console.print(
            f"  [dim cyan]probe:[/dim cyan] [cyan]{p.src_mac}[/cyan]"
            + (f"  {p.vendor}" if p.vendor else "")
        ),
    )

    try:
        profile = historian.collect()
    except KeyboardInterrupt:
        console.print("\n  [yellow]Collection stopped early.[/yellow]")
        profile = historian._build_profile()

    display_profile(profile)

    # Save profile to results/
    RESULTS_DIR.mkdir(exist_ok=True)
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = RESULTS_DIR / f"historian_{ts}.json"
    out.write_text(json.dumps(profile.to_dict(), indent=2))
    console.print(f"  [dim]Profile saved: {out}[/dim]\n")

    # Log to audit chain
    logger.info(
        "BEACON_HISTORIAN ssid=%s bssid=%s stability=%d anomalies=%d probes=%d",
        ssid, bssid, profile.stability_score,
        len(profile.anomalies), len(profile.probe_devices),
    )

    return profile

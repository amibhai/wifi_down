#!/usr/bin/env python3
"""
radio.py — the reliability core of the auditor's RF front-end.

This module is what separates a demo-quality tool from one that survives a real
engagement without bricking the operator's networking. It concentrates every
"why did monitor mode silently fail?" edge case that airgeddon learned the hard
way, and does so with **pure, unit-testable parsers** wrapped by thin
subprocess shims — the same split the EAPOL engine uses.

Responsibilities
----------------
1. **rfkill** — detect and clear soft blocks; surface hard blocks (physical
   switch / BIOS) with an actionable message instead of a mystery failure.
2. **Service save / restore** — record exactly which network services were
   running *before* we tore them down, persist that to disk, and restore only
   those. Never blindly `systemctl start NetworkManager` on an `iwd` /
   `systemd-networkd` / `netctl` box.
3. **Driver quirks** — some chipsets (Realtek 88xxau, some mt76) drive monitor
   mode more reliably through `iw` than `airmon-ng`. Route around known
   breakage automatically.
4. **Monitor enable/disable** — `airmon-ng` primary path with an `iw` + `ip
   link` fallback, both verified via `iw dev`.
5. **Band / channel math** — 2.4, 5, and 6 GHz channel↔frequency conversion.
6. **ProcessSupervisor** — a central registry so a crash or Ctrl-C reaps every
   child (airodump/reaver/hcxdumptool) instead of stranding the card in monitor
   mode with orphaned processes holding it.

Design constraints
------------------
* Import-safe and testable on non-Linux dev boxes: every OS-specific call is
  guarded; the pure parsers take strings, not live command output.
* No hard dependency on `interface.py` (that module imports *this* one).
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import signal
import subprocess
import time
from collections.abc import Iterable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# Optional pretty console; degrade to plain print if rich is unavailable.
try:  # pragma: no cover - trivial import guard
    from rich.console import Console

    _console: Console | None = Console()
except Exception:  # pragma: no cover
    _console = None


def _say(msg: str) -> None:
    """Console notice that never raises and never blocks logic/tests."""
    if _console is not None:
        try:
            _console.print(msg)
            return
        except Exception:
            pass
    # Strip the most common rich tags for a clean plaintext fallback.
    logger.info(re.sub(r"\[/?[^\]]*\]", "", msg))


# State persisted across processes so a *crashed* run can still restore the box.
AUDIT_HOME = Path.home() / ".wifi-auditor"
SERVICES_STATE_FILE = AUDIT_HOME / "services_state.json"


def _is_root() -> bool:
    """True iff running as uid 0. Safe on platforms without ``geteuid``."""
    geteuid = getattr(os, "geteuid", None)
    return geteuid() == 0 if geteuid else False


# ══════════════════════════════════════════════════════════════════════════════
# Band / channel math  (pure)
# ══════════════════════════════════════════════════════════════════════════════

def freq_to_band(freq_mhz: int) -> str:
    """Map a centre frequency in MHz to a human band label: '2.4', '5', or '6'."""
    if freq_mhz < 2500:
        return "2.4"
    if freq_mhz < 5925:
        return "5"
    return "6"


def channel_to_freq(channel: int, band: str | None = None) -> int | None:
    """
    Convert a channel number to its centre frequency in MHz.

    Channels 1–14 exist in *both* 2.4 GHz and 6 GHz, so pass ``band`` ('2.4',
    '5', '6') to disambiguate. Without a hint we assume the lowest plausible
    band (2.4 for ≤14, 5 for ≤196, else 6). Returns ``None`` for nonsense.
    """
    ch = int(channel)
    if band is None:
        band = "2.4" if ch <= 14 else ("5" if ch <= 196 else "6")

    if band == "2.4":
        if ch == 14:
            return 2484
        if 1 <= ch <= 13:
            return 2407 + ch * 5
        return None
    if band == "5":
        # 5 GHz: f = 5000 + ch*5  (covers 36…177 and the low U-NII 7…14 range)
        if 1 <= ch <= 196:
            return 5000 + ch * 5
        return None
    if band == "6":
        # 6 GHz (Wi-Fi 6E / 7): channel 2 is the special 5935 MHz anchor.
        if ch == 2:
            return 5935
        if 1 <= ch <= 233:
            return 5950 + ch * 5
        return None
    return None


def band_of_channel(channel: int) -> str:
    """Best-effort band label from a bare channel number (assumes 2.4 for ≤14)."""
    ch = int(channel)
    if ch <= 14:
        return "2.4"
    if ch <= 196:
        return "5"
    return "6"


# ══════════════════════════════════════════════════════════════════════════════
# rfkill  (pure parsers + thin shim)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class RfkillEntry:
    id: int | None
    type: str            # 'wlan', 'bluetooth', …
    device: str          # 'phy0', …
    soft_blocked: bool
    hard_blocked: bool


def parse_rfkill_json(text: str) -> list[RfkillEntry]:
    """
    Parse ``rfkill --json`` output.

    util-linux nests the list under either ``rfkilldevices`` (newer) or
    ``""`` (older). Returns [] on anything unparseable.
    """
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    rows: Iterable = []
    if isinstance(data, dict):
        rows = data.get("rfkilldevices") or data.get("") or []
    elif isinstance(data, list):
        rows = data
    out: list[RfkillEntry] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        rid = row.get("id")
        out.append(
            RfkillEntry(
                id=int(rid) if isinstance(rid, (int, str)) and str(rid).isdigit() else None,
                type=str(row.get("type", "")).lower(),
                device=str(row.get("device", "")),
                soft_blocked=str(row.get("soft", "")).lower() == "blocked",
                hard_blocked=str(row.get("hard", "")).lower() == "blocked",
            )
        )
    return out


def parse_rfkill_text(text: str) -> list[RfkillEntry]:
    """
    Parse the classic block form of ``rfkill list``::

        0: phy0: Wireless LAN
            Soft blocked: yes
            Hard blocked: no
    """
    entries: list[RfkillEntry] = []
    cur: RfkillEntry | None = None
    header = re.compile(r"^\s*(\d+):\s+([^:]+):\s+(.*)$")
    for line in text.splitlines():
        m = header.match(line)
        if m:
            if cur is not None:
                entries.append(cur)
            desc = m.group(3).lower()
            # Infer type from the human description if not otherwise given.
            if "wireless" in desc or "wlan" in desc or "wifi" in desc:
                typ = "wlan"
            elif "bluetooth" in desc:
                typ = "bluetooth"
            else:
                typ = desc.strip()
            cur = RfkillEntry(
                id=int(m.group(1)),
                type=typ,
                device=m.group(2).strip(),
                soft_blocked=False,
                hard_blocked=False,
            )
            continue
        if cur is None:
            continue
        low = line.strip().lower()
        if low.startswith("soft blocked:"):
            cur.soft_blocked = low.endswith("yes")
        elif low.startswith("hard blocked:"):
            cur.hard_blocked = low.endswith("yes")
    if cur is not None:
        entries.append(cur)
    return entries


@dataclass
class RfkillState:
    any_wifi: bool
    soft_blocked_ids: list[int]
    hard_blocked: bool


def wifi_rfkill_state(entries: list[RfkillEntry]) -> RfkillState:
    """Reduce rfkill entries to the wifi-relevant picture we act on."""
    wifi = [e for e in entries if e.type == "wlan"]
    return RfkillState(
        any_wifi=bool(wifi),
        soft_blocked_ids=[e.id for e in wifi if e.soft_blocked and e.id is not None],
        hard_blocked=any(e.hard_blocked for e in wifi),
    )


def _read_rfkill() -> list[RfkillEntry]:
    """Query rfkill, preferring JSON, falling back to the text block form."""
    if not shutil.which("rfkill"):
        return []
    try:
        res = subprocess.run(
            ["rfkill", "--json"], capture_output=True, text=True, timeout=5
        )
        entries = parse_rfkill_json(res.stdout)
        if entries:
            return entries
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    try:
        res = subprocess.run(
            ["rfkill", "list"], capture_output=True, text=True, timeout=5
        )
        return parse_rfkill_text(res.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []


def ensure_rfkill_unblocked() -> tuple[bool, str]:
    """
    Clear soft rfkill blocks on wifi. Returns ``(ok, message)``.

    * ok=True  — radio is usable (nothing blocked, or we cleared the soft block)
    * ok=False — a **hard** block is present (physical switch / BIOS); no amount
      of software can fix it, so we say so plainly instead of failing opaquely.
    """
    state = wifi_rfkill_state(_read_rfkill())
    if not state.any_wifi:
        return True, "no rfkill-managed wifi radio (nothing to unblock)"

    if state.soft_blocked_ids:
        _say("[dim cyan]◈ Clearing rfkill soft block on wifi radio...[/]")
        try:
            subprocess.run(["rfkill", "unblock", "wifi"], capture_output=True, timeout=5)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        state = wifi_rfkill_state(_read_rfkill())  # re-read

    if state.hard_blocked:
        return False, (
            "wifi radio is HARD blocked (physical Wi-Fi switch or BIOS setting). "
            "Software cannot override this — enable the radio via the hardware "
            "switch / function key / BIOS, then retry."
        )
    if state.soft_blocked_ids:
        return False, (
            "wifi radio remains soft-blocked after 'rfkill unblock wifi'. "
            "Try manually: sudo rfkill unblock all"
        )
    return True, "rfkill clear"


# ══════════════════════════════════════════════════════════════════════════════
# iw dev  (one parser to replace the three near-duplicates)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class IwInterface:
    name: str
    type: str = ""       # 'managed', 'monitor', 'AP', …
    phy: str = ""
    channel: int | None = None
    addr: str = ""


def parse_iw_dev(text: str) -> list[IwInterface]:
    """
    Parse ``iw dev`` into structured interface records.

    ``iw dev`` groups by phy; each ``Interface X`` block carries type/channel/
    addr lines. This single parser supersedes the old managed-only / monitor-
    only / verify variants.
    """
    ifaces: list[IwInterface] = []
    cur: IwInterface | None = None
    cur_phy = ""
    for raw in text.splitlines():
        line = raw.strip()
        pm = re.match(r"^phy#(\d+)", line)
        if pm:
            cur_phy = f"phy{pm.group(1)}"
            continue
        if line.startswith("Interface "):
            if cur is not None:
                ifaces.append(cur)
            cur = IwInterface(name=line.split("Interface ", 1)[1].strip(), phy=cur_phy)
            continue
        if cur is None:
            continue
        if line.startswith("type "):
            cur.type = line.split("type ", 1)[1].strip()
        elif line.startswith("addr "):
            cur.addr = line.split("addr ", 1)[1].strip()
        elif line.startswith("channel "):
            m = re.search(r"channel\s+(\d+)", line)
            if m:
                cur.channel = int(m.group(1))
    if cur is not None:
        ifaces.append(cur)
    return ifaces


def _iw_dev() -> list[IwInterface]:
    try:
        res = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=10)
        return parse_iw_dev(res.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []


def wireless_interfaces(mode: str | None = None) -> list[str]:
    """
    Names of wireless interfaces, optionally filtered by mode.

    ``mode=None`` → all; ``'managed'`` / ``'monitor'`` → just that mode.
    """
    out = []
    for i in _iw_dev():
        if mode is None or i.type == mode:
            out.append(i.name)
    return out


def interface_mode(name: str) -> str | None:
    """Current mode of *name* per ``iw dev`` ('monitor'/'managed'/…) or None."""
    for i in _iw_dev():
        if i.name == name:
            return i.type or None
    return None


def is_monitor(name: str) -> bool:
    return interface_mode(name) == "monitor"


# ── phy band capability (which bands can this card actually reach?) ───────────

def parse_phy_frequencies(text: str) -> list[int]:
    """
    Extract the centre frequencies (MHz) from ``iw phy <phy> info``.

    Lines flagged ``disabled`` (regulatory-blocked) are skipped. DFS / ``no IR``
    channels are *kept* — they're perfectly usable for passive discovery and
    still prove the radio reaches that band, which is all band detection needs.
    """
    freqs: list[int] = []
    for line in text.splitlines():
        low = line.lower()
        if "disabled" in low:
            continue
        m = re.search(r"\*\s*(\d+)(?:\.\d+)?\s*mhz", low)
        if m:
            freqs.append(int(m.group(1)))
    return freqs


def phy_bands_from_info(text: str) -> set[str]:
    """Set of bands ('2.4'/'5'/'6') a phy supports, from its ``iw phy info``."""
    return {freq_to_band(f) for f in parse_phy_frequencies(text)}


def phy_of(interface: str) -> str | None:
    """The ``phyN`` a wireless interface belongs to, per ``iw dev``."""
    for i in _iw_dev():
        if i.name == interface and i.phy:
            return i.phy
    return None


def interface_bands(interface: str) -> set[str]:
    """
    Bands this interface's radio can actually use ('2.4'/'5'/'6').

    Returns an empty set if it can't be determined (caller should then assume
    2.4-only, the safe default).
    """
    phy = phy_of(interface)
    if not phy:
        return set()
    try:
        res = subprocess.run(
            ["iw", "phy", phy, "info"], capture_output=True, text=True, timeout=10
        )
        return phy_bands_from_info(res.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return set()


def airodump_band_flag(bands: set[str]) -> str:
    """
    Map a set of supported bands to an ``airodump-ng --band`` letter string.

    airodump uses 'b'/'g' for 2.4 GHz and 'a' for 5 GHz; there is **no** letter
    for 6 GHz — airodump ≥1.7 hops 6 GHz automatically when the card supports it,
    so it needs no flag. Always includes 'bg' as the floor.
    """
    letters = ""
    if "2.4" in bands or not bands:
        letters += "bg"
    if "5" in bands:
        letters += "a"
    return letters or "bg"


# ══════════════════════════════════════════════════════════════════════════════
# Driver detection + quirks  (pure quirk table)
# ══════════════════════════════════════════════════════════════════════════════

# Drivers that historically drive monitor mode more reliably through the raw
# `iw`/`ip` path than through airmon-ng (Realtek out-of-tree drivers especially).
_IW_PREFERRED_DRIVERS = {
    "rtl8812au", "rtl8814au", "rtl8821au", "rtl88xxau", "88xxau", "8812au",
    "8814au", "8821au", "rtl8188eus", "rtl8192eu", "rtl88x2bu", "88x2bu",
    "rtl8821cu", "8821cu", "rtl8723bu",
}


def parse_ethtool_driver(text: str) -> str:
    """Extract the ``driver:`` field from ``ethtool -i`` output."""
    m = re.search(r"^driver:\s*(\S+)", text, re.MULTILINE)
    return m.group(1).strip() if m else ""


def normalize_driver(driver: str) -> str:
    return re.sub(r"[^a-z0-9]", "", driver.lower())


def prefers_iw(driver: str) -> bool:
    """True if this driver should skip airmon-ng and use the iw path directly."""
    d = normalize_driver(driver)
    if not d:
        return False
    if d in {normalize_driver(x) for x in _IW_PREFERRED_DRIVERS}:
        return True
    # Realtek out-of-tree family match (e.g. 'rtl8812au_v5').
    return bool(re.match(r"(rtl)?88(12|14|21|x2|x0)", d))


def driver_of(interface: str) -> str:
    """Best-effort driver name for *interface* (sysfs symlink, then ethtool)."""
    link = Path(f"/sys/class/net/{interface}/device/driver")
    try:
        if link.exists():
            return os.path.basename(os.path.realpath(link))
    except OSError:
        pass
    if shutil.which("ethtool"):
        try:
            res = subprocess.run(
                ["ethtool", "-i", interface], capture_output=True, text=True, timeout=5
            )
            return parse_ethtool_driver(res.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
    return ""


# ══════════════════════════════════════════════════════════════════════════════
# Service save / restore  (symmetric — the airgeddon lesson)
# ══════════════════════════════════════════════════════════════════════════════

# Ordered by how commonly they hold the radio. We only touch services that are
# actually *active*, and we only restart the ones we personally stopped.
MANAGED_SERVICES = [
    "NetworkManager",
    "wpa_supplicant",
    "iwd",
    "systemd-networkd",
    "connman",
    "netctl-auto",
    "dhcpcd",
    "dhclient",
    "wicd",
]


def service_is_active(name: str) -> bool:
    """True iff ``systemctl is-active`` reports the unit active."""
    if not shutil.which("systemctl"):
        return False
    try:
        res = subprocess.run(
            ["systemctl", "is-active", name], capture_output=True, text=True, timeout=5
        )
        return res.stdout.strip() == "active"
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def snapshot_active_services() -> list[str]:
    """Return the subset of MANAGED_SERVICES currently active."""
    return [s for s in MANAGED_SERVICES if service_is_active(s)]


def _persist_stopped_services(names: list[str]) -> None:
    try:
        AUDIT_HOME.mkdir(parents=True, exist_ok=True)
        # Merge with any prior record so nested/repeated enables don't lose the
        # original set (union — we must restore everything we ever stopped).
        prior = _load_stopped_services()
        merged = sorted(set(prior) | set(names))
        SERVICES_STATE_FILE.write_text(json.dumps(merged), encoding="utf-8")
    except OSError as e:  # pragma: no cover - disk edge case
        logger.debug("Could not persist service state: %s", e)


def _load_stopped_services() -> list[str]:
    try:
        if SERVICES_STATE_FILE.exists():
            data = json.loads(SERVICES_STATE_FILE.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return [str(x) for x in data]
    except (OSError, ValueError):
        pass
    return []


def _clear_persisted_services() -> None:
    try:
        SERVICES_STATE_FILE.unlink(missing_ok=True)
    except OSError:  # pragma: no cover
        pass


def stop_conflicting_services() -> list[str]:
    """
    Stop the network services that hold the radio, recording exactly which ones
    were active so we can restore them symmetrically. Returns the list stopped.
    """
    active = snapshot_active_services()
    if not active:
        return []
    _say(f"[dim cyan]◈ Pausing network services: {', '.join(active)}[/]")
    for svc in active:
        try:
            subprocess.run(["systemctl", "stop", svc], capture_output=True, timeout=10)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
    _persist_stopped_services(active)
    return active


def restore_services(names: list[str] | None = None) -> list[str]:
    """
    Restart the services we previously stopped (from *names* or the persisted
    record) and clear the record. Returns the list restored.
    """
    to_start = names if names is not None else _load_stopped_services()
    if not to_start:
        _clear_persisted_services()
        return []
    _say(f"[dim cyan]◈ Restoring network services: {', '.join(to_start)}[/]")
    for svc in to_start:
        try:
            subprocess.run(["systemctl", "start", svc], capture_output=True, timeout=10)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
    _clear_persisted_services()
    return list(to_start)


def has_pending_restore() -> bool:
    """True if a previous (possibly crashed) run left services stopped."""
    return bool(_load_stopped_services())


# ══════════════════════════════════════════════════════════════════════════════
# Process management  (crash-safe child spawning + reaping)
# ══════════════════════════════════════════════════════════════════════════════

def terminate_process(proc: subprocess.Popen | None, grace: float = 3.0) -> None:
    """
    Gracefully stop a process **and its whole process group** (SIGTERM, then
    SIGKILL after *grace*). None-safe and already-dead-safe. On POSIX this reaps
    the entire session started by :func:`spawn`, so a wrapper like ``reaver`` or
    a shell can never leave a grandchild holding the card.
    """
    if proc is None or proc.poll() is not None:
        return

    def _signal_group(sig: int) -> bool:
        """Signal the process's whole group — but only when it *leads* its own
        group (i.e. it was spawned in a new session, as :func:`spawn` does).
        Signalling a group we don't lead would hit our own process, so in that
        case the caller falls back to a single-pid signal. Returns True if the
        group was signalled."""
        try:
            pgid = os.getpgid(proc.pid)
            if pgid == proc.pid:
                os.killpg(pgid, sig)
                return True
        except (ProcessLookupError, PermissionError, OSError):
            pass
        return False

    try:
        if os.name == "posix":
            if not _signal_group(signal.SIGTERM):
                proc.terminate()
        else:  # pragma: no cover - non-POSIX dev box
            proc.terminate()
    except Exception:  # pragma: no cover
        pass
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        try:
            if os.name == "posix":
                if not _signal_group(signal.SIGKILL):
                    proc.kill()
            else:  # pragma: no cover
                proc.kill()
        except Exception:  # pragma: no cover
            pass
        try:
            proc.wait(timeout=grace)
        except Exception:  # pragma: no cover
            pass


class ProcessSupervisor:
    """
    Central registry of long-lived child processes (airodump/reaver/hcxdumptool
    …). Spawns each in its own process group so a single ``terminate_all`` reaps
    the whole tree on Ctrl-C or crash — no orphan left holding the card in
    monitor mode.
    """

    def __init__(self) -> None:
        self._procs: list[subprocess.Popen] = []

    def spawn(self, cmd: list[str], **kwargs) -> subprocess.Popen:
        """Popen wrapper that starts a new session (process group) on POSIX."""
        if (os.name == "posix"
                and "start_new_session" not in kwargs
                and "preexec_fn" not in kwargs):
            kwargs["start_new_session"] = True
        proc = subprocess.Popen(cmd, **kwargs)
        self._procs.append(proc)
        return proc

    def register(self, proc: subprocess.Popen) -> subprocess.Popen:
        """Track an already-created Popen for later cleanup."""
        self._procs.append(proc)
        return proc

    def terminate_all(self, grace: float = 3.0) -> int:
        """Terminate every tracked process. Returns how many were still alive."""
        alive = [p for p in self._procs if p.poll() is None]
        for proc in alive:
            terminate_process(proc, grace)
        self._procs.clear()
        return len(alive)

    def reap(self) -> None:
        """Drop finished processes from the registry."""
        self._procs = [p for p in self._procs if p.poll() is None]

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len([p for p in self._procs if p.poll() is None])


# Process-wide supervisor used by the RF modules.
SUPERVISOR = ProcessSupervisor()


def spawn(cmd: list[str], *, supervise: bool = True, **kwargs) -> subprocess.Popen:
    """
    The one true way to launch a long-lived child in this codebase.

    Drop-in for ``subprocess.Popen(cmd, **kwargs)`` that (a) puts the child in
    its own session/process-group on POSIX so it can be group-killed, and
    (b) registers it with the global :data:`SUPERVISOR` so a crash or Ctrl-C
    reaps it even if the local cleanup path never runs. Pass ``supervise=False``
    for a child you promise to manage entirely yourself.
    """
    if supervise:
        return SUPERVISOR.spawn(cmd, **kwargs)
    if (os.name == "posix"
            and "start_new_session" not in kwargs
            and "preexec_fn" not in kwargs):
        kwargs["start_new_session"] = True
    return subprocess.Popen(cmd, **kwargs)


@contextmanager
def managed_process(cmd: list[str], *, grace: float = 3.0, **kwargs):
    """
    Context manager for a scoped child: spawn on enter, guaranteed group-kill on
    exit (normal, exception, or Ctrl-C). Replaces the error-prone
    ``Popen(...) / try / finally: terminate()`` boilerplate scattered across the
    attack modules.

        with radio.managed_process(["airodump-ng", ...]) as p:
            ...                      # p is reaped no matter how we leave
    """
    proc = spawn(cmd, **kwargs)
    try:
        yield proc
    finally:
        terminate_process(proc, grace)


# ══════════════════════════════════════════════════════════════════════════════
# airmon-ng output parsing  (pure)
# ══════════════════════════════════════════════════════════════════════════════

def parse_airmon_new_iface(output: str, original: str) -> str | None:
    """
    Parse the new monitor interface name from ``airmon-ng start`` output across
    the several phrasings shipped over the years.
    """
    # airmon-ng brackets the phy and appends the iface: "[phy0]wlan0". The
    # monitor iface is the one after "on [phyN]" — so the full "for … on …"
    # form must be tried before the bare "for X" form (which would otherwise
    # capture the *base* iface).
    patterns = [
        r"enabled for \[[\w-]+\][\w-]+ on \[[\w-]+\]([\w-]+)",  # [phy0]wlan0 on [phy0]wlan0mon
        r"enabled on \[[\w-]+\]([\w-]+)",                       # on [phy0]wlan0mon
        r"monitor mode (?:vif )?enabled on ([\w-]+)",           # enabled on wlan0mon / mon0
        r"monitor mode enabled for ([\w-]+)",                   # enabled for wlan0mon
        r"enabled on ([\w-]+mon)",
    ]
    for pat in patterns:
        m = re.search(pat, output, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return None


def base_matches_monitor(monitor_iface: str, requested: str) -> bool:
    """
    True if a monitor interface corresponds to the requested base interface.

    wlan0mon↔wlan0, wlan0↔wlan0, but wlan1mon✗wlan0.
    """
    if monitor_iface == requested:
        return True
    if monitor_iface == requested + "mon":
        return True
    if monitor_iface.endswith("mon") and monitor_iface[:-3] == requested:
        return True
    return False


# ══════════════════════════════════════════════════════════════════════════════
# Monitor enable / disable orchestrators
# ══════════════════════════════════════════════════════════════════════════════

def _enable_via_iw(interface: str) -> str | None:
    """
    Fallback monitor-mode path using ``ip`` + ``iw`` directly. Works on many
    drivers where airmon-ng's vif dance fails. The interface keeps its name.
    """
    steps = [
        ["ip", "link", "set", interface, "down"],
        ["iw", "dev", interface, "set", "type", "monitor"],
        ["ip", "link", "set", interface, "up"],
    ]
    for cmd in steps:
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logger.debug("iw-path step failed %s: %s", cmd, e)
            return None
        if res.returncode != 0:
            logger.debug("iw-path step rc=%s %s: %s", res.returncode, cmd, res.stderr)
            return None
    return interface if is_monitor(interface) else None


def _disable_via_iw(interface: str) -> bool:
    """Reverse of ``_enable_via_iw`` — restore a same-named iface to managed."""
    steps = [
        ["ip", "link", "set", interface, "down"],
        ["iw", "dev", interface, "set", "type", "managed"],
        ["ip", "link", "set", interface, "up"],
    ]
    ok = True
    for cmd in steps:
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            ok = ok and res.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            ok = False
    return ok


def enable_monitor(interface: str, method: str = "auto") -> str:
    """
    Bring *interface* into monitor mode reliably, returning the monitor iface
    name. Raises ``RuntimeError`` (with actionable diagnostics) on failure.

    Order of operations mirrors what a careful operator does by hand:
      1. require root
      2. reuse an already-matching monitor iface (idempotent)
      3. clear rfkill soft blocks / surface hard blocks
      4. snapshot + stop conflicting services (symmetric restore later)
      5. pick airmon-ng or the iw fallback (driver-quirk aware)
      6. verify via ``iw dev`` — trust nothing that isn't confirmed
    """
    if not _is_root():
        raise RuntimeError(
            "Root privileges required for monitor mode. Run: sudo wifi-auditor"
        )

    # (2) Idempotent reuse.
    for mon in wireless_interfaces("monitor"):
        if base_matches_monitor(mon, interface):
            _say(f"[dim green]◈ Monitor interface already active: [bold]{mon}[/bold][/]")
            return mon

    _say(f"\n[cyan]◈ Enabling monitor mode on [bold]{interface}[/bold]...[/]")

    # (3) rfkill.
    ok, msg = ensure_rfkill_unblocked()
    if not ok:
        raise RuntimeError(f"Cannot enable monitor mode: {msg}")

    # (4) Services (recorded for symmetric restore).
    stop_conflicting_services()
    # airmon-ng's own killer catches a couple of stragglers the unit files miss.
    if shutil.which("airmon-ng"):
        try:
            subprocess.run(
                ["airmon-ng", "check", "kill"], capture_output=True, timeout=30
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
    time.sleep(0.5)

    # (5) Choose method.
    driver = driver_of(interface)
    use_iw = method == "iw" or (
        method == "auto" and (prefers_iw(driver) or not shutil.which("airmon-ng"))
    )
    if driver:
        logger.debug("Driver for %s: %s (prefers_iw=%s)", interface, driver, prefers_iw(driver))

    new_iface: str | None = None
    diag = ""

    if not use_iw:
        _say(f"[dim cyan]◈ airmon-ng start {interface}...[/]")
        try:
            res = subprocess.run(
                ["airmon-ng", "start", interface],
                capture_output=True, text=True, timeout=30,
            )
            combined = res.stdout + res.stderr
            diag = combined
            new_iface = parse_airmon_new_iface(combined, interface)
            if not new_iface:
                for mon in wireless_interfaces("monitor"):
                    if base_matches_monitor(mon, interface):
                        new_iface = mon
                        break
            if not new_iface and is_monitor(interface):
                new_iface = interface
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            diag = f"airmon-ng error: {e}"

        # Verify airmon's claim; if it lied, fall through to the iw path.
        if new_iface and not is_monitor(new_iface):
            logger.debug("airmon-ng reported %s but it is not monitor; trying iw", new_iface)
            new_iface = None

    if not new_iface:
        _say(f"[dim cyan]◈ Falling back to iw monitor path on {interface}...[/]")
        new_iface = _enable_via_iw(interface)

    if not new_iface or not is_monitor(new_iface):
        raise RuntimeError(
            f"Failed to enable monitor mode on {interface}.\n"
            f"Driver: {driver or 'unknown'}\n"
            f"airmon-ng output:\n{diag or '(not run)'}\n"
            f"Interfaces now: {[ (i.name, i.type) for i in _iw_dev() ]}\n"
            f"Manual fix: sudo rfkill unblock wifi && sudo airmon-ng check kill && "
            f"sudo ip link set {interface} down && sudo iw dev {interface} set type "
            f"monitor && sudo ip link set {interface} up"
        )

    _say(f"[green]◈ Monitor mode enabled: [bold]{new_iface}[/bold] ✓[/]")
    return new_iface


def disable_monitor(monitor_interface: str) -> bool:
    """
    Restore *monitor_interface* to managed mode and symmetrically restart the
    services we stopped. Returns True on a confirmed managed state.
    """
    _say(f"[dim cyan]◈ Restoring {monitor_interface} to managed mode...[/]")
    restored_managed = False

    if shutil.which("airmon-ng") and monitor_interface.endswith("mon"):
        try:
            subprocess.run(
                ["airmon-ng", "stop", monitor_interface],
                capture_output=True, text=True, timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        # airmon-ng usually restores the base iface (wlan0mon → wlan0).
        base = monitor_interface[:-3]
        if interface_mode(base) == "managed":
            restored_managed = True
        elif interface_mode(monitor_interface) == "monitor":
            restored_managed = _disable_via_iw(monitor_interface)
    else:
        restored_managed = _disable_via_iw(monitor_interface)

    # Symmetric service restore (only what we stopped, from the persisted set).
    restore_services()
    _say("[dim green]  ✓ Interface restored[/]")
    return restored_managed


def check_injection_support(interface: str, timeout: int = 10) -> bool:
    """
    Confirm packet injection via ``aireplay-ng --test`` — the same gate
    airgeddon uses before attempting deauth.
    """
    _say(f"[dim cyan]◈ Testing injection on {interface}...[/]")
    try:
        res = subprocess.run(
            ["aireplay-ng", "--test", interface],
            capture_output=True, text=True, timeout=timeout,
        )
        if re.search(r"injection is working", res.stdout + res.stderr, re.IGNORECASE):
            _say("[dim green]  ✓ Injection supported[/]")
            return True
        _say("[dim red]  ✗ Injection test failed[/]")
        return False
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        _say("[dim yellow]  ? Injection test inconclusive[/]")
        return False

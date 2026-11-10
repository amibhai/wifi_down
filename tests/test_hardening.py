"""Regression tests for the hardening pass (branch: hardening/pass-1).

Each test pins a specific, previously-verified bug so it cannot silently return:

  * packaging build-backend actually exists (pip install / wheel build),
  * StateManager signal cleanup restores services + reaps children via radio
    (not a bare ``airmon-ng stop`` that strands networking),
  * ``--deauth-limit`` is threaded from headless mode into capture,
  * ``capture_handshake`` keeps its fast default so interactive capture is
    unchanged,
  * cap->hc22000 conversion never aliases its output onto the input path,
  * ``_spoof_mac`` genuinely falls back to macchanger on failure,
  * 5/6 GHz band labels are self-consistent.

All pure / monkeypatched — no RF, cross-platform (matches the suite's style).
"""
from __future__ import annotations

import importlib
import inspect
import pathlib
import re

import pytest

# ─────────────────────────────── packaging ──────────────────────────────────

def test_build_backend_is_importable():
    """The pyproject build-backend must be a real, importable module+object.

    Regression: ``setuptools.backends.legacy:build`` does not exist and broke
    ``pip install .`` / wheel builds entirely.
    """
    text = (pathlib.Path(__file__).parent.parent / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'(?m)^\s*build-backend\s*=\s*["\']([^"\']+)["\']', text)
    assert m, "no build-backend in pyproject.toml"
    backend = m.group(1)
    module_name = backend.split(":", 1)[0]
    mod = importlib.import_module(module_name)   # must not raise
    if ":" in backend:
        attr = backend.split(":", 1)[1]
        assert hasattr(mod, attr), f"{module_name} has no {attr!r}"


# ─────────────────────────── state cleanup (signals) ────────────────────────

def test_state_cleanup_restores_via_radio(monkeypatch, tmp_path):
    """Signal cleanup must reap RF children AND restore services symmetrically.

    Regression: the old ``_cleanup_interface`` ran a bare ``airmon-ng stop`` with
    no service restore / supervisor teardown, so a headless Ctrl-C could leave
    NetworkManager/iwd stopped and airodump orphaned.
    """
    from modules import radio
    from modules import state as state_mod

    monkeypatch.setattr(state_mod, "SESSIONS_DIR", tmp_path / "sessions")
    calls: list = []
    monkeypatch.setattr(radio.SUPERVISOR, "terminate_all",
                        lambda *a, **k: calls.append("terminate_all") or 0)
    monkeypatch.setattr(radio, "disable_monitor",
                        lambda iface: calls.append(("disable_monitor", iface)) or True)

    sm = state_mod.StateManager()
    sm.state.monitor_interface = "wlan0mon"
    sm._cleanup_interface()

    assert "terminate_all" in calls, "supervised children were not reaped"
    assert ("disable_monitor", "wlan0mon") in calls, "did not go through radio.disable_monitor"
    assert sm.state.monitor_interface is None


def test_state_cleanup_restores_pending_when_no_iface(monkeypatch, tmp_path):
    """With no monitor iface but a pending restore, services are still restored."""
    from modules import radio
    from modules import state as state_mod

    monkeypatch.setattr(state_mod, "SESSIONS_DIR", tmp_path / "sessions")
    calls: list = []
    monkeypatch.setattr(radio.SUPERVISOR, "terminate_all", lambda *a, **k: 0)
    monkeypatch.setattr(radio, "has_pending_restore", lambda: True)
    monkeypatch.setattr(radio, "restore_services",
                        lambda *a, **k: calls.append("restore_services") or [])

    sm = state_mod.StateManager()
    sm.state.monitor_interface = None
    sm._cleanup_interface()

    assert "restore_services" in calls


# ────────────────────────── deauth-limit threading ──────────────────────────

def test_capture_handshake_default_is_max():
    """Interactive capture is unchanged: default rate is the MAX burst cap."""
    from modules.handshake import capture_handshake
    from modules.ratelimit import MAX_ALLOWED_BURSTS_PER_MIN

    sig = inspect.signature(capture_handshake)
    assert "max_bursts_per_min" in sig.parameters
    assert sig.parameters["max_bursts_per_min"].default == MAX_ALLOWED_BURSTS_PER_MIN


def test_capture_handshake_threads_rate_to_limiter(monkeypatch):
    """The ``max_bursts_per_min`` argument must reach the DeauthRateLimiter.

    Regression: the rate limiter was hardcoded, so ``--deauth-limit`` had no
    effect on capture-time deauth.
    """
    from modules import handshake

    rec: dict = {}
    real = handshake.DeauthRateLimiter

    def spy(max_bursts_per_min):
        rec["value"] = max_bursts_per_min
        return real(max_bursts_per_min=max_bursts_per_min)

    monkeypatch.setattr(handshake, "DeauthRateLimiter", spy)
    monkeypatch.setattr(handshake, "_kill_interfering", lambda: None)
    monkeypatch.setattr(handshake, "_set_channel", lambda *a, **k: True)

    def _stop(*a, **k):
        raise RuntimeError("stop-here")

    monkeypatch.setattr(handshake, "_start_airodump_capture", _stop)

    with pytest.raises(RuntimeError, match="stop-here"):
        handshake.capture_handshake(
            bssid="AA:BB:CC:DD:EE:FF", ssid="x", channel=6,
            monitor_interface="wlan0mon", timeout=5,
            security="WPA2", band="2.4", max_bursts_per_min=7,
        )
    assert rec.get("value") == 7


def test_run_headless_passes_deauth_limit(monkeypatch):
    """``run_headless`` forwards ``--deauth-limit`` to capture_handshake."""
    from modules import radio, strategy, utils
    from wifi_auditor import cli

    target_bssid = "AA:BB:CC:DD:EE:FF"
    cap_kwargs: dict = {}

    class _FakeState:
        session_id = "TESTSESSION"
        result = None

    class _FakeSM:
        def __init__(self, *a, **k):
            self.state = _FakeState()

        def transition(self, *a, **k):
            pass

    monkeypatch.setattr(cli, "StateManager", _FakeSM)
    monkeypatch.setattr(utils, "setup_logging", lambda *a, **k: None)
    monkeypatch.setattr(cli, "get_wireless_interfaces", lambda: ["wlan0"])
    monkeypatch.setattr(cli, "enable_monitor_mode", lambda iface: "wlan0mon")
    monkeypatch.setattr(cli, "scan_networks", lambda *a, **k: [
        {"bssid": target_bssid, "ssid": "x", "channel": 6,
         "security_tier": "WPA2", "band": "2.4"},
    ])
    monkeypatch.setattr(cli._sequencer, "score_target", lambda t: None)
    monkeypatch.setattr(strategy, "build_auto_wordlist", lambda t: "wl.txt")

    def _fake_capture(**kwargs):
        cap_kwargs.update(kwargs)
        return "cap.cap"

    monkeypatch.setattr(cli, "capture_handshake", _fake_capture)
    monkeypatch.setattr(cli, "cracker_menu", lambda *a, **k: None)
    monkeypatch.setattr(cli, "disable_monitor_mode", lambda *a, **k: True)
    monkeypatch.setattr(radio.SUPERVISOR, "terminate_all", lambda *a, **k: 0)
    monkeypatch.setattr(radio, "is_monitor", lambda name: False)

    rc = cli.run_headless(target_bssid=target_bssid, iface="wlan0mon", deauth_limit=3)

    assert rc == 0
    assert cap_kwargs.get("max_bursts_per_min") == 3


# ──────────────────────── cap->hc22000 path safety ──────────────────────────

def test_convert_cap_never_aliases_output(monkeypatch, tmp_path):
    """Output path must differ from input even when the input isn't ``*.cap``.

    Regression: ``cap_file.replace(".cap", ...)`` could equal the input and let
    hcxpcapngtool overwrite the capture.
    """
    from modules import cracker

    monkeypatch.setattr(cracker.shutil, "which", lambda name: "/usr/bin/" + name)
    captured: dict = {}

    class _R:
        returncode = 0
        stderr = ""

    def _fake_run(cmd, **kw):
        captured["out"] = cmd[2]
        captured["in"] = cmd[3]
        pathlib.Path(cmd[2]).write_text("WPA*02*deadbeef\n", encoding="utf-8")
        return _R()

    monkeypatch.setattr(cracker.subprocess, "run", _fake_run)

    src = tmp_path / "capture.pcap"          # deliberately NOT ".cap"
    src.write_bytes(b"x" * 400)
    out = cracker._convert_cap_to_hc22000(str(src))

    assert captured["out"] != captured["in"], "conversion aliased output onto input"
    assert out is not None and out.endswith(".hc22000")


# ──────────────────────────── MAC spoof fallback ────────────────────────────

def test_spoof_mac_falls_back_to_macchanger(monkeypatch):
    """A rejected ``ip link set address`` must trigger the macchanger fallback.

    Regression: no returncode check meant the fallback never ran and failure was
    reported as success.
    """
    from modules import deauth

    calls: list = []

    class _R:
        def __init__(self, rc):
            self.returncode = rc
            self.stdout = ""

    def _fake_run(cmd, **kw):
        calls.append(cmd[0])
        if cmd[0] == "ip":
            return _R(1 if "address" in cmd else 0)   # the address set is rejected
        if cmd[0] == "macchanger":
            return _R(0)
        return _R(0)

    monkeypatch.setattr(deauth.subprocess, "run", _fake_run)
    monkeypatch.setattr(deauth, "_get_interface_mac", lambda i: "00:11:22:33:44:55")

    ok = deauth._spoof_mac("wlan0", "AA:BB:CC:DD:EE:FF")

    assert "macchanger" in calls, "fallback to macchanger was not attempted"
    assert ok is True


# ───────────────────────── band-label consistency ───────────────────────────

def test_band_labels_self_consistent():
    """channel_to_freq / freq_to_band / band_of_channel agree around 5/6 GHz."""
    from modules import radio

    for ch in (1, 6, 36, 100, 149, 165, 177):
        f5 = radio.channel_to_freq(ch, "5")
        if f5 is not None:
            assert radio.freq_to_band(f5) == "5", f"ch{ch} -> {f5} mislabeled"

    # Above the real 5 GHz max there is no 5 GHz frequency (6 GHz starts 5925).
    assert radio.channel_to_freq(181, "5") is None
    assert radio.band_of_channel(165) == "5"
    assert radio.band_of_channel(181) == "6"
    # 6 GHz still resolves and is labeled 6.
    assert radio.freq_to_band(radio.channel_to_freq(37, "6")) == "6"

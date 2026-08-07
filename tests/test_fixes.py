"""Regression tests for the v0.8.x bug-fix pass.

Each test pins a specific bug that was fixed so it cannot silently return:
  • cracker._hashcat_result read the disabled potfile → key never found
  • cracker_menu mis-routed PMKID .hc22000 files to the WPA .cap path
  • deauth continuous mode spawned infinite (--deauth 0) processes forever
  • wep airodump used --ivs, which suppresses the .cap the pipeline cracks
  • sequencer.score_target crashed on integer `power` values
"""
from __future__ import annotations

import threading
from pathlib import Path
from unittest import mock

import pytest


# ── cracker: hashcat result comes from the --outfile, not the potfile ────────

def test_hashcat_result_reads_outfile(tmp_path: Path):
    from modules.cracker import _hashcat_result
    out = tmp_path / "cracked.txt"
    out.write_text("hunter2\n")
    assert _hashcat_result(str(out)) == "hunter2"


def test_hashcat_result_missing_file_returns_none(tmp_path: Path):
    from modules.cracker import _hashcat_result
    assert _hashcat_result(str(tmp_path / "nope.txt")) is None


def test_hashcat_result_empty_file_returns_none(tmp_path: Path):
    from modules.cracker import _hashcat_result
    out = tmp_path / "empty.txt"
    out.write_text("")
    assert _hashcat_result(str(out)) is None


# ── cracker: a PMKID/hashcat hash file routes to the hashcat PMKID cracker ────

@pytest.mark.parametrize("name", ["cap.hc22000", "cap.22000", "cap.16800"])
def test_cracker_routes_hash_files_to_pmkid(name, tmp_path: Path):
    from modules import cracker
    hash_file = tmp_path / name
    hash_file.write_text("WPA*01*deadbeef\n")
    wl = tmp_path / "wl.txt"
    wl.write_text("password\n")
    with mock.patch.object(cracker, "_crack_pmkid_menu") as pmkid, \
         mock.patch.object(cracker, "_run_aircrack") as aircrack:
        cracker.cracker_menu(str(hash_file), str(wl))
    pmkid.assert_called_once()
    aircrack.assert_not_called()


# ── deauth: continuous mode sends finite bursts (never --deauth 0) ───────────

def test_deauth_continuous_uses_finite_bursts(monkeypatch):
    import modules.deauth as d

    launched: list[list[str]] = []

    def fake_popen(cmd, **kwargs):
        launched.append(cmd)
        raise KeyboardInterrupt  # break out of the infinite while-loop

    monkeypatch.setattr(d.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(d, "_draw_stats", lambda *a, **k: None)

    class FakeLimiter:
        _max_bursts = 5
        def wait_for_burst(self, *a):
            pass
        def record_frame(self):
            return True

    d._run_continuous(
        "wlan0mon", "AA:BB:CC:DD:EE:FF", ["11:22:33:44:55:66"],
        burst_count=64, procs=[],
        stats={"11:22:33:44:55:66": {"packets": 0, "acks": 0}},
        lock=threading.Lock(), reader=lambda p, m: None, limiter=FakeLimiter(),
    )

    assert launched, "no aireplay-ng process was launched"
    cmd = launched[0]
    count = cmd[cmd.index("--deauth") + 1]
    assert count != "0", "continuous mode must not use infinite --deauth 0"
    assert count == "64"


# ── wep: airodump must not use --ivs (it hides the crackable .cap) ───────────

def test_wep_airodump_has_no_ivs_flag(monkeypatch):
    import modules.wep as wep
    captured: dict = {}

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = cmd
        return mock.Mock()

    monkeypatch.setattr(wep.subprocess, "Popen", fake_popen)
    wep._start_airodump_wep("wlan0mon", "AA:BB:CC:DD:EE:FF", 6, "captures/x")
    assert "--ivs" not in captured["cmd"]
    assert "cap,csv" in captured["cmd"]


# ── sequencer: integer power must not crash score_target ─────────────────────

@pytest.mark.parametrize("power", [-65, "-70", "", None, "garbage"])
def test_sequencer_accepts_any_power_type(power):
    from modules.sequencer import AttackSequencer
    with mock.patch.object(AttackSequencer, "display_plan", lambda self, p: None):
        plan = AttackSequencer().score_target({
            "bssid": "AA:BB:CC:DD:EE:FF", "ssid": "Net",
            "privacy": "WPA2", "power": power, "client_count": 1,
        })
    assert plan.steps

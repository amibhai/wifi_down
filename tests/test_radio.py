"""
Unit tests for modules/radio.py — the reliability core.

Pure-logic first (band math, rfkill/iw/ethtool parsers, driver quirks,
airmon output parsing), then behaviour tests for the persisted service
save/restore and the ProcessSupervisor. Zero RF, cross-platform.
"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from modules import radio


# ══════════════════════════════════════════════════════════════════════════════
# Band / channel math
# ══════════════════════════════════════════════════════════════════════════════

class TestBandMath:
    def test_freq_to_band_24(self):
        assert radio.freq_to_band(2412) == "2.4"
        assert radio.freq_to_band(2484) == "2.4"

    def test_freq_to_band_5(self):
        assert radio.freq_to_band(5180) == "5"
        assert radio.freq_to_band(5825) == "5"

    def test_freq_to_band_6(self):
        assert radio.freq_to_band(5955) == "6"
        assert radio.freq_to_band(6415) == "6"

    def test_channel_to_freq_24(self):
        assert radio.channel_to_freq(1) == 2412
        assert radio.channel_to_freq(6) == 2437
        assert radio.channel_to_freq(11) == 2462
        assert radio.channel_to_freq(13) == 2472
        assert radio.channel_to_freq(14) == 2484

    def test_channel_to_freq_5(self):
        assert radio.channel_to_freq(36) == 5180
        assert radio.channel_to_freq(149) == 5745
        assert radio.channel_to_freq(165) == 5825

    def test_channel_to_freq_6(self):
        # 6 GHz needs a band hint since ch 1..14 also exist at 2.4.
        assert radio.channel_to_freq(1, band="6") == 5955
        assert radio.channel_to_freq(2, band="6") == 5935  # the special anchor
        assert radio.channel_to_freq(37, band="6") == 6135

    def test_channel_to_freq_invalid(self):
        assert radio.channel_to_freq(99, band="2.4") is None
        assert radio.channel_to_freq(0, band="5") is None
        assert radio.channel_to_freq(999) is None

    def test_channel_to_freq_default_band_inference(self):
        assert radio.channel_to_freq(6) == 2437          # ≤14 → 2.4
        assert radio.channel_to_freq(36) == 5180         # ≤196 → 5
        assert radio.channel_to_freq(200) == radio.channel_to_freq(200, band="6")

    def test_band_of_channel(self):
        assert radio.band_of_channel(6) == "2.4"
        assert radio.band_of_channel(36) == "5"
        assert radio.band_of_channel(200) == "6"


# ══════════════════════════════════════════════════════════════════════════════
# rfkill parsing
# ══════════════════════════════════════════════════════════════════════════════

class TestRfkillJson:
    def test_newer_key(self):
        text = json.dumps({"rfkilldevices": [
            {"id": 0, "type": "wlan", "device": "phy0", "soft": "unblocked", "hard": "unblocked"},
            {"id": 1, "type": "bluetooth", "device": "hci0", "soft": "blocked", "hard": "unblocked"},
        ]})
        entries = radio.parse_rfkill_json(text)
        assert len(entries) == 2
        assert entries[0].type == "wlan"
        assert entries[0].soft_blocked is False
        assert entries[1].type == "bluetooth"
        assert entries[1].soft_blocked is True

    def test_older_empty_key(self):
        text = json.dumps({"": [
            {"id": 0, "type": "wlan", "device": "phy0", "soft": "blocked", "hard": "blocked"},
        ]})
        entries = radio.parse_rfkill_json(text)
        assert len(entries) == 1
        assert entries[0].soft_blocked and entries[0].hard_blocked

    def test_malformed_returns_empty(self):
        assert radio.parse_rfkill_json("not json") == []
        assert radio.parse_rfkill_json("") == []


class TestRfkillText:
    SAMPLE = (
        "0: phy0: Wireless LAN\n"
        "\tSoft blocked: yes\n"
        "\tHard blocked: no\n"
        "1: hci0: Bluetooth\n"
        "\tSoft blocked: no\n"
        "\tHard blocked: no\n"
    )

    def test_block_form(self):
        entries = radio.parse_rfkill_text(self.SAMPLE)
        assert len(entries) == 2
        wlan = entries[0]
        assert wlan.id == 0
        assert wlan.type == "wlan"
        assert wlan.soft_blocked is True
        assert wlan.hard_blocked is False
        assert entries[1].type == "bluetooth"

    def test_hard_blocked(self):
        text = "0: phy0: Wireless LAN\n\tSoft blocked: no\n\tHard blocked: yes\n"
        entries = radio.parse_rfkill_text(text)
        assert entries[0].hard_blocked is True

    def test_empty(self):
        assert radio.parse_rfkill_text("") == []


class TestWifiRfkillState:
    def _mk(self, typ, soft, hard, rid=0):
        return radio.RfkillEntry(id=rid, type=typ, device="phy0",
                                 soft_blocked=soft, hard_blocked=hard)

    def test_clean(self):
        st = radio.wifi_rfkill_state([self._mk("wlan", False, False)])
        assert st.any_wifi and not st.soft_blocked_ids and not st.hard_blocked

    def test_soft_blocked_ids(self):
        st = radio.wifi_rfkill_state([self._mk("wlan", True, False, rid=3)])
        assert st.soft_blocked_ids == [3]

    def test_hard_blocked(self):
        st = radio.wifi_rfkill_state([self._mk("wlan", False, True)])
        assert st.hard_blocked is True

    def test_ignores_bluetooth(self):
        st = radio.wifi_rfkill_state([self._mk("bluetooth", True, True)])
        assert not st.any_wifi and not st.hard_blocked


class TestEnsureRfkillUnblocked:
    def test_no_wifi_radio(self, monkeypatch):
        monkeypatch.setattr(radio, "_read_rfkill", lambda: [])
        ok, msg = radio.ensure_rfkill_unblocked()
        assert ok is True

    def test_hard_block_is_unfixable(self, monkeypatch):
        entry = radio.RfkillEntry(0, "wlan", "phy0", soft_blocked=False, hard_blocked=True)
        monkeypatch.setattr(radio, "_read_rfkill", lambda: [entry])
        ok, msg = radio.ensure_rfkill_unblocked()
        assert ok is False
        assert "HARD" in msg

    def test_soft_block_cleared(self, monkeypatch):
        blocked = radio.RfkillEntry(0, "wlan", "phy0", soft_blocked=True, hard_blocked=False)
        clear = radio.RfkillEntry(0, "wlan", "phy0", soft_blocked=False, hard_blocked=False)
        seq = [[blocked], [clear]]
        monkeypatch.setattr(radio, "_read_rfkill", lambda: seq.pop(0))
        monkeypatch.setattr(radio.subprocess, "run", lambda *a, **k: None)
        ok, msg = radio.ensure_rfkill_unblocked()
        assert ok is True


# ══════════════════════════════════════════════════════════════════════════════
# iw dev parsing
# ══════════════════════════════════════════════════════════════════════════════

class TestParseIwDev:
    SAMPLE = (
        "phy#1\n"
        "\tInterface wlan1mon\n"
        "\t\tifindex 5\n"
        "\t\taddr 00:11:22:33:44:55\n"
        "\t\ttype monitor\n"
        "\t\tchannel 36 (5180 MHz)\n"
        "phy#0\n"
        "\tInterface wlan0\n"
        "\t\taddr aa:bb:cc:dd:ee:ff\n"
        "\t\ttype managed\n"
    )

    def test_parses_two(self):
        ifaces = radio.parse_iw_dev(self.SAMPLE)
        assert [i.name for i in ifaces] == ["wlan1mon", "wlan0"]

    def test_types_and_phy(self):
        ifaces = radio.parse_iw_dev(self.SAMPLE)
        mon = ifaces[0]
        assert mon.type == "monitor"
        assert mon.phy == "phy1"
        assert mon.channel == 36
        assert mon.addr == "00:11:22:33:44:55"
        assert ifaces[1].type == "managed"

    def test_empty(self):
        assert radio.parse_iw_dev("") == []

    def test_wireless_interfaces_filter(self, monkeypatch):
        parsed = radio.parse_iw_dev(self.SAMPLE)
        monkeypatch.setattr(radio, "_iw_dev", lambda: parsed)
        assert radio.wireless_interfaces() == ["wlan1mon", "wlan0"]
        assert radio.wireless_interfaces("monitor") == ["wlan1mon"]
        assert radio.wireless_interfaces("managed") == ["wlan0"]
        assert radio.is_monitor("wlan1mon") is True
        assert radio.is_monitor("wlan0") is False
        assert radio.interface_mode("nope") is None


# ══════════════════════════════════════════════════════════════════════════════
# Driver detection + quirks
# ══════════════════════════════════════════════════════════════════════════════

class TestDriverQuirks:
    def test_parse_ethtool(self):
        out = "driver: rtl88x2bu\nversion: 5.13.1\nfirmware-version: N/A\n"
        assert radio.parse_ethtool_driver(out) == "rtl88x2bu"

    def test_parse_ethtool_none(self):
        assert radio.parse_ethtool_driver("bus-info: usb-0000:00:14.0-1") == ""

    def test_normalize(self):
        assert radio.normalize_driver("RTL-8812_AU v5") == "rtl8812auv5"

    @pytest.mark.parametrize("drv", [
        "rtl8812au", "88XXau", "rtl88x2bu", "8814au", "rtl8821cu", "rtl8812au_v5",
    ])
    def test_prefers_iw_true(self, drv):
        assert radio.prefers_iw(drv) is True

    @pytest.mark.parametrize("drv", ["iwlwifi", "ath9k_htc", "mt7601u", "", "brcmfmac"])
    def test_prefers_iw_false(self, drv):
        assert radio.prefers_iw(drv) is False


# ══════════════════════════════════════════════════════════════════════════════
# airmon-ng output parsing
# ══════════════════════════════════════════════════════════════════════════════

class TestAirmonParse:
    @pytest.mark.parametrize("out,expect", [
        ("(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)", "wlan0mon"),
        ("monitor mode vif enabled on wlan0mon", "wlan0mon"),
        ("monitor mode enabled for wlan0mon", "wlan0mon"),
        ("monitor mode enabled on wlan0mon", "wlan0mon"),
    ])
    def test_variants(self, out, expect):
        assert radio.parse_airmon_new_iface(out, "wlan0") == expect

    def test_none(self):
        assert radio.parse_airmon_new_iface("nothing useful here", "wlan0") is None

    def test_base_matches(self):
        assert radio.base_matches_monitor("wlan0mon", "wlan0") is True
        assert radio.base_matches_monitor("wlan0", "wlan0") is True
        assert radio.base_matches_monitor("wlan1mon", "wlan0") is False


# ══════════════════════════════════════════════════════════════════════════════
# Service save / restore (persisted, symmetric)
# ══════════════════════════════════════════════════════════════════════════════

class TestServiceStateFile:
    @pytest.fixture(autouse=True)
    def _tmp_state(self, tmp_path, monkeypatch):
        monkeypatch.setattr(radio, "AUDIT_HOME", tmp_path)
        monkeypatch.setattr(radio, "SERVICES_STATE_FILE", tmp_path / "services_state.json")

    def test_persist_and_load(self):
        radio._persist_stopped_services(["NetworkManager", "wpa_supplicant"])
        assert set(radio._load_stopped_services()) == {"NetworkManager", "wpa_supplicant"}

    def test_persist_unions(self):
        radio._persist_stopped_services(["NetworkManager"])
        radio._persist_stopped_services(["iwd"])
        assert set(radio._load_stopped_services()) == {"NetworkManager", "iwd"}

    def test_has_pending_restore(self):
        assert radio.has_pending_restore() is False
        radio._persist_stopped_services(["iwd"])
        assert radio.has_pending_restore() is True

    def test_restore_clears_file(self, monkeypatch):
        started = []
        monkeypatch.setattr(radio.subprocess, "run",
                            lambda cmd, **k: started.append(cmd[-1]))
        radio._persist_stopped_services(["NetworkManager", "iwd"])
        restored = radio.restore_services()
        assert set(restored) == {"NetworkManager", "iwd"}
        assert set(started) == {"NetworkManager", "iwd"}
        assert radio.has_pending_restore() is False  # file removed

    def test_restore_noop_when_empty(self):
        assert radio.restore_services() == []

    def test_stop_only_active(self, monkeypatch):
        active = {"NetworkManager", "dhcpcd"}
        monkeypatch.setattr(radio, "service_is_active", lambda s: s in active)
        stopped_cmds = []
        monkeypatch.setattr(radio.subprocess, "run",
                            lambda cmd, **k: stopped_cmds.append(cmd))
        stopped = radio.stop_conflicting_services()
        assert set(stopped) == active
        # persisted for a later symmetric restore
        assert set(radio._load_stopped_services()) == active


class TestServiceIsActive:
    def test_active(self, monkeypatch):
        monkeypatch.setattr(radio.shutil, "which", lambda x: "/usr/bin/systemctl")
        monkeypatch.setattr(radio.subprocess, "run",
                            lambda *a, **k: subprocess.CompletedProcess(a, 0, "active\n", ""))
        assert radio.service_is_active("NetworkManager") is True

    def test_inactive(self, monkeypatch):
        monkeypatch.setattr(radio.shutil, "which", lambda x: "/usr/bin/systemctl")
        monkeypatch.setattr(radio.subprocess, "run",
                            lambda *a, **k: subprocess.CompletedProcess(a, 3, "inactive\n", ""))
        assert radio.service_is_active("NetworkManager") is False

    def test_no_systemctl(self, monkeypatch):
        monkeypatch.setattr(radio.shutil, "which", lambda x: None)
        assert radio.service_is_active("NetworkManager") is False


# ══════════════════════════════════════════════════════════════════════════════
# ProcessSupervisor (real child processes, cross-platform)
# ══════════════════════════════════════════════════════════════════════════════

class TestProcessSupervisor:
    def _sleeper(self, sup):
        return sup.spawn([sys.executable, "-c", "import time; time.sleep(30)"])

    def test_spawn_and_terminate(self):
        sup = radio.ProcessSupervisor()
        p1 = self._sleeper(sup)
        p2 = self._sleeper(sup)
        assert len(sup) == 2
        still_alive = sup.terminate_all(grace=5.0)
        assert still_alive == 2                 # both were running when reaped
        assert p1.poll() is not None
        assert p2.poll() is not None
        assert len(sup) == 0

    def test_reap_drops_finished(self):
        sup = radio.ProcessSupervisor()
        p = sup.spawn([sys.executable, "-c", "pass"])
        p.wait(timeout=10)
        sup.reap()
        assert len(sup) == 0

    def test_register(self):
        sup = radio.ProcessSupervisor()
        p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        sup.register(p)
        assert len(sup) == 1
        sup.terminate_all(grace=5.0)
        assert p.poll() is not None

    def test_terminate_all_empty(self):
        sup = radio.ProcessSupervisor()
        assert sup.terminate_all() == 0

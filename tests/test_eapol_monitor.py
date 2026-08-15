"""Unit tests for modules/eapol_monitor.py — pure logic, zero RF required."""
from __future__ import annotations

import pytest

from modules.eapol_monitor import (
    classify_eapol,
    is_crackable,
    pmkid_from_m1,
    client_from_data_frame,
    _is_station_mac,
    _parse_station_csv,
    KI_ACK, KI_MIC, KI_INSTALL, KI_SECURE, KI_PAIRWISE,
)

# Canonical Key Information values for the four handshake messages
M1 = KI_ACK | KI_PAIRWISE
M2 = KI_MIC | KI_PAIRWISE
M3 = KI_MIC | KI_ACK | KI_INSTALL | KI_SECURE | KI_PAIRWISE
M4 = KI_MIC | KI_SECURE | KI_PAIRWISE

BSSID = "AA:BB:CC:DD:EE:FF"
STA   = "10:22:33:44:55:66"      # 0x10 even → unicast


# ── classify_eapol ────────────────────────────────────────────────────────────

class TestClassifyEapol:
    def test_m1(self):
        assert classify_eapol(M1) == 1

    def test_m2(self):
        assert classify_eapol(M2) == 2

    def test_m3(self):
        assert classify_eapol(M3) == 3

    def test_m4(self):
        assert classify_eapol(M4) == 4

    def test_group_rekey_not_classified_as_4way(self):
        # Group Key Handshake msg 1: ACK+MIC+Secure, no Install → not a pairwise message
        assert classify_eapol(KI_ACK | KI_MIC | KI_SECURE) == 0

    def test_empty_is_unknown(self):
        assert classify_eapol(0x0000) == 0


# ── is_crackable ──────────────────────────────────────────────────────────────

class TestIsCrackable:
    def test_m1_m2_same_replay(self):
        assert is_crackable({5: {1, 2}}) is True

    def test_m2_then_m3_next_replay(self):
        assert is_crackable({5: {2}, 6: {3}}) is True

    def test_m1_then_m2_next_replay(self):
        assert is_crackable({5: {1}, 6: {2}}) is True

    def test_both_in_one_bucket(self):
        assert is_crackable({7: {2, 3}}) is True

    def test_m1_only_not_crackable(self):
        assert is_crackable({5: {1}}) is False

    def test_m3_m4_not_sufficient(self):
        assert is_crackable({5: {3, 4}}) is False

    def test_empty(self):
        assert is_crackable({}) is False


# ── pmkid_from_m1 ─────────────────────────────────────────────────────────────

class TestPmkidFromM1:
    def _kde(self, pmkid: bytes) -> bytes:
        return b"\xdd" + bytes([4 + len(pmkid)]) + b"\x00\x0f\xac\x04" + pmkid

    def test_valid_pmkid(self):
        pmkid = bytes(range(1, 17))
        assert pmkid_from_m1(self._kde(pmkid)) == pmkid.hex()

    def test_all_zero_pmkid_ignored(self):
        assert pmkid_from_m1(self._kde(b"\x00" * 16)) is None

    def test_empty_key_data(self):
        assert pmkid_from_m1(b"") is None

    def test_non_pmkid_kde(self):
        # RSN KDE with a different data type (0x02 = GTK) → no PMKID
        other = b"\xdd\x16\x00\x0f\xac\x02" + b"\x11" * 16
        assert pmkid_from_m1(other) is None


# ── client_from_data_frame + _is_station_mac ─────────────────────────────────

class TestClientFromDataFrame:
    def test_to_ds_client_is_addr2(self):
        assert client_from_data_frame(True, False, BSSID, STA, "AA:BB:CC:00:00:01", BSSID) == STA

    def test_from_ds_client_is_addr1(self):
        assert client_from_data_frame(False, True, STA, BSSID, BSSID, BSSID) == STA

    def test_bssid_itself_rejected(self):
        assert client_from_data_frame(True, False, BSSID, BSSID, BSSID, BSSID) is None

    def test_broadcast_rejected(self):
        assert client_from_data_frame(True, False, BSSID, "FF:FF:FF:FF:FF:FF", BSSID, BSSID) is None

    def test_multicast_ig_bit_rejected(self):
        assert client_from_data_frame(True, False, BSSID, "01:00:5E:00:00:01", BSSID, BSSID) is None

    def test_wds_frame_skipped(self):
        assert client_from_data_frame(True, True, BSSID, STA, BSSID, BSSID) is None

    def test_ibss_frame_skipped(self):
        assert client_from_data_frame(False, False, STA, BSSID, BSSID, BSSID) is None

    def test_is_station_mac(self):
        assert _is_station_mac(STA, BSSID) is True
        assert _is_station_mac(BSSID, BSSID) is False
        assert _is_station_mac("01:00:5E:00:00:01", BSSID) is False  # I/G set
        assert _is_station_mac(None, BSSID) is False


# ── _parse_station_csv ────────────────────────────────────────────────────────

class TestParseStationCsv:
    def test_parses_associated_clients(self, tmp_path):
        csv = tmp_path / "s-01.csv"
        csv.write_text(
            "BSSID, First, Last, channel, Speed, Privacy, Cipher, Auth, Power, beacons, IV, IP, IDlen, ESSID, Key\n"
            "AA:BB:CC:DD:EE:FF, x, x, 6, 54, WPA2, CCMP, PSK, -40, 100, 0, 0.0.0.0, 8, Net, \n"
            "\n"
            "Station MAC, First, Last, Power, packets, BSSID, Probed\n"
            "10:22:33:44:55:66, x, x, -55, 100, AA:BB:CC:DD:EE:FF, Net\n"
            "20:22:33:44:55:66, x, x, -70, 30, 00:11:22:33:44:55, Other\n"
        )
        out = _parse_station_csv(str(csv), BSSID)
        assert "10:22:33:44:55:66" in out
        assert out["10:22:33:44:55:66"]["power"] == -55
        assert "20:22:33:44:55:66" not in out          # different AP

    def test_missing_file(self):
        assert _parse_station_csv("/nope/x.csv", BSSID) == {}

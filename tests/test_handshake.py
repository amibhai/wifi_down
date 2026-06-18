"""Tests for modules/handshake.py and modules/client_scanner.py"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.client_scanner import _parse_airodump_csv, WifiClient


class TestCSVParsing:
    """Bug 4+5+6 regression tests."""

    def test_null_bytes_stripped(self, tmp_path):
        csv_content = (
            "BSSID, First time seen, Last time seen, channel, Speed,"
            " Privacy, Cipher, Authentication, Power, # beacons,"
            " # IV, LAN IP, ID-length, ESSID, Key\r\n"
            "AA:BB:CC:11:22:33, 2024-01-01 00:00:00, 2024-01-01 00:00:01,"
            " 6, 54, WPA2, CCMP, PSK, -50, 10, 0,  , 4, TestAP, \r\n"
            "\r\n"
            "Station MAC, First time seen, Last time seen,"
            " Power, # packets, BSSID, Probed ESSIDs\r\n"
            "FF:EE:DD:33:22:11\x00, 2024-01-01 00:00:00,"
            " 2024-01-01 00:00:01, -65, 42,"
            " AA:BB:CC:11:22:33, TestAP\r\n"
        )
        f = tmp_path / "test-01.csv"
        f.write_bytes(csv_content.encode())
        clients = _parse_airodump_csv(str(f), "AA:BB:CC:11:22:33")
        assert len(clients) == 1
        assert clients[0].mac == "FF:EE:DD:33:22:11"  # null byte stripped

    def test_not_associated_filtered(self, tmp_path):
        csv_content = (
            "BSSID, First time seen\r\n\r\n"
            "Station MAC, First time seen, Last time seen,"
            " Power, # packets, BSSID, Probed ESSIDs\r\n"
            "FF:EE:DD:33:22:11, 2024-01-01, 2024-01-01,"
            " -70, 5, (not associated), \r\n"
        )
        f = tmp_path / "test-01.csv"
        f.write_bytes(csv_content.encode())
        clients = _parse_airodump_csv(str(f), "AA:BB:CC:11:22:33")
        assert len(clients) == 0  # not associated must be filtered

    def test_wrong_bssid_filtered(self, tmp_path):
        csv_content = (
            "BSSID, First time seen\r\n\r\n"
            "Station MAC, First time seen, Last time seen,"
            " Power, # packets, BSSID, Probed ESSIDs\r\n"
            "FF:EE:DD:33:22:11, 2024-01-01, 2024-01-01,"
            " -60, 8, 00:11:22:33:44:55, \r\n"
        )
        f = tmp_path / "test-01.csv"
        f.write_bytes(csv_content.encode())
        clients = _parse_airodump_csv(str(f), "AA:BB:CC:11:22:33")
        assert len(clients) == 0

    def test_first_client_not_dropped(self, tmp_path):
        """Bug 5 regression: first client row must NOT be skipped."""
        csv_content = (
            "BSSID, First time seen\r\n\r\n"
            "Station MAC, First time seen, Last time seen,"
            " Power, # packets, BSSID, Probed ESSIDs\r\n"
            "AA:AA:AA:AA:AA:01, 2024-01-01, 2024-01-01,"
            " -55, 10, AA:BB:CC:11:22:33, TestAP\r\n"
            "BB:BB:BB:BB:BB:02, 2024-01-01, 2024-01-01,"
            " -70, 5, AA:BB:CC:11:22:33, TestAP\r\n"
        )
        f = tmp_path / "test-01.csv"
        f.write_bytes(csv_content.encode())
        clients = _parse_airodump_csv(str(f), "AA:BB:CC:11:22:33")
        assert len(clients) == 2
        # Sorted by signal: -55 first (stronger)
        assert clients[0].mac == "AA:AA:AA:AA:AA:01"

    def test_whitespace_stripped_from_bssid(self, tmp_path):
        """Bug 6 regression: spaces around BSSID must be stripped."""
        csv_content = (
            "BSSID, First time seen\r\n\r\n"
            "Station MAC, First time seen, Last time seen,"
            " Power, # packets, BSSID, Probed ESSIDs\r\n"
            "FF:EE:DD:33:22:11, 2024-01-01, 2024-01-01,"
            " -60, 8,  AA:BB:CC:11:22:33 , TestAP\r\n"  # spaces around BSSID
        )
        f = tmp_path / "test-01.csv"
        f.write_bytes(csv_content.encode())
        clients = _parse_airodump_csv(str(f), "AA:BB:CC:11:22:33")
        assert len(clients) == 1

    def test_missing_file_returns_empty(self, tmp_path):
        clients = _parse_airodump_csv(str(tmp_path / "nonexistent.csv"), "AA:BB:CC:11:22:33")
        assert clients == []

    def test_duplicate_macs_deduplicated(self, tmp_path):
        """Duplicate MACs from CSV re-writes must be collapsed to one entry."""
        csv_content = (
            "BSSID, First time seen\r\n\r\n"
            "Station MAC, First time seen, Last time seen,"
            " Power, # packets, BSSID, Probed ESSIDs\r\n"
            "AA:AA:AA:AA:AA:01, 2024-01-01, 2024-01-01,"
            " -55, 10, AA:BB:CC:11:22:33, TestAP\r\n"
            "AA:AA:AA:AA:AA:01, 2024-01-01, 2024-01-01,"
            " -55, 20, AA:BB:CC:11:22:33, TestAP\r\n"
        )
        f = tmp_path / "test-01.csv"
        f.write_bytes(csv_content.encode())
        clients = _parse_airodump_csv(str(f), "AA:BB:CC:11:22:33")
        assert len(clients) == 1

    def test_sorted_strongest_first(self, tmp_path):
        """Clients should be sorted by signal strength, strongest first."""
        csv_content = (
            "BSSID, First time seen\r\n\r\n"
            "Station MAC, First time seen, Last time seen,"
            " Power, # packets, BSSID, Probed ESSIDs\r\n"
            "AA:AA:AA:AA:AA:01, 2024-01-01, 2024-01-01,"
            " -80, 5, AA:BB:CC:11:22:33, TestAP\r\n"
            "BB:BB:BB:BB:BB:02, 2024-01-01, 2024-01-01,"
            " -45, 8, AA:BB:CC:11:22:33, TestAP\r\n"
        )
        f = tmp_path / "test-01.csv"
        f.write_bytes(csv_content.encode())
        clients = _parse_airodump_csv(str(f), "AA:BB:CC:11:22:33")
        assert clients[0].mac == "BB:BB:BB:BB:BB:02"  # -45 dBm is stronger than -80


class TestWifiClientSignalDisplay:
    """WifiClient.signal_display property tests."""

    def test_excellent_signal(self):
        c = WifiClient("AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", -40, 10, "", "")
        assert "excellent" in c.signal_display

    def test_good_signal(self):
        c = WifiClient("AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", -60, 10, "", "")
        assert "good" in c.signal_display

    def test_fair_signal(self):
        c = WifiClient("AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", -70, 10, "", "")
        assert "fair" in c.signal_display

    def test_weak_signal(self):
        c = WifiClient("AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", -85, 10, "", "")
        assert "weak" in c.signal_display


class TestVerifyHandshake:
    """Bug 10 regression: verify requires M1+M2 not just 2 frames."""

    def test_rejects_when_aircrack_reports_zero(self):
        """Zero handshakes from aircrack must NOT be counted as success."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                stdout="0 handshake found",
                stderr="",
                returncode=1
            )
            from modules.handshake import verify_handshake
            with patch('os.path.exists', return_value=True), \
                 patch('os.path.getsize', return_value=1024):
                result = verify_handshake('/tmp/fake.cap', 'AA:BB:CC:11:22:33')
                assert result is False

    def test_accepts_when_aircrack_reports_one(self):
        """1 handshake from aircrack must be accepted."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                stdout="1 handshake found",
                stderr="",
                returncode=1
            )
            from modules.handshake import verify_handshake
            with patch('os.path.exists', return_value=True), \
                 patch('os.path.getsize', return_value=2048):
                result = verify_handshake('/tmp/fake.cap', 'AA:BB:CC:11:22:33')
                assert result is True

    def test_rejects_file_too_small(self):
        """Files under 200 bytes cannot contain a handshake."""
        from modules.handshake import verify_handshake
        with patch('os.path.exists', return_value=True), \
             patch('os.path.getsize', return_value=100):
            result = verify_handshake('/tmp/tiny.cap', 'AA:BB:CC:11:22:33')
            assert result is False

    def test_rejects_missing_file(self):
        from modules.handshake import verify_handshake
        result = verify_handshake('/nonexistent/path.cap', 'AA:BB:CC:11:22:33')
        assert result is False


class TestCapFileFinding:
    """Bug 1 regression: find prefix-01.cap not prefix.cap."""

    def test_finds_numbered_cap_file(self, tmp_path):
        cap = tmp_path / "handshake-01.cap"
        cap.write_bytes(b'\x00' * 100)
        from modules.handshake import _find_cap_file
        found = _find_cap_file(str(tmp_path / "handshake"))
        assert found == str(cap)

    def test_returns_none_when_no_cap_exists(self, tmp_path):
        from modules.handshake import _find_cap_file
        assert _find_cap_file(str(tmp_path / "handshake")) is None

    def test_ignores_unprefixed_cap_file(self, tmp_path):
        """A file named exactly prefix.cap (no number) must NOT be returned."""
        cap = tmp_path / "handshake.cap"
        cap.write_bytes(b'\x00' * 100)
        from modules.handshake import _find_cap_file
        # The glob pattern is prefix-*.cap, so prefix.cap should not match
        assert _find_cap_file(str(tmp_path / "handshake")) is None

    def test_returns_most_recent_when_multiple(self, tmp_path):
        """When multiple numbered cap files exist, return the newest."""
        import time as _time
        cap1 = tmp_path / "handshake-01.cap"
        cap1.write_bytes(b'\x00' * 100)
        _time.sleep(0.01)
        cap2 = tmp_path / "handshake-02.cap"
        cap2.write_bytes(b'\x00' * 100)
        from modules.handshake import _find_cap_file
        found = _find_cap_file(str(tmp_path / "handshake"))
        assert found == str(cap2)


class TestLockChannelVerified:
    """Bug 11 regression: channel lock must be verified by readback."""

    def test_returns_true_when_channel_confirmed(self):
        from modules.handshake import lock_channel_verified
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                stdout="channel 6 (2437 MHz), width: 20 MHz (no HT)",
                stderr="",
                returncode=0
            )
            with patch('time.sleep'):
                result = lock_channel_verified(6, 'wlan0mon')
        assert result is True

    def test_returns_false_when_channel_mismatch(self):
        from modules.handshake import lock_channel_verified
        with patch('subprocess.run') as mock_run:
            # iw dev info always reports channel 1, not 6
            mock_run.return_value = MagicMock(
                stdout="channel 1 (2412 MHz)",
                stderr="",
                returncode=0
            )
            with patch('time.sleep'):
                result = lock_channel_verified(6, 'wlan0mon')
        assert result is False

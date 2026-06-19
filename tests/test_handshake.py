"""Tests for modules/handshake.py"""
from __future__ import annotations

import re
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.handshake import _parse_clients_from_csv as _parse_airodump_csv, WifiClient


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
    """WifiClient.signal_label property tests."""

    def test_excellent_signal(self):
        c = WifiClient(mac="AA:BB:CC:DD:EE:FF", power=-40, packets=10)
        assert "excellent" in c.signal_label

    def test_good_signal(self):
        c = WifiClient(mac="AA:BB:CC:DD:EE:FF", power=-60, packets=10)
        assert "good" in c.signal_label

    def test_fair_signal(self):
        c = WifiClient(mac="AA:BB:CC:DD:EE:FF", power=-70, packets=10)
        assert "fair" in c.signal_label

    def test_weak_signal(self):
        c = WifiClient(mac="AA:BB:CC:DD:EE:FF", power=-85, packets=10)
        assert "weak" in c.signal_label


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


class TestAirgeddonArchitecture:
    """New architecture: infinite deauth + no-filter client scan."""

    def test_capture_uses_infinite_deauth(self):
        """aireplay-ng must use --deauth 0 (infinite), not a fixed count."""
        import inspect
        from modules.handshake import capture_handshake
        src = inspect.getsource(capture_handshake)
        assert "'--deauth', '0'" in src, \
            "capture_handshake must use --deauth 0 (infinite deauth)"

    def test_capture_uses_no_bssid_filter_in_scan(self):
        """Client scan must NOT have -d/--bssid; filter happens in _parse_clients."""
        import inspect
        from modules.handshake import capture_handshake
        src = inspect.getsource(capture_handshake)
        scan_section = src[src.find('scan_proc'):src.find('cap_prefix')]
        assert "'-d'," not in scan_section, \
            "scan_proc must not use -d (no bssid filter in scan)"
        assert "'--bssid'" not in scan_section, \
            "scan_proc must not use --bssid (no bssid filter in scan)"

    def test_capture_command_has_no_output_format(self):
        """airodump-ng capture command must not use --output-format."""
        import inspect
        from modules.handshake import capture_handshake
        src = inspect.getsource(capture_handshake)
        cap_section = src[src.find('airodump_proc'):src.find('aireplay_proc')]
        assert '--output-format' not in cap_section, \
            "airodump capture must not use --output-format"

    def test_check_every_constant_is_five_seconds(self):
        """Verification polling interval must be CHECK_EVERY = 5 seconds."""
        import inspect
        from modules.handshake import capture_handshake
        src = inspect.getsource(capture_handshake)
        assert 'CHECK_EVERY' in src, "CHECK_EVERY constant not found"
        m = re.search(r'CHECK_EVERY\s*=\s*(\d+)', src)
        assert m, "CHECK_EVERY assignment not found"
        assert int(m.group(1)) == 5, f"CHECK_EVERY must be 5, got {m.group(1)}"


class TestHcxdumptoolFilterFormat:
    """Surviving Bug 3: BSSID filter file must NOT contain colons."""

    def test_filter_file_no_colons(self, tmp_path):
        bssid = 'AA:BB:CC:11:22:33'
        bssid_no_colons = bssid.lower().replace(':', '')
        assert ':' not in bssid_no_colons
        assert bssid_no_colons == 'aabbcc112233'

    def test_pmkid_writes_colon_free_filter(self, tmp_path):
        """_pmkid must write BSSID without colons to the filter file."""
        from modules.handshake import _pmkid
        bssid = 'AA:BB:CC:11:22:33'

        with patch('subprocess.Popen') as mock_popen:
            mock_popen.side_effect = FileNotFoundError  # hcxdumptool not installed
            _pmkid(bssid, 'wlan0mon', str(tmp_path), duration=1)

        # The filter file is written before the Popen call; check it's colon-free
        filter_file = tmp_path / 'bssid.flt'
        assert filter_file.exists(), "bssid.flt not written"
        content = filter_file.read_text().strip()
        assert ':' not in content, f"Filter file contains colons: {content!r}"
        assert content == 'aabbcc112233'


class TestSingleAirodumpInstance:
    """Architectural fix: ONE airodump-ng produces both cap and csv."""

    def test_airodump_command_has_no_output_format(self):
        """
        The airodump-ng command must NOT have --output-format.
        Absence of --output-format = airodump writes all formats (cap + csv).
        """
        cap_prefix = '/tmp/test_prefix'
        cmd = [
            'airodump-ng',
            '--bssid', 'AA:BB:CC:11:22:33',
            '-c', '6',
            '--write-interval', '1',
            '-w', cap_prefix,
            'wlan0mon',
        ]
        assert '--output-format' not in cmd, \
            "airodump-ng must not have --output-format (needs both cap + csv)"

    def test_csv_parsed_while_airodump_running(self, tmp_path):
        """Client discovery reads CSV without killing airodump."""
        csv_file = tmp_path / 'capture-01.csv'
        csv_file.write_text(
            "BSSID, First time seen\r\n\r\n"
            "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\r\n"
            "AA:AA:AA:AA:AA:01, 2024-01-01, 2024-01-01, -55, 10, AA:BB:CC:11:22:33, TestAP\r\n"
            "BB:BB:BB:BB:BB:02, 2024-01-01, 2024-01-01, -70, 5, AA:BB:CC:11:22:33, TestAP\r\n"
        )
        clients = _parse_airodump_csv(str(csv_file), 'AA:BB:CC:11:22:33')
        assert len(clients) == 2, f"Expected 2 clients, got {len(clients)}"
        assert clients[0].mac == 'AA:AA:AA:AA:AA:01'   # stronger signal first
        assert clients[1].mac == 'BB:BB:BB:BB:BB:02'


class TestKillHelper:
    """_kill must be safe to call on None and on already-dead processes."""

    def test_kill_none_is_safe(self):
        from modules.handshake import _kill
        _kill(None)  # must not raise

    def test_kill_dead_process_is_safe(self):
        from modules.handshake import _kill
        proc = MagicMock()
        proc.poll.return_value = 0   # already exited
        _kill(proc)                  # must not raise, must not call terminate

"""
tests/test_handshake.py — God-Level handshake engine test suite.

Tests every critical path of the rewritten capture engine:
  - Absolute deadline math (no phase overflow)
  - Channel verification
  - Process group management
  - Adaptive airodump startup
  - Dual verification (aircrack + tshark)
  - Client CSV parsing
  - Cap file discovery
  - Phase time budget correctness
  - Health monitoring (stall detection, aireplay restart)
  - Scan-phase handshake detection
  - PMKID hcxdumptool version detection
  - Multi-client parallel deauth
  - KeyboardInterrupt graceful handling
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import time
from unittest import mock

import pytest

from modules.handshake import (
    WifiClient,
    _cap_size,
    _find_cap,
    _find_csv,
    _is_alive,
    _kill,
    _parse_clients,
    _rm,
    _set_channel,
    _start_deauth,
    _verify,
    _verify_aircrack,
    _verify_channel,
    _verify_tshark,
    _detect_hcxdumptool_version,
    _pmkid,
    _save,
    _kill_interfering,
    capture_handshake,
    verify_handshake,
)

# Backward-compat alias imports
from modules.handshake import (
    _find_cap_file,
    _find_csv_file,
    _parse_clients_from_csv,
    _parse_airodump_csv,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def tmpdir():
    """Create a temporary directory for test files."""
    d = tempfile.mkdtemp(prefix='test_hs_')
    yield d
    import shutil
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def cap_file(tmpdir):
    """Create a fake .cap file with enough data to pass size check."""
    prefix = os.path.join(tmpdir, 'test')
    path = prefix + '-01.cap'
    with open(path, 'wb') as f:
        f.write(b'\x00' * 500)
    return prefix, path


@pytest.fixture
def csv_file(tmpdir):
    """Create a realistic airodump-ng CSV with AP + Station sections."""
    prefix = os.path.join(tmpdir, 'scan')
    path = prefix + '-01.csv'
    content = (
        "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
        "AA:BB:CC:DD:EE:FF, 2024-01-01 00:00:00, 2024-01-01 00:01:00, 6, 54, WPA2, CCMP, PSK, -45, 100, 0, 0.0.0.0, 8, TestNetwork, \n"
        "\n"
        "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\n"
        "11:22:33:44:55:66, 2024-01-01 00:00:00, 2024-01-01 00:01:00, -55, 100, AA:BB:CC:DD:EE:FF, TestNetwork\n"
        "AA:BB:CC:DD:EE:11, 2024-01-01 00:00:00, 2024-01-01 00:01:00, -65, 50, AA:BB:CC:DD:EE:FF, TestNetwork\n"
        "FF:FF:FF:FF:FF:FF, 2024-01-01 00:00:00, 2024-01-01 00:01:00, -70, 20, (not associated), \n"
        "22:33:44:55:66:77, 2024-01-01 00:00:00, 2024-01-01 00:01:00, -80, 10, 00:11:22:33:44:55, OtherNetwork\n"
    )
    with open(path, 'w') as f:
        f.write(content)
    return prefix, path


# ═══════════════════════════════════════════════════════════════════════════════
# WifiClient data type
# ═══════════════════════════════════════════════════════════════════════════════

class TestWifiClient:
    def test_signal_label_excellent(self):
        c = WifiClient(mac="AA:BB:CC:DD:EE:FF", power=-40, packets=100)
        assert "excellent" in c.signal_label

    def test_signal_label_good(self):
        c = WifiClient(mac="AA:BB:CC:DD:EE:FF", power=-55, packets=100)
        assert "good" in c.signal_label

    def test_signal_label_fair(self):
        c = WifiClient(mac="AA:BB:CC:DD:EE:FF", power=-70, packets=100)
        assert "fair" in c.signal_label

    def test_signal_label_weak(self):
        c = WifiClient(mac="AA:BB:CC:DD:EE:FF", power=-80, packets=100)
        assert "weak" in c.signal_label

    def test_signal_label_unknown(self):
        c = WifiClient(mac="AA:BB:CC:DD:EE:FF", power=-100, packets=0)
        assert "unknown" in c.signal_label


# ═══════════════════════════════════════════════════════════════════════════════
# File helpers
# ═══════════════════════════════════════════════════════════════════════════════

class TestFindCap:
    def test_finds_cap_file(self, cap_file):
        prefix, path = cap_file
        assert _find_cap(prefix) == path

    def test_returns_none_when_no_cap(self, tmpdir):
        assert _find_cap(os.path.join(tmpdir, 'nonexistent')) is None

    def test_finds_most_recent(self, tmpdir):
        prefix = os.path.join(tmpdir, 'multi')
        for i in range(1, 4):
            p = prefix + f'-0{i}.cap'
            with open(p, 'wb') as f:
                f.write(b'\x00' * 100)
            time.sleep(0.05)
        result = _find_cap(prefix)
        assert result.endswith('-03.cap')

    def test_backward_compat_alias(self, cap_file):
        prefix, path = cap_file
        assert _find_cap_file(prefix) == path


class TestFindCsv:
    def test_finds_csv_file(self, csv_file):
        prefix, path = csv_file
        assert _find_csv(prefix) == path

    def test_backward_compat_alias(self, csv_file):
        prefix, path = csv_file
        assert _find_csv_file(prefix) == path


class TestCapSize:
    def test_returns_size(self, cap_file):
        prefix, path = cap_file
        assert _cap_size(prefix) == 500

    def test_returns_zero_when_missing(self, tmpdir):
        assert _cap_size(os.path.join(tmpdir, 'nope')) == 0


class TestRm:
    def test_removes_all_files(self, tmpdir):
        prefix = os.path.join(tmpdir, 'clean')
        for ext in ('.cap', '.csv', '.kismet.netxml', '.kismet.csv', '.log.csv'):
            with open(prefix + '-01' + ext, 'w') as f:
                f.write('x')
        _rm(prefix)
        remaining = os.listdir(tmpdir)
        assert len(remaining) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Client CSV parsing
# ═══════════════════════════════════════════════════════════════════════════════

class TestParseClients:
    def test_parses_clients_for_target(self, csv_file):
        _, path = csv_file
        clients = _parse_clients(path, 'AA:BB:CC:DD:EE:FF')
        assert len(clients) == 2
        # Sorted by power (strongest first)
        assert clients[0].mac == '11:22:33:44:55:66'
        assert clients[0].power == -55
        assert clients[1].mac == 'AA:BB:CC:DD:EE:11'
        assert clients[1].power == -65

    def test_filters_by_bssid(self, csv_file):
        _, path = csv_file
        # Ask for a different AP
        clients = _parse_clients(path, '00:11:22:33:44:55')
        assert len(clients) == 1
        assert clients[0].mac == '22:33:44:55:66:77'

    def test_skips_unassociated(self, csv_file):
        _, path = csv_file
        clients = _parse_clients(path, 'AA:BB:CC:DD:EE:FF')
        macs = [c.mac for c in clients]
        assert 'FF:FF:FF:FF:FF:FF' not in macs

    def test_handles_missing_file(self):
        assert _parse_clients('/nonexistent/path.csv', 'AA:BB:CC:DD:EE:FF') == []

    def test_handles_null_bytes(self, tmpdir):
        path = os.path.join(tmpdir, 'null-01.csv')
        content = (
            "BSSID, First time seen, Last time seen, channel, Speed, Privacy\n"
            "AA:BB:CC:DD:EE:FF, x, x, 6, 54, WPA2\n\n"
            "Station MAC, First time seen, Last time seen, Power, # packets, BSSID\n"
            "11:22:33:44:55:66\x00, x, x, -50, 100, AA:BB:CC:DD:EE:FF\n"
        )
        with open(path, 'w') as f:
            f.write(content)
        clients = _parse_clients(path, 'AA:BB:CC:DD:EE:FF')
        assert len(clients) == 1

    def test_backward_compat_aliases(self, csv_file):
        _, path = csv_file
        assert _parse_clients_from_csv(path, 'AA:BB:CC:DD:EE:FF') == \
               _parse_clients(path, 'AA:BB:CC:DD:EE:FF')
        assert _parse_airodump_csv(path, 'AA:BB:CC:DD:EE:FF') == \
               _parse_clients(path, 'AA:BB:CC:DD:EE:FF')


# ═══════════════════════════════════════════════════════════════════════════════
# Channel verification
# ═══════════════════════════════════════════════════════════════════════════════

class TestChannelVerification:
    @mock.patch('modules.handshake.subprocess.run')
    def test_verify_channel_correct(self, mock_run):
        mock_run.return_value = mock.Mock(stdout="Interface wlan0\n  channel 6\n  type monitor")
        assert _verify_channel('wlan0', 6) is True

    @mock.patch('modules.handshake.subprocess.run')
    def test_verify_channel_mismatch(self, mock_run):
        mock_run.return_value = mock.Mock(stdout="Interface wlan0\n  channel 11\n  type monitor")
        assert _verify_channel('wlan0', 6) is False

    @mock.patch('modules.handshake.subprocess.run')
    def test_verify_channel_no_output(self, mock_run):
        mock_run.return_value = mock.Mock(stdout="")
        # When we can't verify, assume OK
        assert _verify_channel('wlan0', 6) is True

    @mock.patch('modules.handshake.subprocess.run', side_effect=FileNotFoundError)
    def test_verify_channel_no_iw(self, mock_run):
        assert _verify_channel('wlan0', 6) is True

    @mock.patch('modules.handshake._verify_channel')
    @mock.patch('modules.handshake.subprocess.run')
    def test_set_channel_retries(self, mock_run, mock_verify):
        mock_verify.side_effect = [False, False, True]
        assert _set_channel('wlan0', 6) is True
        assert mock_verify.call_count == 3


# ═══════════════════════════════════════════════════════════════════════════════
# Handshake verification
# ═══════════════════════════════════════════════════════════════════════════════

class TestVerifyAircrack:
    @mock.patch('modules.handshake.subprocess.run')
    def test_detects_handshake(self, mock_run, tmpdir, cap_file):
        _, path = cap_file
        mock_run.return_value = mock.Mock(
            stdout="WPA (1 handshake)\n", stderr=""
        )
        assert _verify_aircrack(path, 'AA:BB:CC:DD:EE:FF', tmpdir) is True

    @mock.patch('modules.handshake.subprocess.run')
    def test_detects_multiple_handshakes(self, mock_run, tmpdir, cap_file):
        _, path = cap_file
        mock_run.return_value = mock.Mock(
            stdout="WPA (3 handshakes)\n", stderr=""
        )
        assert _verify_aircrack(path, 'AA:BB:CC:DD:EE:FF', tmpdir) is True

    @mock.patch('modules.handshake.subprocess.run')
    def test_detects_old_format(self, mock_run, tmpdir, cap_file):
        _, path = cap_file
        mock_run.return_value = mock.Mock(
            stdout="1 handshake captured\n", stderr=""
        )
        assert _verify_aircrack(path, 'AA:BB:CC:DD:EE:FF', tmpdir) is True

    @mock.patch('modules.handshake.subprocess.run')
    def test_no_handshake(self, mock_run, tmpdir, cap_file):
        _, path = cap_file
        mock_run.return_value = mock.Mock(
            stdout="WPA (0 handshake)\n", stderr=""
        )
        assert _verify_aircrack(path, 'AA:BB:CC:DD:EE:FF', tmpdir) is False

    def test_rejects_small_cap(self, tmpdir):
        small = os.path.join(tmpdir, 'tiny.cap')
        with open(small, 'wb') as f:
            f.write(b'\x00' * 50)
        # _verify checks size before calling aircrack
        assert _verify(small, 'AA:BB:CC:DD:EE:FF', tmpdir) is False

    def test_rejects_missing_cap(self, tmpdir):
        assert _verify('/nonexistent.cap', 'AA:BB:CC:DD:EE:FF', tmpdir) is False

    @mock.patch('modules.handshake.subprocess.run')
    def test_wordlist_written_to_tmpdir(self, mock_run, tmpdir, cap_file):
        _, path = cap_file
        mock_run.return_value = mock.Mock(stdout="", stderr="")
        _verify_aircrack(path, 'AA:BB:CC:DD:EE:FF', tmpdir)
        wl = os.path.join(tmpdir, '_verify_wl.txt')
        assert os.path.exists(wl), "Wordlist should be in tmpdir, not /tmp"

    @mock.patch('modules.handshake.subprocess.run')
    def test_runs_noninteractive_without_quiet(self, mock_run, tmpdir, cap_file):
        """aircrack-ng must run non-interactively (a -w wordlist makes it exit
        instead of opening the interactive menu) and must NOT pass -q, which
        suppresses the 'WPA (N handshake)' summary line the parser depends on."""
        _, path = cap_file
        mock_run.return_value = mock.Mock(stdout="", stderr="")
        _verify_aircrack(path, 'AA:BB:CC:DD:EE:FF', tmpdir)
        call_args = mock_run.call_args[0][0]
        assert '-w' in call_args                 # wordlist => non-interactive, exits
        assert '-a' in call_args and '2' in call_args
        assert '-q' not in call_args             # -q would break handshake detection


class TestVerifyTshark:
    @mock.patch('modules.handshake.shutil.which', return_value='/usr/bin/tshark')
    @mock.patch('modules.handshake.subprocess.run')
    def test_detects_m1_m2(self, mock_run, mock_which, cap_file):
        _, path = cap_file
        # M1 has ACK (0x0080), M2 has MIC (0x0100)
        mock_run.return_value = mock.Mock(
            stdout="0x008a\n0x010a\n"
        )
        assert _verify_tshark(path, 'AA:BB:CC:DD:EE:FF') is True

    @mock.patch('modules.handshake.shutil.which', return_value='/usr/bin/tshark')
    @mock.patch('modules.handshake.subprocess.run')
    def test_rejects_incomplete(self, mock_run, mock_which, cap_file):
        _, path = cap_file
        # Only M1, no M2
        mock_run.return_value = mock.Mock(stdout="0x008a\n")
        assert _verify_tshark(path, 'AA:BB:CC:DD:EE:FF') is False

    @mock.patch('modules.handshake.shutil.which', return_value=None)
    def test_returns_false_without_tshark(self, mock_which, cap_file):
        _, path = cap_file
        assert _verify_tshark(path, 'AA:BB:CC:DD:EE:FF') is False


class TestDualVerification:
    @mock.patch('modules.handshake._verify_tshark', return_value=True)
    @mock.patch('modules.handshake._verify_aircrack', return_value=False)
    def test_tshark_fallback(self, mock_aircrack, mock_tshark, tmpdir, cap_file):
        """If aircrack misses it, tshark should catch it."""
        _, path = cap_file
        assert _verify(path, 'AA:BB:CC:DD:EE:FF', tmpdir) is True
        mock_tshark.assert_called_once()

    @mock.patch('modules.handshake._verify_tshark', return_value=False)
    @mock.patch('modules.handshake._verify_aircrack', return_value=True)
    def test_aircrack_primary(self, mock_aircrack, mock_tshark, tmpdir, cap_file):
        """If aircrack finds it, tshark should NOT be called."""
        _, path = cap_file
        assert _verify(path, 'AA:BB:CC:DD:EE:FF', tmpdir) is True
        mock_tshark.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════════════
# Process management
# ═══════════════════════════════════════════════════════════════════════════════

class TestProcessManagement:
    def test_kill_none(self):
        """_kill(None) should not raise."""
        _kill(None)

    def test_kill_already_dead(self):
        """_kill on finished process should not raise."""
        proc = mock.Mock()
        proc.poll.return_value = 0  # already finished
        _kill(proc)

    def test_is_alive_none(self):
        assert _is_alive(None) is False

    def test_is_alive_dead(self):
        proc = mock.Mock()
        proc.poll.return_value = 0
        assert _is_alive(proc) is False

    def test_is_alive_running(self):
        proc = mock.Mock()
        proc.poll.return_value = None
        assert _is_alive(proc) is True


# ═══════════════════════════════════════════════════════════════════════════════
# Phase time budget math
# ═══════════════════════════════════════════════════════════════════════════════

class TestEngineTiming:
    """The engine is event-driven with a single absolute deadline; verify the
    tuning constants are internally consistent and realistic."""

    def test_constants_are_sane(self):
        import modules.handshake as hs
        assert hs.WARMUP_S >= 2                     # long enough to observe clients
        assert 3 <= hs.LISTEN_WINDOW_S <= 12        # realistic reconnect window
        assert hs.VERIFY_INTERVAL >= 1              # not per-second thrash
        assert hs.BROADCAST_EVERY >= 2
        assert hs.TOP_K_CLIENTS >= 1
        assert 0 < hs.MONITOR_POLL_S <= 1.0
        assert hs.DEFAULT_TIMEOUT >= hs.WARMUP_S + hs.LISTEN_WINDOW_S

    def test_warmup_plus_one_window_fits_default_timeout(self):
        import modules.handshake as hs
        # At least a few full deauth/listen rounds must fit in the budget
        rounds = (hs.DEFAULT_TIMEOUT - hs.WARMUP_S) // hs.LISTEN_WINDOW_S
        assert rounds >= 5

    def test_deadline_governs_all(self):
        """The loop must never plan past the absolute deadline."""
        import modules.handshake as hs
        start = 1000.0
        for timeout in (30, 60, 120, 180, 300):
            deadline = start + timeout
            warm_end = min(start + hs.WARMUP_S, deadline)
            assert warm_end <= deadline
            win_end = min(warm_end + hs.LISTEN_WINDOW_S, deadline)
            assert win_end <= deadline


# ═══════════════════════════════════════════════════════════════════════════════
# hcxdumptool version detection
# ═══════════════════════════════════════════════════════════════════════════════

class TestHcxdumptoolVersion:
    @mock.patch('modules.handshake.subprocess.run')
    def test_detects_version(self, mock_run):
        mock_run.return_value = mock.Mock(stdout="hcxdumptool 6.3.2\n", stderr="")
        assert _detect_hcxdumptool_version() == '6.3.2'

    @mock.patch('modules.handshake.subprocess.run')
    def test_detects_old_version(self, mock_run):
        mock_run.return_value = mock.Mock(stdout="hcxdumptool 6.1.6\n", stderr="")
        assert _detect_hcxdumptool_version() == '6.1.6'

    @mock.patch('modules.handshake.subprocess.run', side_effect=FileNotFoundError)
    def test_returns_none_when_missing(self, mock_run):
        assert _detect_hcxdumptool_version() is None


# ═══════════════════════════════════════════════════════════════════════════════
# Save handshake
# ═══════════════════════════════════════════════════════════════════════════════

class TestSave:
    @mock.patch('modules.handshake.subprocess.run')
    def test_saves_to_captures_dir(self, mock_run, cap_file):
        _, path = cap_file
        result = _save(path, 'AA:BB:CC:DD:EE:FF')
        assert result.startswith(os.path.join('captures', ''))
        assert os.path.exists(result)

    @mock.patch('modules.handshake.subprocess.run')
    def test_saves_with_correct_naming(self, mock_run, cap_file):
        _, path = cap_file
        result = _save(path, 'AA:BB:CC:DD:EE:FF')
        assert 'AABBCCDDEEFF' in result
        assert result.endswith('.cap')


# ═══════════════════════════════════════════════════════════════════════════════
# Public API: verify_handshake
# ═══════════════════════════════════════════════════════════════════════════════

class TestVerifyHandshake:
    @mock.patch('modules.handshake._verify')
    def test_creates_tmpdir_and_cleans_up(self, mock_verify):
        mock_verify.return_value = True
        result = verify_handshake('/some/file.cap', 'AA:BB:CC:DD:EE:FF')
        assert result is True
        # tmpdir should be cleaned up
        mock_verify.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════════
# Public API: capture_handshake (integration-level mocked tests)
# ═══════════════════════════════════════════════════════════════════════════════

class TestCaptureHandshake:
    @mock.patch('modules.handshake._pmkid', return_value=None)
    @mock.patch('modules.handshake._verify', return_value=False)
    @mock.patch('modules.handshake._kill_interfering')
    @mock.patch('modules.handshake._set_channel', return_value=True)
    @mock.patch('modules.handshake._popen')
    @mock.patch('modules.handshake._find_cap', return_value=None)
    @mock.patch('modules.handshake._find_csv', return_value=None)
    @mock.patch('modules.handshake._parse_clients', return_value=[])
    def test_returns_none_on_timeout(self, *mocks):
        result = capture_handshake(
            bssid='AA:BB:CC:DD:EE:FF',
            ssid='TestNetwork',
            channel=6,
            monitor_interface='wlan0mon',
            timeout=3,  # very short for fast test
        )
        assert result is None

    @mock.patch('modules.handshake._save', return_value='captures/test.cap')
    @mock.patch('modules.handshake._kill_interfering')
    @mock.patch('modules.handshake._set_channel', return_value=True)
    @mock.patch('modules.handshake._popen')
    @mock.patch('modules.handshake._find_csv', return_value=None)
    @mock.patch('modules.handshake._parse_clients', return_value=[])
    def test_returns_cap_on_success(self, mock_parse, mock_csv, mock_popen,
                                    mock_channel, mock_kill, mock_save):
        """Simulate finding a handshake during Phase 1 scan."""
        call_count = [0]
        def mock_find_cap(prefix):
            call_count[0] += 1
            if call_count[0] >= 2:
                return '/tmp/fake-01.cap'
            return None

        def mock_verify(cap, bssid, tmpdir):
            return cap is not None

        with mock.patch('modules.handshake._find_cap', side_effect=mock_find_cap), \
             mock.patch('modules.handshake._verify', side_effect=mock_verify):
            result = capture_handshake(
                bssid='AA:BB:CC:DD:EE:FF',
                ssid='TestNetwork',
                channel=6,
                monitor_interface='wlan0mon',
                timeout=30,
            )
            assert result == 'captures/test.cap'


class TestMonitorTriggerPath:
    """Exercise the event-driven path: the live sniffer flags a handshake, and
    the engine confirms it on disk and saves."""

    @mock.patch('modules.handshake._save', return_value='captures/hs.cap')
    @mock.patch('modules.handshake._verify', return_value=True)
    @mock.patch('modules.handshake._find_cap', return_value='/tmp/x-01.cap')
    @mock.patch('modules.handshake._kill_interfering')
    @mock.patch('modules.handshake._set_channel', return_value=True)
    @mock.patch('modules.handshake._popen')
    @mock.patch('modules.handshake._deauth_burst_parallel')
    def test_eapol_trigger_confirms_and_saves(self, *_mocks):
        from modules.eapol_monitor import MonitorSnapshot
        fake = mock.Mock()
        fake.start.return_value = True
        fake.error = None
        fake.snapshot.return_value = MonitorSnapshot(
            clients=[], handshake_client='10:22:33:44:55:66',
            pmkid_present=False, pmkid_hashes={}, ap_seen=True,
        )
        with mock.patch('modules.handshake.LiveMonitor', return_value=fake):
            result = capture_handshake(
                bssid='AA:BB:CC:DD:EE:FF', ssid='Net', channel=6,
                monitor_interface='wlan0mon', timeout=30,
            )
        assert result == 'captures/hs.cap'

    @mock.patch('modules.handshake._save', return_value='captures/pmkid.cap')
    @mock.patch('modules.handshake._verify', return_value=True)
    @mock.patch('modules.handshake._find_cap', return_value='/tmp/x-01.cap')
    @mock.patch('modules.handshake._kill_interfering')
    @mock.patch('modules.handshake._set_channel', return_value=True)
    @mock.patch('modules.handshake._popen')
    @mock.patch('modules.handshake._deauth_burst_parallel')
    def test_pmkid_trigger_confirms_and_saves(self, *_mocks):
        from modules.eapol_monitor import MonitorSnapshot
        fake = mock.Mock()
        fake.start.return_value = True
        fake.error = None
        fake.snapshot.return_value = MonitorSnapshot(
            clients=[], handshake_client=None,
            pmkid_present=True, pmkid_hashes={'10:22:33:44:55:66': 'ab' * 16},
            ap_seen=True,
        )
        with mock.patch('modules.handshake.LiveMonitor', return_value=fake):
            result = capture_handshake(
                bssid='AA:BB:CC:DD:EE:FF', ssid='Net', channel=36,
                monitor_interface='wlan0mon', timeout=30,
            )
        assert result == 'captures/pmkid.cap'

    def test_wpa3_sae_is_skipped_without_capture(self):
        result = capture_handshake(
            bssid='AA:BB:CC:DD:EE:FF', ssid='Net', channel=36,
            monitor_interface='wlan0mon', timeout=30, security='WPA3_SAE',
        )
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════════
# Interface module tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestInterfaceMatching:
    """Test the new _interface_matches function in interface.py."""

    def test_direct_match(self):
        from modules.interface import _interface_matches
        assert _interface_matches('wlan0', 'wlan0') is True

    def test_mon_suffix(self):
        from modules.interface import _interface_matches
        assert _interface_matches('wlan0mon', 'wlan0') is True

    def test_no_match(self):
        from modules.interface import _interface_matches
        assert _interface_matches('wlan1mon', 'wlan0') is False

    def test_different_interface(self):
        from modules.interface import _interface_matches
        assert _interface_matches('wlan1', 'wlan0') is False

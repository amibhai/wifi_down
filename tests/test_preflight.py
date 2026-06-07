"""Tests for modules/preflight.py — pre-flight dependency checks."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.preflight import (
    ToolStatus,
    _check_tool,
    _check_monitor_mode,
    _get_wireless_interfaces,
    _get_version,
    run_preflight,
)


# ── _get_version ─────────────────────────────────────────────────────────────

def test_get_version_parses_output():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout="Aircrack-ng 1.7.0", stderr="", returncode=0
        )
        version = _get_version("aircrack-ng --version", r"Aircrack-ng\s+(\d+\.\d+)")
        assert version == "1.7"


def test_get_version_returns_found_when_no_match():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="aircrack-ng: no version info", stderr="", returncode=0)
        # Pattern won't match, should return "found" (tool exists but version unknown)
        version = _get_version("aircrack-ng", r"Aircrack-ng (\d+\.\d+)")
        assert version == "found"


def test_get_version_returns_none_on_exception():
    with patch("subprocess.run", side_effect=FileNotFoundError):
        version = _get_version("nonexistent-tool --version", r"(\d+\.\d+)")
        assert version is None


# ── _check_tool ──────────────────────────────────────────────────────────────

def test_check_tool_missing_tool():
    with patch("shutil.which", return_value=None):
        status = _check_tool("nonexistent", "nonexistent --version", r"(\d+\.\d+)", required=True)
    assert not status.ok
    assert status.path is None
    assert status.required is True


def test_check_tool_found_tool():
    with patch("shutil.which", return_value="/usr/bin/aircrack-ng"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="Aircrack-ng 1.7", stderr="", returncode=0
            )
            status = _check_tool(
                "aircrack-ng", "aircrack-ng --version",
                r"Aircrack-ng\s+(\d+\.\d+)", required=True
            )
    assert status.path == "/usr/bin/aircrack-ng"
    assert status.ok


def test_check_tool_old_aircrack_fails():
    with patch("shutil.which", return_value="/usr/bin/aircrack-ng"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="Aircrack-ng 1.2", stderr="", returncode=0
            )
            status = _check_tool(
                "aircrack-ng", "aircrack-ng --version",
                r"Aircrack-ng\s+(\d+\.\d+)", required=True
            )
    assert not status.ok
    assert "1.7" in status.note


# ── _get_wireless_interfaces ─────────────────────────────────────────────────

def test_get_wireless_interfaces_parses_iw_dev():
    sample_output = """
phy#0
        Interface wlan0
                ifindex 3
                type managed
        Interface wlan0mon
                ifindex 4
                type monitor
"""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=sample_output, stderr="", returncode=0)
        ifaces = _get_wireless_interfaces()
    assert "wlan0" in ifaces
    assert "wlan0mon" in ifaces


def test_get_wireless_interfaces_returns_empty_on_failure():
    with patch("subprocess.run", side_effect=FileNotFoundError):
        ifaces = _get_wireless_interfaces()
    assert ifaces == []


# ── run_preflight ─────────────────────────────────────────────────────────────

def test_run_preflight_exits_on_missing_tool():
    with patch("shutil.which", return_value=None):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            with pytest.raises(SystemExit) as exc_info:
                run_preflight(exit_on_failure=True)
    assert exc_info.value.code == 2


def test_run_preflight_returns_false_no_exit():
    with patch("shutil.which", return_value=None):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = run_preflight(exit_on_failure=False)
    assert result is False

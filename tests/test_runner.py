"""Tests for modules/runner.py — SubprocessRunner timeout and retry behaviour."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.exceptions import CaptureError, DependencyError
from modules.runner import SubprocessRunner


runner = SubprocessRunner()


# ── Successful run ────────────────────────────────────────────────────────────

def test_run_success():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0, stdout="output line\n", stderr=""
        )
        result = runner.run(["echo", "hello"])
    assert result.returncode == 0


def test_run_calls_on_output_line():
    lines_seen: list[str] = []
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0, stdout="line1\nline2\n", stderr=""
        )
        runner.run(["cat", "file"], on_output_line=lines_seen.append)
    assert "line1" in lines_seen
    assert "line2" in lines_seen


# ── Timeout ────────────────────────────────────────────────────────────────────

def test_run_timeout_raises_capture_error():
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["sleep"], timeout=1)):
        with pytest.raises(CaptureError) as exc_info:
            runner.run(["sleep", "100"], timeout=1.0)
    assert "timed out" in str(exc_info.value).lower()


def test_run_timeout_includes_duration():
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["sleep"], timeout=5)):
        with pytest.raises(CaptureError) as exc_info:
            runner.run(["sleep", "100"], timeout=5.0)
    assert "5" in str(exc_info.value)


# ── FileNotFoundError → DependencyError ──────────────────────────────────────

def test_run_missing_binary_raises_dependency_error():
    with patch("subprocess.run", side_effect=FileNotFoundError):
        with pytest.raises(DependencyError) as exc_info:
            runner.run(["nonexistent-binary"])
    assert exc_info.value.binary == "nonexistent-binary"


# ── Retries ────────────────────────────────────────────────────────────────────

def test_run_retries_on_timeout():
    side_effects = [
        subprocess.TimeoutExpired(cmd=["cmd"], timeout=1),
        subprocess.TimeoutExpired(cmd=["cmd"], timeout=1),
        MagicMock(returncode=0, stdout="", stderr=""),
    ]
    with patch("subprocess.run", side_effect=side_effects):
        with patch("time.sleep"):   # skip backoff delay
            result = runner.run(["cmd"], timeout=1.0, retries=2)
    assert result.returncode == 0


def test_run_raises_after_all_retries_exhausted():
    with patch("subprocess.run",
               side_effect=subprocess.TimeoutExpired(cmd=["cmd"], timeout=1)):
        with patch("time.sleep"):
            with pytest.raises(CaptureError):
                runner.run(["cmd"], timeout=1.0, retries=2)


def test_run_zero_retries_raises_immediately():
    with patch("subprocess.run",
               side_effect=subprocess.TimeoutExpired(cmd=["cmd"], timeout=1)):
        with pytest.raises(CaptureError):
            runner.run(["cmd"], timeout=1.0, retries=0)


# ── stream ─────────────────────────────────────────────────────────────────────

def test_stream_calls_on_output_line():
    lines_seen: list[str] = []

    fake_proc = MagicMock()
    fake_proc.stdout = iter(["line A\n", "line B\n"])
    fake_proc.returncode = 0
    fake_proc.pid = 1234
    fake_proc.wait.return_value = 0

    with patch("subprocess.Popen", return_value=fake_proc):
        runner.stream(["cmd"], on_output_line=lines_seen.append)

    assert "line A" in lines_seen
    assert "line B" in lines_seen


def test_stream_missing_binary_raises_dependency_error():
    with patch("subprocess.Popen", side_effect=FileNotFoundError):
        with pytest.raises(DependencyError):
            runner.stream(["nonexistent-binary"])

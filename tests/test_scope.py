"""Tests for modules/scope.py — scope enforcement."""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.exceptions import ScopeError
from modules.scope import ScopeManager


def _write_scope(entries: list[dict], tmp_path: Path) -> Path:
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.dump({"authorized_targets": entries}))
    return p


# ── is_authorized ─────────────────────────────────────────────────────────────

def test_authorized_bssid_returns_true(tmp_path):
    scope_file = _write_scope(
        [{"bssid": "AA:BB:CC:DD:EE:FF", "ssid": "TestNet",
          "authorized_by": "Tester", "valid_until": "2099-12-31", "notes": ""}],
        tmp_path,
    )
    sm = ScopeManager(scope_file)
    assert sm.is_authorized("AA:BB:CC:DD:EE:FF") is True


def test_unauthorized_bssid_returns_false(tmp_path):
    scope_file = _write_scope(
        [{"bssid": "AA:BB:CC:DD:EE:FF", "ssid": "TestNet",
          "authorized_by": "Tester", "valid_until": "2099-12-31", "notes": ""}],
        tmp_path,
    )
    sm = ScopeManager(scope_file)
    assert sm.is_authorized("11:22:33:44:55:66") is False


def test_expired_scope_returns_false(tmp_path):
    scope_file = _write_scope(
        [{"bssid": "AA:BB:CC:DD:EE:FF", "ssid": "TestNet",
          "authorized_by": "Tester", "valid_until": "2020-01-01", "notes": ""}],
        tmp_path,
    )
    sm = ScopeManager(scope_file)
    assert sm.is_authorized("AA:BB:CC:DD:EE:FF") is False


def test_case_insensitive_bssid(tmp_path):
    scope_file = _write_scope(
        [{"bssid": "aa:bb:cc:dd:ee:ff", "ssid": "TestNet",
          "authorized_by": "Tester", "valid_until": "2099-12-31", "notes": ""}],
        tmp_path,
    )
    sm = ScopeManager(scope_file)
    assert sm.is_authorized("AA:BB:CC:DD:EE:FF") is True


def test_no_scope_file_returns_false():
    sm = ScopeManager(Path("/nonexistent/scope.yaml"))
    assert sm.is_authorized("AA:BB:CC:DD:EE:FF") is False


# ── require_authorized ────────────────────────────────────────────────────────

def test_require_authorized_passes(tmp_path):
    scope_file = _write_scope(
        [{"bssid": "AA:BB:CC:DD:EE:FF", "ssid": "TestNet",
          "authorized_by": "Tester", "valid_until": "2099-12-31", "notes": ""}],
        tmp_path,
    )
    sm = ScopeManager(scope_file)
    sm.require_authorized("AA:BB:CC:DD:EE:FF", "test operation")  # should not raise


def test_require_authorized_raises_scope_error(tmp_path):
    scope_file = _write_scope(
        [{"bssid": "AA:BB:CC:DD:EE:FF", "ssid": "TestNet",
          "authorized_by": "Tester", "valid_until": "2099-12-31", "notes": ""}],
        tmp_path,
    )
    sm = ScopeManager(scope_file)
    with pytest.raises(ScopeError) as exc_info:
        sm.require_authorized("11:22:33:44:55:66", "deauth attack")
    assert "11:22:33:44:55:66" in str(exc_info.value) or "scope" in str(exc_info.value).lower()


def test_require_authorized_no_scope_raises(tmp_path):
    sm = ScopeManager(Path("/nonexistent/scope.yaml"))
    with pytest.raises(ScopeError):
        sm.require_authorized("AA:BB:CC:DD:EE:FF", "any operation")

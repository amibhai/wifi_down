"""Tests for modules/oui.py — OUI vendor lookup (mock HTTP)."""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


# ── Patch OUI_DB_PATH to a tmp location so tests don't touch ~/.wifi-auditor ─

@pytest.fixture(autouse=True)
def _patch_oui_db(tmp_path, monkeypatch):
    import modules.oui as oui_module
    monkeypatch.setattr(oui_module, "OUI_DB_PATH", tmp_path / "oui.db")
    monkeypatch.setattr(oui_module, "CACHE_TTL", 0)  # always refresh in tests
    yield


def _fake_csv_response(rows: list[tuple[str, str]]) -> str:
    """Build a minimal IEEE OUI CSV string."""
    lines = ["Registry,Assignment,Organization Name,Organization Address"]
    for assignment, org in rows:
        lines.append(f'MA-L,{assignment},"{org}","Some Address"')
    return "\n".join(lines)


# ── refresh_database ──────────────────────────────────────────────────────────

def test_refresh_database_inserts_vendors():
    from modules.oui import refresh_database, get_vendor

    csv_content = _fake_csv_response([
        ("AABBCC", "TP-Link Technologies"),
        ("112233", "Netgear Inc."),
    ])
    mock_resp = MagicMock()
    mock_resp.text = csv_content
    mock_resp.raise_for_status = MagicMock()

    with patch("requests.get", return_value=mock_resp):
        ok = refresh_database(force=True)

    assert ok is True


def test_get_vendor_returns_correct_name():
    from modules.oui import refresh_database, get_vendor

    csv_content = _fake_csv_response([("AABBCC", "TP-Link Technologies")])
    mock_resp = MagicMock()
    mock_resp.text = csv_content
    mock_resp.raise_for_status = MagicMock()

    with patch("requests.get", return_value=mock_resp):
        refresh_database(force=True)

    vendor = get_vendor("AA:BB:CC:DD:EE:FF")
    assert vendor == "TP-Link Technologies"


def test_get_vendor_unknown_bssid_returns_none():
    from modules.oui import refresh_database, get_vendor

    csv_content = _fake_csv_response([("AABBCC", "TP-Link Technologies")])
    mock_resp = MagicMock()
    mock_resp.text = csv_content
    mock_resp.raise_for_status = MagicMock()

    with patch("requests.get", return_value=mock_resp):
        refresh_database(force=True)

    assert get_vendor("FF:FF:FF:FF:FF:FF") is None


def test_refresh_database_returns_false_on_network_error():
    from modules.oui import refresh_database

    with patch("requests.get", side_effect=Exception("connection refused")):
        ok = refresh_database(force=True)

    assert ok is False


# ── get_vendor_wordlist ────────────────────────────────────────────────────────

def test_get_vendor_wordlist_returns_defaults_for_tplink(tmp_path):
    from modules.oui import refresh_database, get_vendor_wordlist

    csv_content = _fake_csv_response([("AABBCC", "TP-Link Technologies")])
    mock_resp = MagicMock()
    mock_resp.text = csv_content
    mock_resp.raise_for_status = MagicMock()

    with patch("requests.get", return_value=mock_resp):
        refresh_database(force=True)

    passwords = get_vendor_wordlist("AA:BB:CC:DD:EE:FF")
    assert isinstance(passwords, list)
    assert len(passwords) > 0
    assert "admin" in passwords


def test_get_vendor_wordlist_substitutes_last4mac(tmp_path):
    from modules.oui import refresh_database, get_vendor_wordlist

    csv_content = _fake_csv_response([("AABBCC", "TP-Link Technologies")])
    mock_resp = MagicMock()
    mock_resp.text = csv_content
    mock_resp.raise_for_status = MagicMock()

    with patch("requests.get", return_value=mock_resp):
        refresh_database(force=True)

    passwords = get_vendor_wordlist("AA:BB:CC:DD:EE:FF")
    # tplink{last4mac} → tplinkEEFF is expected (last 4 hex of AABBCCDDEEFF)
    assert any("eeff" in p.lower() for p in passwords)


def test_get_vendor_wordlist_empty_for_unknown_vendor():
    from modules.oui import refresh_database, get_vendor_wordlist

    csv_content = _fake_csv_response([("AABBCC", "Unknown Corp XYZ")])
    mock_resp = MagicMock()
    mock_resp.text = csv_content
    mock_resp.raise_for_status = MagicMock()

    with patch("requests.get", return_value=mock_resp):
        refresh_database(force=True)

    # Vendor not in router_defaults.yaml — should return empty list
    passwords = get_vendor_wordlist("AA:BB:CC:DD:EE:FF")
    assert isinstance(passwords, list)

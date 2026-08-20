"""
Tests for the evil-twin captive-portal live PSK verification (Phase 9).

The portal turns from a blind credential logger into a *verified* PSK harvester:
a password a victim submits is checked against a captured PMKID with the offline
crypto, so "wrong password, try again" is genuine and success is confirmed.

Pure logic — no HTTP socket, no RF, no hostapd.
"""
from __future__ import annotations

import pytest

from modules import pmkid, wpacrypto
from modules.phantom import _PortalHandler

SSID, AP, STA, PW = "HomeNet", "aabbccddeeff", "112233445566", "correct1x"


def _hash_file(tmp_path, ssid=SSID, ap=AP, sta=STA, pw=PW):
    pmkid_hex = wpacrypto.compute_pmkid(wpacrypto.pmk(pw, ssid), ap, sta).hex()
    line = f"WPA*01*{pmkid_hex}*{ap}*{sta}*{ssid.encode().hex()}***"
    f = tmp_path / "cap.hc22000"
    f.write_text(line + "\n", encoding="utf-8")
    return str(f)


class TestVerifierFactory:
    def test_correct_password_accepted(self, tmp_path):
        v = pmkid.make_pmkid_verifier(_hash_file(tmp_path))
        assert v is not None
        assert v(PW) is True

    def test_wrong_password_rejected(self, tmp_path):
        v = pmkid.make_pmkid_verifier(_hash_file(tmp_path))
        assert v("wrongpass") is False

    def test_invalid_length_rejected(self, tmp_path):
        v = pmkid.make_pmkid_verifier(_hash_file(tmp_path))
        assert v("short") is False        # < 8 chars, never a valid WPA PSK
        assert v("") is False

    def test_no_pmkid_returns_none(self, tmp_path):
        f = tmp_path / "empty.hc22000"
        f.write_text("garbage\n", encoding="utf-8")
        assert pmkid.make_pmkid_verifier(str(f)) is None

    def test_missing_file_returns_none(self):
        assert pmkid.make_pmkid_verifier("/no/such/file.hc22000") is None


class TestPortalEvaluate:
    @pytest.fixture(autouse=True)
    def _reset(self):
        # Isolate the class-level verifier between tests.
        _PortalHandler.verify_password = None
        _PortalHandler.verified_password = None
        yield
        _PortalHandler.verify_password = None
        _PortalHandler.verified_password = None

    def test_correct_shows_connecting(self, tmp_path):
        _PortalHandler.verify_password = staticmethod(
            pmkid.make_pmkid_verifier(_hash_file(tmp_path)))
        verified, show_connecting = _PortalHandler._evaluate(PW, 1)
        assert verified is True and show_connecting is True

    def test_wrong_shows_retry(self, tmp_path):
        _PortalHandler.verify_password = staticmethod(
            pmkid.make_pmkid_verifier(_hash_file(tmp_path)))
        verified, show_connecting = _PortalHandler._evaluate("nottheone", 1)
        assert verified is False and show_connecting is False

    def test_verifier_exception_is_safe(self):
        def boom(_pw):
            raise RuntimeError("bad")
        _PortalHandler.verify_password = staticmethod(boom)
        verified, show_connecting = _PortalHandler._evaluate("whatever1", 1)
        assert verified is False and show_connecting is False

    def test_no_verifier_legacy_heuristic(self):
        # Without a verifier: first attempt looks wrong, second is accepted.
        assert _PortalHandler._evaluate("guess123", 1) == (None, False)
        assert _PortalHandler._evaluate("guess123", 2) == (None, True)

"""
Unit tests for modules/scanner.py security classification + band resolution.

Pure logic only — no airodump, no RF. Verifies that the tier classifier tells
Enterprise/OWE/SAE apart from crackable PSK networks (so the capture engine
never wastes its budget) and that band-aware scanning picks the right
airodump-ng --band flag.
"""
from __future__ import annotations

import pytest

from modules import scanner
from modules.scanner import (
    classify_security, is_dictionary_crackable, enrich_network,
    SEC_WPA3_SAE, SEC_WPA3_TRANS, SEC_WPA3_ENT, SEC_WPA2, SEC_WPA2_ENT,
    SEC_WPA, SEC_OWE, SEC_WEP, SEC_OPEN,
)


def _net(privacy="", auth="", cipher=""):
    return {"privacy": privacy, "auth": auth, "cipher": cipher}


class TestClassifySecurity:
    def test_wpa2_psk(self):
        r = classify_security(_net("WPA2", "PSK", "CCMP"))
        assert r["security_tier"] == SEC_WPA2
        assert r["crackable"] is True
        assert r["enterprise"] is False
        assert r["wpa3_downgrade_risk"] is False

    def test_wpa2_enterprise(self):
        r = classify_security(_net("WPA2", "MGT", "CCMP"))
        assert r["security_tier"] == SEC_WPA2_ENT
        assert r["crackable"] is False           # no PSK to guess
        assert r["enterprise"] is True

    def test_wpa3_sae_only(self):
        r = classify_security(_net("WPA3", "SAE", "CCMP"))
        assert r["security_tier"] == SEC_WPA3_SAE
        assert r["crackable"] is False
        assert r["wpa3_downgrade_risk"] is False

    def test_wpa3_transition(self):
        r = classify_security(_net("WPA2 WPA3", "PSK SAE", "CCMP"))
        assert r["security_tier"] == SEC_WPA3_TRANS
        assert r["crackable"] is True            # the WPA2 4-way is attackable
        assert r["wpa3_downgrade_risk"] is True

    def test_wpa3_transition_via_auth_only(self):
        # Some APs advertise privacy WPA2 but auth "PSK SAE".
        r = classify_security(_net("WPA2", "PSK SAE"))
        assert r["security_tier"] == SEC_WPA3_TRANS
        assert r["wpa3_downgrade_risk"] is True

    def test_wpa3_enterprise(self):
        r = classify_security(_net("WPA3", "MGT SAE", "GCMP"))
        assert r["security_tier"] == SEC_WPA3_ENT
        assert r["crackable"] is False
        assert r["enterprise"] is True

    def test_wpa1_legacy(self):
        r = classify_security(_net("WPA", "PSK", "TKIP"))
        assert r["security_tier"] == SEC_WPA
        assert r["crackable"] is True

    def test_owe(self):
        r = classify_security(_net("OWE", "OWE", "CCMP"))
        assert r["security_tier"] == SEC_OWE
        assert r["crackable"] is False

    def test_wep(self):
        r = classify_security(_net("WEP", "", "WEP"))
        assert r["security_tier"] == SEC_WEP
        assert r["crackable"] is False           # own key-recovery path

    def test_open(self):
        r = classify_security(_net("", "", ""))
        assert r["security_tier"] == SEC_OPEN
        assert r["crackable"] is False


class TestIsDictionaryCrackable:
    @pytest.mark.parametrize("tier", [SEC_WPA2, SEC_WPA, SEC_WPA3_TRANS])
    def test_crackable(self, tier):
        assert is_dictionary_crackable(tier) is True

    @pytest.mark.parametrize("tier", [
        SEC_WPA3_SAE, SEC_WPA3_ENT, SEC_WPA2_ENT, SEC_OWE, SEC_WEP, SEC_OPEN,
    ])
    def test_not_crackable(self, tier):
        assert is_dictionary_crackable(tier) is False

    def test_empty_is_attempted(self):
        # Unknown classification must not silently skip a real target.
        assert is_dictionary_crackable("") is True
        assert is_dictionary_crackable(None) is True

    def test_raw_privacy_strings(self):
        # Robust to raw airodump strings, not just SEC_* constants.
        assert is_dictionary_crackable("WPA2 WPA3") is True
        assert is_dictionary_crackable("WPA2-EAP") is False
        assert is_dictionary_crackable("MGT") is False


class TestEnrichBand:
    def test_band_tagged(self):
        n = enrich_network({"ssid": "x", "bssid": "AA:BB:CC:DD:EE:FF",
                            "channel": 36, "privacy": "WPA2", "auth": "PSK"})
        assert n["band"] == "5"
        assert n["security_tier"] == SEC_WPA2

    def test_band_24(self):
        n = enrich_network({"ssid": "y", "bssid": "AA:BB:CC:DD:EE:FF",
                            "channel": 6, "privacy": "WPA2", "auth": "PSK"})
        assert n["band"] == "2.4"


class TestResolveBandFlag:
    def test_explicit_choices(self):
        assert scanner._resolve_band_flag("wlan0", "2.4") == "bg"
        assert scanner._resolve_band_flag("wlan0", "5") == "a"
        assert scanner._resolve_band_flag("wlan0", "all") == "abg"

    def test_auto_uses_phy(self, monkeypatch):
        from modules import radio
        monkeypatch.setattr(radio, "interface_bands", lambda i: {"2.4", "5"})
        assert scanner._resolve_band_flag("wlan0", "auto") == "bga"

    def test_auto_falls_back_to_bg(self, monkeypatch):
        from modules import radio
        monkeypatch.setattr(radio, "interface_bands", lambda i: set())
        assert scanner._resolve_band_flag("wlan0", "auto") == "bg"

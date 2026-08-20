"""
Unit tests for modules/strategy.py — the target-driven crack-strategy engine.

Pure logic. Verifies the fusion of SSID class + vendor + tier + entropy into a
ranked, deduplicated, correctly-ordered plan, and that non-PSK targets yield
nothing.
"""
from __future__ import annotations

from modules import strategy
from modules.strategy import (
    recommend_strategies, primary_strategy, vendor_has_temporal_algo,
    describe_plan,
    S_VENDOR_DEFAULTS, S_TEMPORAL_PSK, S_ISP_PATTERNS, S_PHONE_NUMBERS,
    S_DIGIT_MASKS, S_CUPP_PERSONAL, S_COMMON, S_RULE_BASED, S_MASK_BRUTEFORCE,
)


def _names(target):
    return [s.name for s in recommend_strategies(target)]


class TestNonCrackable:
    def test_enterprise_empty(self):
        assert recommend_strategies({"security_tier": "WPA2_ENT"}) == []

    def test_sae_empty(self):
        assert recommend_strategies({"security_tier": "WPA3_SAE"}) == []

    def test_owe_empty(self):
        assert recommend_strategies({"security_tier": "OWE"}) == []

    def test_wep_empty(self):
        assert recommend_strategies({"security_tier": "WEP"}) == []

    def test_open_empty(self):
        assert recommend_strategies({"security_tier": "OPEN"}) == []

    def test_explicit_crackable_false_wins(self):
        assert recommend_strategies(
            {"security_tier": "WPA2", "crackable": False}) == []

    def test_primary_none(self):
        assert primary_strategy({"security_tier": "WPA2_ENT"}) is None

    def test_describe_empty(self):
        assert "no dictionary-crackable" in describe_plan([])


class TestCrackablePlans:
    def test_default_ssid_prefers_vendor_defaults(self):
        t = {"security_tier": "WPA2", "ssid_tag": "DEFAULT_SSID",
             "vendor": "TP-Link", "bssid": "AA:BB:CC:DD:EE:FF"}
        names = _names(t)
        assert names[0] == S_VENDOR_DEFAULTS
        assert primary_strategy(t) == S_VENDOR_DEFAULTS

    def test_numeric_ssid_phone_numbers(self):
        t = {"security_tier": "WPA2", "ssid_tag": "NUMERIC", "ssid_entropy": 1.8}
        names = _names(t)
        assert names[0] == S_PHONE_NUMBERS
        assert S_DIGIT_MASKS in names

    def test_isp_format(self):
        t = {"security_tier": "WPA2", "ssid_tag": "ISP_FORMAT"}
        assert S_ISP_PATTERNS in _names(t)

    def test_personal_cupp(self):
        t = {"security_tier": "WPA2", "ssid_tag": "PERSONAL_NAME"}
        assert S_CUPP_PERSONAL in _names(t)

    def test_random_hex_deprioritises_dictionary(self):
        t = {"security_tier": "WPA2", "ssid_tag": "RANDOM_HEX"}
        names = _names(t)
        assert S_MASK_BRUTEFORCE in names
        # common list should outrank the mask brute-force for a hex SSID
        assert names.index(S_COMMON) < names.index(S_MASK_BRUTEFORCE)

    def test_transition_mode_is_crackable(self):
        t = {"security_tier": "WPA3_TRANS", "ssid_tag": "ISP_FORMAT", "vendor": "Huawei"}
        assert recommend_strategies(t)          # non-empty

    def test_universal_fallbacks_always_present(self):
        t = {"security_tier": "WPA2", "ssid_tag": "CUSTOM"}
        names = _names(t)
        assert S_COMMON in names and S_RULE_BASED in names

    def test_unknown_tier_still_attempts(self):
        # No tier at all → treat as attemptable (never silently skip).
        assert recommend_strategies({"ssid_tag": "CUSTOM"})


class TestOrderingAndDedup:
    def test_sorted_descending(self):
        t = {"security_tier": "WPA2", "ssid_tag": "DEFAULT_SSID", "vendor": "ZTE"}
        scores = [s.score for s in recommend_strategies(t)]
        assert scores == sorted(scores, reverse=True)

    def test_no_duplicate_names(self):
        t = {"security_tier": "WPA2", "ssid_tag": "DEFAULT_SSID", "vendor": "TP-Link"}
        names = _names(t)
        assert len(names) == len(set(names))

    def test_low_entropy_boosts_common(self):
        low  = {"security_tier": "WPA2", "ssid_tag": "CUSTOM", "ssid_entropy": 1.0}
        high = {"security_tier": "WPA2", "ssid_tag": "CUSTOM", "ssid_entropy": 4.0}
        lc = next(s for s in recommend_strategies(low)  if s.name == S_COMMON)
        hc = next(s for s in recommend_strategies(high) if s.name == S_COMMON)
        assert lc.score > hc.score


class TestVendorTemporal:
    def test_known_vendors(self):
        assert vendor_has_temporal_algo("TP-Link") is True
        assert vendor_has_temporal_algo("Huawei") is True
        assert vendor_has_temporal_algo("ZTE") is True

    def test_unknown_vendor(self):
        assert vendor_has_temporal_algo("Acme Widgets") is False

    def test_empty(self):
        assert vendor_has_temporal_algo("") is False
        assert vendor_has_temporal_algo(None) is False

    def test_temporal_strategy_included_for_known_vendor(self):
        t = {"security_tier": "WPA2", "ssid_tag": "CUSTOM", "vendor": "ZTE"}
        assert S_TEMPORAL_PSK in _names(t)

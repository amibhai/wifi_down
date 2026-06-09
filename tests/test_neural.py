"""Tests for modules/neural.py — Neural Pathfinder."""
from __future__ import annotations

from unittest.mock import patch, MagicMock
import pytest

from modules.neural import (
    AttackBrief, AttackStep,
    _sanitize_scan_data, _rule_based_brief, _infer_risk_flags,
    _parse_openai_response,
)


class TestSanitizeScnData:
    """Verify privacy filtering removes sensitive fields."""

    def test_full_mac_not_included(self) -> None:
        networks = [{
            "bssid":   "AA:BB:CC:DD:EE:FF",
            "ssid":    "TestNet",
            "privacy": "WPA2",
            "channel": 6,
            "vendor":  "TP-Link",
        }]
        safe = _sanitize_scan_data(networks)
        assert len(safe) == 1
        # Only OUI prefix (first 8 chars = XX:XX:XX) allowed
        assert safe[0]["bssid_prefix"] == "AA:BB:CC"
        assert "bssid" not in safe[0]

    def test_client_macs_not_present(self) -> None:
        networks = [{
            "bssid":        "AA:BB:CC:DD:EE:FF",
            "ssid":         "TestNet",
            "privacy":      "WPA2",
            "channel":      6,
            "client_macs":  ["11:22:33:44:55:66"],  # must be stripped
        }]
        safe = _sanitize_scan_data(networks)
        assert "client_macs" not in safe[0]

    def test_essential_fields_present(self) -> None:
        networks = [{
            "bssid":   "AA:BB:CC:DD:EE:FF",
            "ssid":    "HomeNet",
            "privacy": "WPA2",
            "channel": 11,
            "vendor":  "Netgear",
        }]
        safe = _sanitize_scan_data(networks)
        s = safe[0]
        assert s["ssid"]     == "HomeNet"
        assert s["security"] == "WPA2"
        assert s["channel"]  == 11
        assert s["vendor"]   == "Netgear"


class TestRuleBasedFallback:
    """Rule-based sequencer should work without any API key."""

    def test_empty_networks_returns_brief(self) -> None:
        brief = _rule_based_brief([])
        assert isinstance(brief, AttackBrief)
        assert brief.generated_by == "rule_based"

    def test_non_empty_networks_returns_steps(self) -> None:
        networks = [{
            "bssid":      "AA:BB:CC:DD:EE:FF",
            "ssid":       "TestNet",
            "privacy":    "WPA2",
            "channel":    6,
            "power":      -65,
            "vendor":     "TP-Link",
            "wps_enabled": False,
            "wps_locked":  False,
        }]
        brief = _rule_based_brief(networks)
        assert isinstance(brief, AttackBrief)
        assert brief.generated_by == "rule_based"
        assert len(brief.executive_summary) > 0

    def test_wps_locked_flag(self) -> None:
        target = {
            "bssid":      "AA:BB:CC:DD:EE:FF",
            "ssid":       "TestNet",
            "privacy":    "WPA2",
            "channel":    6,
            "power":      -65,
            "wps_enabled": True,
            "wps_locked":  True,
            "ssid_tag":   "",
        }
        flags = _infer_risk_flags(target)
        assert any("lockout" in f.lower() or "lock" in f.lower() for f in flags)

    def test_wpa3_transition_flag(self) -> None:
        target = {
            "bssid":      "AA:BB:CC:DD:EE:FF",
            "ssid":       "TestNet",
            "privacy":    "WPA3/WPA2 Transition",
            "channel":    6,
            "power":      -65,
            "wps_enabled": False,
            "wps_locked":  False,
            "ssid_tag":   "",
        }
        flags = _infer_risk_flags(target)
        assert any("wpa3" in f.lower() or "transition" in f.lower() or "downgrade" in f.lower()
                   for f in flags)


class TestParseOpenAIResponse:
    """Test JSON response parsing from OpenAI."""

    def test_valid_response(self) -> None:
        data = {
            "recommended_path": [
                {
                    "name": "WPS Pixie-Dust",
                    "rationale": "WPS enabled and unlocked",
                    "estimated_time": "2-5 min",
                    "success_probability": "HIGH",
                }
            ],
            "wordlist_hints": ["tplink", "admin"],
            "risk_flags":     ["WPS lockout risk"],
            "executive_summary": "Target uses WPA2 with WPS. PSK attack is viable.",
        }
        brief = _parse_openai_response(data)
        assert len(brief.recommended_path) == 1
        assert brief.recommended_path[0].name == "WPS Pixie-Dust"
        assert brief.wordlist_hints == ["tplink", "admin"]
        assert brief.generated_by == "neural"

    def test_empty_response_returns_empty_brief(self) -> None:
        brief = _parse_openai_response({})
        assert isinstance(brief, AttackBrief)
        assert len(brief.recommended_path) == 0

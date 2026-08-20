"""
Tests for modules/sequencer.py — the security-tier-aware early exits that stop
the planner recommending futile attacks against networks with no PSK.
"""
from __future__ import annotations

from modules.sequencer import AttackSequencer


def _plan(**ap):
    return AttackSequencer().score_target(ap)


class TestNonCrackableEarlyExit:
    def test_wpa3_sae_no_steps(self):
        plan = _plan(bssid="AA:BB:CC:DD:EE:FF", ssid="sae-net",
                     privacy="WPA3", security_tier="WPA3_SAE")
        assert plan.steps == []
        assert any("SAE" in r for r in plan.reasoning)

    def test_wpa2_enterprise_no_steps(self):
        plan = _plan(bssid="AA:BB:CC:DD:EE:FF", ssid="corp",
                     privacy="WPA2", security_tier="WPA2_ENT")
        assert plan.steps == []
        assert any("Enterprise" in r for r in plan.reasoning)

    def test_owe_no_steps(self):
        plan = _plan(bssid="AA:BB:CC:DD:EE:FF", ssid="open-enc",
                     privacy="OWE", security_tier="OWE")
        assert plan.steps == []


class TestCrackablePathStillPlanned:
    def test_wpa2_psk_gets_steps(self):
        plan = _plan(bssid="AA:BB:CC:DD:EE:FF", ssid="home",
                     privacy="WPA2", security_tier="WPA2",
                     wps_enabled=False, power=-55)
        assert len(plan.steps) >= 1        # handshake/PMKID path planned

    def test_transition_mode_is_crackable(self):
        plan = _plan(bssid="AA:BB:CC:DD:EE:FF", ssid="mixed",
                     privacy="WPA2 WPA3", security_tier="WPA3_TRANS",
                     power=-60)
        assert len(plan.steps) >= 1

    def test_wep_still_shortcuts(self):
        plan = _plan(bssid="AA:BB:CC:DD:EE:FF", ssid="oldnet",
                     privacy="WEP", security_tier="WEP")
        assert len(plan.steps) == 1
        assert plan.steps[0].attack_type == "wep_arp_replay"

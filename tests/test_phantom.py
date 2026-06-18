"""Tests for modules/phantom.py — Phantom AP module."""
from __future__ import annotations

from unittest.mock import patch
import pytest


class TestPhantomBasic:
    """Basic phantom_menu behaviour."""

    def test_no_target_returns_early(self) -> None:
        """phantom_menu with target=None should return without any action."""
        from modules.phantom import phantom_menu
        with patch("builtins.input", return_value=""):
            phantom_menu(interface="wlan0mon", target=None)


class TestPhantomConfig:
    """Test hostapd/dnsmasq config file generation."""

    def test_hostapd_conf_mirror(self) -> None:
        from modules.phantom import _write_hostapd_conf, PERSONALITY_MIRROR
        p = _write_hostapd_conf("wlan0", "TestSSID", 6, PERSONALITY_MIRROR)
        try:
            content = p.read_text()
            assert "interface=wlan0" in content
            assert "ssid=TestSSID" in content
            assert "channel=6" in content
        finally:
            p.unlink(missing_ok=True)

    def test_hostapd_conf_upgrade_adds_wpa3(self) -> None:
        from modules.phantom import _write_hostapd_conf, PERSONALITY_UPGRADE
        p = _write_hostapd_conf("wlan0", "TestSSID", 6, PERSONALITY_UPGRADE)
        try:
            content = p.read_text()
            assert "SAE" in content
        finally:
            p.unlink(missing_ok=True)

    def test_dnsmasq_conf_has_dhcp(self) -> None:
        from modules.phantom import _write_dnsmasq_conf
        p = _write_dnsmasq_conf("wlan0", "10.0.0.1")
        try:
            content = p.read_text()
            assert "dhcp-range" in content
            assert "10.0.0.1" in content
        finally:
            p.unlink(missing_ok=True)


class TestPhantomPortal:
    """Test captive portal HTML generation."""

    def test_vendor_specific_portal(self) -> None:
        from modules.phantom import _build_portal_html
        html = _build_portal_html("tplink", "MyNet")
        assert "TP-Link" in html
        assert "MyNet" in html
        assert "password" in html.lower()

    def test_generic_portal_fallback(self) -> None:
        from modules.phantom import _build_portal_html
        html = _build_portal_html("unknownvendor", "TestSSID")
        assert "TestSSID" in html
        assert "<form" in html

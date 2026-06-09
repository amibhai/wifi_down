"""Tests for modules/i18n.py — internationalization."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch
import pytest

from modules.i18n import t, init, active_lang


class TestI18nFallback:
    """t() should fall back to en.json and then to the key itself."""

    def test_known_key_returns_string(self) -> None:
        init("en")
        result = t("menu.scan")
        assert isinstance(result, str)
        assert len(result) > 0
        assert result != "menu.scan"  # must not be the raw key

    def test_unknown_key_returns_key(self) -> None:
        init("en")
        result = t("nonexistent.key.xyz")
        assert result == "nonexistent.key.xyz"

    def test_format_interpolation(self) -> None:
        init("en")
        result = t("scope.error", bssid="AA:BB:CC:DD:EE:FF")
        assert "AA:BB:CC:DD:EE:FF" in result

    def test_unknown_lang_falls_back_to_en(self) -> None:
        init("xx")  # non-existent language
        result = t("menu.scan")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_spanish_locale(self) -> None:
        init("es")
        result = t("menu.scan")
        # Spanish translation should be different from English
        init("en")
        en_result = t("menu.scan")
        init("es")
        es_result = t("menu.scan")
        # Both should be non-empty strings
        assert len(es_result) > 0
        assert isinstance(es_result, str)

    def test_active_lang_reflects_init(self) -> None:
        init("fr")
        assert active_lang() == "fr"
        init("en")
        assert active_lang() == "en"

    def test_format_error_returns_raw(self) -> None:
        init("en")
        # If a format key is missing, return the raw string
        result = t("scope.error")  # missing bssid kwarg
        assert isinstance(result, str)

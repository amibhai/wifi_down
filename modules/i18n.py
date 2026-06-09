#!/usr/bin/env python3
"""
wifi_down — Internationalization (i18n) module.
Exposes t(key) for all user-facing strings.
Language auto-detected from system locale; overrideable via --lang flag or
the WIFI_AUDITOR_LANG environment variable.
"""
from __future__ import annotations

import json
import locale
import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_LOCALE_DIR = Path(__file__).parent.parent / "locale"
_FALLBACK_LANG = "en"

# Loaded translations cache
_strings: dict[str, str] = {}
_active_lang: str = _FALLBACK_LANG


def _load_lang(lang: str) -> dict[str, str]:
    path = _LOCALE_DIR / f"{lang}.json"
    if not path.exists():
        logger.debug("Locale file not found for %s, falling back to %s", lang, _FALLBACK_LANG)
        path = _LOCALE_DIR / f"{_FALLBACK_LANG}.json"
    if not path.exists():
        logger.warning("No locale files found in %s", _LOCALE_DIR)
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Failed to load locale %s: %s", path, exc)
        return {}


def _detect_system_lang() -> str:
    """Return a 2-letter language code from system locale, defaulting to 'en'."""
    # Environment variable override takes highest priority
    env_lang = os.environ.get("WIFI_AUDITOR_LANG", "")
    if env_lang:
        return env_lang[:2].lower()

    try:
        lang_code, _ = locale.getdefaultlocale()
        if lang_code:
            return lang_code[:2].lower()
    except Exception:
        pass
    return _FALLBACK_LANG


def init(lang: Optional[str] = None) -> None:
    """
    Initialize i18n with the given language code.
    Call once at startup (CLI does this via --lang flag or auto-detection).
    """
    global _strings, _active_lang
    resolved = lang if lang else _detect_system_lang()
    _active_lang = resolved
    _strings = _load_lang(resolved)
    # Merge with English fallback so missing keys degrade gracefully
    if resolved != _FALLBACK_LANG:
        en = _load_lang(_FALLBACK_LANG)
        en.update(_strings)
        _strings = en
    logger.debug("i18n initialized: lang=%s, %d strings loaded", _active_lang, len(_strings))


def t(key: str, **kwargs: object) -> str:
    """
    Return the translated string for *key*.
    Falls back to the key itself if the translation is missing.
    Supports Python str.format() style placeholders: t("foo.bar", name="Alice").
    """
    raw = _strings.get(key, key)
    if kwargs:
        try:
            return raw.format(**kwargs)
        except (KeyError, IndexError):
            return raw
    return raw


def active_lang() -> str:
    return _active_lang


# Auto-initialize on import so t() works immediately without explicit init()
init()

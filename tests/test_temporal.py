"""Tests for modules/temporal.py — Temporal Attack Engine."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
import pytest

from modules.temporal import (
    _mac_to_bytes, _find_algorithms, generate_temporal_wordlist,
    WPA_MIN, WPA_MAX, _filter_wpa,
)


class TestMacParsing:
    def test_valid_mac(self) -> None:
        b = _mac_to_bytes("AA:BB:CC:DD:EE:FF")
        assert b == bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])

    def test_invalid_mac_returns_zeros(self) -> None:
        b = _mac_to_bytes("not-a-mac")
        assert b == b"\x00" * 6

    def test_hyphen_delimiter(self) -> None:
        b = _mac_to_bytes("AA-BB-CC-DD-EE-FF")
        assert b == bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])


class TestAlgorithmSelection:
    def test_tp_link_vendor_matches(self) -> None:
        algos = _find_algorithms("TP-Link")
        names = [a.name for a in algos]
        assert any("tp" in n.lower() or "mac" in n.lower() for n in names)

    def test_zte_vendor_matches(self) -> None:
        algos = _find_algorithms("ZTE Corporation")
        names = [a.name for a in algos]
        assert any("zte" in n.lower() for n in names)

    def test_unknown_vendor_returns_generic(self) -> None:
        algos = _find_algorithms("unknown_vendor_xyz")
        assert len(algos) > 0  # Generic algorithms should always match


class TestWPAFilter:
    def test_too_short_filtered(self) -> None:
        candidates = iter(["short", "validpassword123"])
        result = list(_filter_wpa(candidates))
        assert "short" not in result
        assert "validpassword123" in result

    def test_too_long_filtered(self) -> None:
        long_pw = "a" * 64  # > WPA_MAX (63)
        ok_pw   = "a" * 20
        candidates = iter([long_pw, ok_pw])
        result = list(_filter_wpa(candidates))
        assert long_pw not in result
        assert ok_pw in result

    def test_non_printable_filtered(self) -> None:
        candidates = iter(["valid12345678", "invalid\x00chars_here"])
        result = list(_filter_wpa(candidates))
        assert "valid12345678" in result
        assert "invalid\x00chars_here" not in result


class TestWordlistGeneration:
    def test_generates_file(self, tmp_path: Path) -> None:
        out = tmp_path / "temporal_test.txt"
        path, count = generate_temporal_wordlist(
            bssid="AA:BB:CC:DD:EE:FF",
            vendor="TP-Link",
            beacon_timestamp=datetime(2024, 6, 1),
            out_path=out,
        )
        assert path.exists()
        assert count > 0

    def test_all_candidates_are_wpa_valid(self, tmp_path: Path) -> None:
        out = tmp_path / "temporal_valid.txt"
        generate_temporal_wordlist(
            bssid="11:22:33:44:55:66",
            vendor="Netgear",
            beacon_timestamp=datetime(2024, 1, 1),
            out_path=out,
        )
        for line in out.read_text().splitlines():
            assert WPA_MIN <= len(line) <= WPA_MAX, f"Invalid candidate: {line!r}"

    def test_no_duplicates(self, tmp_path: Path) -> None:
        out = tmp_path / "temporal_nodup.txt"
        generate_temporal_wordlist(
            bssid="AA:BB:CC:11:22:33",
            vendor="generic",
            beacon_timestamp=datetime(2024, 3, 15),
            out_path=out,
        )
        lines = out.read_text().splitlines()
        assert len(lines) == len(set(lines)), "Duplicate candidates found"

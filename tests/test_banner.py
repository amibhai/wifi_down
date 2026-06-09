"""Tests for modules/banner.py — animated banner and display helpers."""
from __future__ import annotations

from unittest.mock import patch
import pytest


class TestBannerArt:
    """Test block letter art construction."""

    def test_build_art_rows_five_rows(self) -> None:
        from modules.banner import _build_art_rows
        rows = _build_art_rows()
        assert len(rows) == 5

    def test_all_rows_same_length(self) -> None:
        from modules.banner import _build_art_rows
        rows = _build_art_rows()
        lengths = [len(r) for r in rows]
        # Rows must be equal width (letters are padded to same size)
        assert max(lengths) - min(lengths) <= 0, (
            f"Row lengths differ: {lengths}"
        )

    def test_no_empty_rows(self) -> None:
        from modules.banner import _build_art_rows
        for row in _build_art_rows():
            assert len(row.strip()) > 0

    def test_art_contains_box_drawing_chars(self) -> None:
        from modules.banner import _build_art_rows
        art = "\n".join(_build_art_rows())
        box_chars = set("─│╭╰╮╯╷╵╌╴╶╋┼├┤┬┴")
        assert any(ch in art for ch in box_chars), \
            "Banner art should contain box-drawing characters"


class TestBannerOutput:
    """Test print_banner runs without error in non-animate mode."""

    def test_print_banner_no_animation(self, capsys) -> None:
        from modules.banner import print_banner
        with patch("os.system"):
            print_banner(
                interface="wlan0mon",
                targets=3,
                scope_file="scope.yaml",
                animate=False,
            )
        # Should not raise


class TestDisplayHelpers:
    """Test info/success/warn/error/found helpers."""

    def test_info(self, capsys) -> None:
        from modules.banner import info
        info("test message")
        out = capsys.readouterr().out
        assert "test message" in out

    def test_success(self, capsys) -> None:
        from modules.banner import success
        success("it worked")
        out = capsys.readouterr().out
        assert "it worked" in out

    def test_warn(self, capsys) -> None:
        from modules.banner import warn
        warn("caution")
        out = capsys.readouterr().out
        assert "caution" in out

    def test_error(self, capsys) -> None:
        from modules.banner import error
        error("something failed")
        out = capsys.readouterr().out
        assert "something failed" in out


class TestColors:
    """Colors class backward compatibility."""

    def test_colors_attrs_exist(self) -> None:
        from modules.banner import Colors, C
        for attr in ("RED", "GREEN", "YELLOW", "CYAN", "WHITE", "BOLD", "DIM", "RESET"):
            assert hasattr(Colors, attr)
            assert hasattr(C, attr)

"""Smoke tests for modules/banner.py — ensures banner renders without exception."""
import io
import unittest
from unittest.mock import patch


class TestBannerArt:
    """Test ASCII art constant."""

    def test_art_not_empty(self) -> None:
        from modules.banner import WIFI_DOWN_ART
        assert len(WIFI_DOWN_ART.strip()) > 0

    def test_art_contains_block_chars(self) -> None:
        from modules.banner import WIFI_DOWN_ART
        assert "█" in WIFI_DOWN_ART or "╗" in WIFI_DOWN_ART


class TestBannerOutput:
    """Test print_banner runs without error."""

    def test_print_banner_no_error(self, capsys) -> None:
        from modules.banner import print_banner
        with patch("os.system"), \
             patch("builtins.input", return_value=""), \
             patch("time.sleep"):
            print_banner()
        # Should not raise


    def test_print_menu_does_not_raise(self):
        """print_menu() must not raise regardless of session state contents."""
        from modules.banner import print_menu
        state_empty = {
            "interface": None,
            "monitor_interface": None,
            "target": None,
            "capture_file": None,
            "wordlist_file": None,
            "result": None,
        }
        state_full = {
            "interface": "wlan0",
            "monitor_interface": "wlan0mon",
            "target": {"ssid": "TestNet", "bssid": "AA:BB:CC:DD:EE:FF", "channel": "6"},
            "capture_file": "/tmp/test.cap",
            "wordlist_file": "/tmp/test.txt",
            "result": "password123",
        }
        captured = io.StringIO()
        with patch("sys.stdout", captured):
            print_menu(state_empty)
            print_menu(state_full)

    def test_color_constants_exist(self):
        """C color constants must all be strings (not None)."""
        from modules.banner import C
        for attr in ("RED", "GREEN", "YELLOW", "CYAN", "WHITE", "RESET", "BOLD", "DIM"):
            val = getattr(C, attr, None)
            assert val is not None, f"C.{attr} is missing"
            assert isinstance(val, str), f"C.{attr} is not a string"

    def test_info_outputs_message(self):
        """info() must print the message to stdout."""
        from modules.banner import info
        captured = io.StringIO()
        with patch("sys.stdout", captured):
            info("test message")
        assert "test message" in captured.getvalue()

    def test_success_outputs_message(self):
        """success() must print the message to stdout."""
        from modules.banner import success
        captured = io.StringIO()
        with patch("sys.stdout", captured):
            success("it worked")
        assert "it worked" in captured.getvalue()

    def test_warn_outputs_message(self):
        """warn() must print the message to stdout."""
        from modules.banner import warn
        captured = io.StringIO()
        with patch("sys.stdout", captured):
            warn("caution")
        assert "caution" in captured.getvalue()

    def test_error_outputs_message(self):
        """error() must print the message to stdout."""
        from modules.banner import error
        captured = io.StringIO()
        with patch("sys.stdout", captured):
            error("something failed")
        assert "something failed" in captured.getvalue()

    def test_print_compact_header_does_not_raise(self):
        """print_compact_header() must not raise."""
        from modules.banner import print_compact_header
        captured = io.StringIO()
        with patch("sys.stdout", captured):
            print_compact_header(interface="wlan0mon")
            print_compact_header(interface=None)


if __name__ == "__main__":
    unittest.main()
#

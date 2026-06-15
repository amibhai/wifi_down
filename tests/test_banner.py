"""Smoke tests for modules/banner.py — ensures banner renders without exception."""
import io
import sys
import unittest
from unittest.mock import patch


class TestBanner(unittest.TestCase):

    def test_print_banner_does_not_raise(self):
        """print_banner() must complete without throwing under any terminal width."""
        from modules.banner import print_banner
        captured = io.StringIO()
        with patch("builtins.input", return_value=""), \
             patch("sys.stdout", captured):
            try:
                print_banner()
            except SystemExit:
                pass  # os.system("clear") may raise in test env — acceptable

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

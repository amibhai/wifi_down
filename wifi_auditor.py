#!/usr/bin/env python3
"""
wifi_auditor.py — Legacy entry point. Delegates to wifi_auditor/cli.py.

Prefer: sudo wifi-auditor   (installed via install.sh)
Or:     sudo python3 -m wifi_auditor
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wifi_auditor.cli import main

if __name__ == '__main__':
    main()

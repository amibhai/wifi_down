"""WiFi Auditor exception hierarchy."""
from __future__ import annotations


class WiFiAuditorError(Exception):
    """Base exception for all WiFi Auditor errors."""


class InterfaceError(WiFiAuditorError):
    """Monitor mode or adapter issues."""


class CaptureError(WiFiAuditorError):
    """Handshake/PMKID capture failures."""


class PartialCaptureError(CaptureError):
    """Capture file exists but MIC is incomplete."""

    def __init__(self, message: str, capture_file: str) -> None:
        super().__init__(message)
        self.capture_file = capture_file


class CrackError(WiFiAuditorError):
    """aircrack / hashcat failures."""


class WordlistError(WiFiAuditorError):
    """Wordlist generation or merge failures."""


class ScopeError(WiFiAuditorError):
    """Unauthorized target or scope.yaml violation."""

    def __init__(self, message: str, bssid: str | None = None) -> None:
        super().__init__(message)
        self.bssid = bssid


class DependencyError(WiFiAuditorError):
    """Missing required binary or wrong version."""

    def __init__(self, message: str, binary: str | None = None) -> None:
        super().__init__(message)
        self.binary = binary

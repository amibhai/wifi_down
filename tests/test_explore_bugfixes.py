"""Regression tests for the from-scratch exploration bug-fix pass.

Each test pins a specific bug found while exploring the tool end to end:
  • wep_crack_menu option [4] called an undefined `_crack_loop` → NameError
  • fingerprint._VENDOR_IE_MAP had a duplicate 00:17:f2 key → every Apple
    device was mislabeled "Apple HomeKit / likely static key"
  • `python -m wifi_auditor` was documented but had no package __main__
"""
from __future__ import annotations

from unittest import mock

# ── WEP: "crack existing .cap" (mode 4) reaches the real cracker ─────────────

def test_wep_menu_mode4_uses_real_cracker():
    """Option [4] must call _crack_wep_attempt, not the removed _crack_loop."""
    from modules import wep

    # The bug was a hard reference to a name that never existed.
    assert not hasattr(wep, "_crack_loop")

    target = {"ssid": "Net", "bssid": "AA:BB:CC:DD:EE:FF",
              "channel": 6, "privacy": "WEP"}

    with mock.patch("builtins.input", side_effect=["4", "/tmp/have.cap"]), \
         mock.patch("modules.wep.os.path.exists", return_value=True), \
         mock.patch("modules.wep._crack_wep_attempt",
                    return_value="AB:CD:EF:12:34") as crack, \
         mock.patch("modules.wep._save_wep_result") as save:
        key = wep.wep_crack_menu("wlan0mon", target)

    assert key == "AB:CD:EF:12:34"
    crack.assert_called_once_with("/tmp/have.cap")
    save.assert_called_once()


def test_wep_menu_mode4_missing_file_returns_none():
    from modules import wep
    target = {"ssid": "Net", "bssid": "AA:BB:CC:DD:EE:FF",
              "channel": 6, "privacy": "WEP"}
    with mock.patch("builtins.input", side_effect=["4", "/nope.cap"]), \
         mock.patch("modules.wep.os.path.exists", return_value=False):
        assert wep.wep_crack_menu("wlan0mon", target) is None


# ── Fingerprint: a generic Apple vendor IE is not called HomeKit ─────────────

def test_apple_oui_maps_to_generic_apple():
    from modules.fingerprint import _VENDOR_IE_MAP
    assert _VENDOR_IE_MAP[b"\x00\x17\xf2"] == "Apple"


def test_generic_apple_device_not_mislabeled_homekit():
    from modules.fingerprint import DeviceFingerprint, _identify_device
    d = DeviceFingerprint(bssid="AA:BB:CC:DD:EE:FF")
    d.vendor_ies = ["Apple"]
    label = _identify_device(d)
    assert "HomeKit" not in label
    assert "static key" not in label
    assert label == "Apple device (Mac / iPhone / iPad)"


# ── `python -m wifi_auditor` entry point exists ─────────────────────────────

def test_package_has_runnable_main():
    import importlib
    mod = importlib.import_module("wifi_auditor.__main__")
    assert callable(mod.main)


# ── ratelimit: a 0/negative burst limit must not hang forever ───────────────

def test_tokenbucket_zero_limit_does_not_deadlock():
    """TokenBucket(0) used to have fill_rate 0 → wait_for_token() looped forever."""
    from modules.ratelimit import TokenBucket
    tb = TokenBucket(0)
    assert tb.capacity >= 1
    # A token must eventually be available (proves the bucket can refill).
    assert tb.consume() is True


def test_deauth_rate_limiter_clamps_nonpositive():
    from modules.ratelimit import DeauthRateLimiter
    lim = DeauthRateLimiter(max_bursts_per_min=-5)
    # wait_for_burst() must not block on a valid, refillable bucket.
    lim.wait_for_burst("AA:BB:CC:DD:EE:FF")   # returns => no deadlock
    assert lim.get_stats("AA:BB:CC:DD:EE:FF")["capacity"] >= 1

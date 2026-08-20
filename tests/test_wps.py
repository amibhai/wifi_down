"""Unit tests for modules/wps.py lockout backoff scheduling (pure logic)."""
from __future__ import annotations

from modules.wps import lockout_backoff_schedule


class TestLockoutBackoff:
    def test_default_shape(self):
        s = lockout_backoff_schedule()
        assert s == [60, 120]

    def test_exponential(self):
        s = lockout_backoff_schedule(max_waits=4, base=10, factor=2.0, cap=10_000)
        assert s == [10, 20, 40, 80]

    def test_cap_applied(self):
        s = lockout_backoff_schedule(max_waits=5, base=100, factor=3.0, cap=300)
        assert s == [100, 300, 300, 300, 300]

    def test_zero_waits(self):
        assert lockout_backoff_schedule(max_waits=0) == []

    def test_negative_waits_safe(self):
        assert lockout_backoff_schedule(max_waits=-3) == []

    def test_monotonic_nondecreasing(self):
        s = lockout_backoff_schedule(max_waits=6, base=30, factor=1.5, cap=200)
        assert all(b >= a for a, b in zip(s, s[1:]))
        assert all(x <= 200 for x in s)

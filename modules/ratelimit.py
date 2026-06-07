"""Token-bucket rate limiter for deauth frame injection."""
from __future__ import annotations

import threading
import time
from collections import defaultdict

DEFAULT_MAX_BURSTS_PER_MIN = 5
MAX_ALLOWED_BURSTS_PER_MIN = 20
HARD_CAP_FRAMES_PER_SEC    = 100


class TokenBucket:
    """
    Classic leaky-bucket with:
      capacity  = max_bursts (tokens)
      fill rate = max_bursts / 60  tokens per second
    """

    def __init__(self, max_bursts: int = DEFAULT_MAX_BURSTS_PER_MIN) -> None:
        self._capacity    = float(min(max_bursts, MAX_ALLOWED_BURSTS_PER_MIN))
        self._tokens      = self._capacity
        self._fill_rate   = self._capacity / 60.0   # tokens/second
        self._last_check  = time.monotonic()
        self._lock        = threading.Lock()

    def consume(self, tokens: float = 1.0) -> bool:
        """Try to consume *tokens*. Returns True if allowed."""
        with self._lock:
            now     = time.monotonic()
            elapsed = now - self._last_check
            self._last_check = now
            self._tokens = min(self._capacity, self._tokens + elapsed * self._fill_rate)
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def wait_for_token(self) -> None:
        """Block until a token is available (polls every 0.5 s)."""
        while not self.consume():
            time.sleep(0.5)

    @property
    def available(self) -> float:
        with self._lock:
            return round(self._tokens, 2)

    @property
    def capacity(self) -> float:
        return self._capacity


class DeauthRateLimiter:
    """
    Per-BSSID token buckets + a global frames-per-second hard cap.

    Usage:
        limiter = DeauthRateLimiter(max_bursts_per_min=5)
        # Before each burst:
        limiter.wait_for_burst(bssid)
        # Before each individual frame:
        if not limiter.record_frame():
            time.sleep(0.1)   # global cap hit
    """

    def __init__(self, max_bursts_per_min: int = DEFAULT_MAX_BURSTS_PER_MIN) -> None:
        self._max_bursts = min(max_bursts_per_min, MAX_ALLOWED_BURSTS_PER_MIN)
        self._buckets: dict[str, TokenBucket] = defaultdict(
            lambda: TokenBucket(self._max_bursts)
        )
        self._global_frames   = 0
        self._window_start    = time.monotonic()
        self._lock            = threading.Lock()

    def check_burst(self, bssid: str) -> bool:
        """Non-blocking: returns True if a burst is allowed right now."""
        return self._buckets[bssid.upper()].consume()

    def wait_for_burst(self, bssid: str) -> None:
        """Block until a burst token is available for *bssid*."""
        self._buckets[bssid.upper()].wait_for_token()

    def record_frame(self) -> bool:
        """
        Record one injected frame against the global hard cap.
        Returns False if the cap (HARD_CAP_FRAMES_PER_SEC) is exceeded.
        """
        with self._lock:
            now = time.monotonic()
            if now - self._window_start >= 1.0:
                self._global_frames = 0
                self._window_start  = now
            if self._global_frames >= HARD_CAP_FRAMES_PER_SEC:
                return False
            self._global_frames += 1
            return True

    def get_stats(self, bssid: str) -> dict:
        bssid = bssid.upper()
        bucket = self._buckets[bssid]
        return {
            "bssid":              bssid,
            "tokens_remaining":   bucket.available,
            "capacity":           int(bucket.capacity),
            "max_bursts_per_min": self._max_bursts,
            "global_fps":         self._global_frames,
            "hard_cap_fps":       HARD_CAP_FRAMES_PER_SEC,
        }

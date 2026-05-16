"""Token-bucket rate limiter tests.

Cover four behaviours:

1. Burst within capacity acquires immediately.
2. Beyond capacity acquires wait until tokens refill.
3. ``timeout=0`` (well, very small) returns ``False`` when bucket is dry.
4. Env override + disable flag work as documented.

We re-enable ratelimit locally via ``monkeypatch.delenv`` because the
session conftest disables every known source by default to keep the
broader test suite fast.
"""

from __future__ import annotations

import os
import time

from ioc_tool.core import ratelimit


def _force_enable(monkeypatch, key: str = "VIRUSTOTAL") -> None:
    """Drop the session-level disable flag for this test only."""
    monkeypatch.delenv(f"RATELIMIT_{key}_DISABLE", raising=False)
    ratelimit.reset()


def test_burst_within_capacity(monkeypatch):
    _force_enable(monkeypatch)
    bucket = ratelimit.get_bucket("virustotal")
    assert bucket is not None
    # Default cap is 4 — burst all four immediately.
    for _ in range(4):
        assert bucket.acquire(timeout=0.05) is True


def test_beyond_capacity_blocks_then_succeeds(monkeypatch):
    """Custom bucket: 2 tokens, refilling every 0.1s. Burst then wait."""
    monkeypatch.setenv("RATELIMIT_VIRUSTOTAL", "2/0.2")  # 2 tokens / 200 ms
    monkeypatch.delenv("RATELIMIT_VIRUSTOTAL_DISABLE", raising=False)
    ratelimit.reset()

    bucket = ratelimit.get_bucket("virustotal")
    assert bucket is not None
    assert bucket.acquire(timeout=0.01) is True
    assert bucket.acquire(timeout=0.01) is True
    # Third token must wait ~100 ms for refill.
    started = time.monotonic()
    assert bucket.acquire(timeout=1.0) is True
    elapsed = time.monotonic() - started
    assert 0.05 < elapsed < 0.5


def test_timeout_returns_false_when_dry(monkeypatch):
    monkeypatch.setenv("RATELIMIT_VIRUSTOTAL", "1/60")  # 1 token per minute
    monkeypatch.delenv("RATELIMIT_VIRUSTOTAL_DISABLE", raising=False)
    ratelimit.reset()

    bucket = ratelimit.get_bucket("virustotal")
    assert bucket is not None
    assert bucket.acquire(timeout=0.01) is True   # consume the only token
    started = time.monotonic()
    assert bucket.acquire(timeout=0.05) is False  # next one times out fast
    elapsed = time.monotonic() - started
    # Tight bound — the helper should give up well under a second.
    assert elapsed < 0.5


def test_disable_env_skips_bucket(monkeypatch):
    monkeypatch.setenv("RATELIMIT_VIRUSTOTAL_DISABLE", "1")
    ratelimit.reset()
    assert ratelimit.get_bucket("virustotal") is None
    # The convenience wrapper still returns True so callers don't have
    # to special-case the disabled path.
    assert ratelimit.acquire("virustotal") is True


def test_unknown_source_returns_none(monkeypatch):
    # Strip any session-level overrides for our synthetic key.
    for env in list(os.environ):
        if env.startswith("RATELIMIT_NEVER"):
            monkeypatch.delenv(env, raising=False)
    ratelimit.reset()
    # No default + no env override → no bucket → acquire is a no-op.
    assert ratelimit.get_bucket("never-heard-of-this") is None
    assert ratelimit.acquire("never-heard-of-this") is True


def test_env_override_parses(monkeypatch):
    monkeypatch.setenv("RATELIMIT_VIRUSTOTAL", "10/1")
    monkeypatch.delenv("RATELIMIT_VIRUSTOTAL_DISABLE", raising=False)
    ratelimit.reset()
    bucket = ratelimit.get_bucket("virustotal")
    assert bucket is not None
    assert bucket.capacity == 10.0
    assert bucket.refill_per_sec == 10.0


def test_env_override_malformed_falls_back(monkeypatch):
    monkeypatch.setenv("RATELIMIT_VIRUSTOTAL", "garbage")
    monkeypatch.delenv("RATELIMIT_VIRUSTOTAL_DISABLE", raising=False)
    ratelimit.reset()
    bucket = ratelimit.get_bucket("virustotal")
    # Bad value silently falls back to the default 4/60.
    assert bucket is not None
    assert bucket.capacity == 4.0

"""Per-source token-bucket rate limiter for upstream API calls.

Free tiers throttle aggressively (VirusTotal: 4 req/min, AbuseIPDB:
1000/day, IPQS: 5000/month). Without a local limiter every enrichment
burst can wallpaper a source with 429s for the rest of the day.

This module gives the enrichment pipeline a *cooperative* limiter:
each per-source bucket holds N tokens that refill at a steady rate.
Callers ``acquire(timeout)`` a token before issuing a request; if
the bucket is empty the call sleeps until a token regenerates (or
``timeout`` expires, in which case the caller backs off and returns
no data — same convention as a real 429).

Thread-safe (``threading.Lock``); intentionally process-local — we
don't try to coordinate across multiple ShadowScope processes
because the cache layer is already per-process.

Configuration shape::

    Bucket(capacity=4, refill_per_sec=4/60)  # 4 req/min, burst 4

Buckets are looked up by source key. The defaults below match the
public free-tier docs; an analyst can override via ``RATELIMIT_<KEY>``
env vars (format ``CAPACITY/PERIOD`` e.g. ``4/60`` for 4 every 60 s,
or ``RATELIMIT_VT_DISABLE=1`` to opt out entirely for that source).
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass


@dataclass
class Bucket:
    """A single token bucket. ``capacity`` is also the burst size.

    Concurrency model: a single :class:`threading.Condition` guards both
    the ``tokens`` state and the wakeups. ``acquire`` enters the
    condition, refills, and either consumes a token immediately or
    ``wait()``s on the condition for a bounded interval (using
    ``Condition.wait(timeout=...)`` so it's interrupted both by the
    deadline and by a sibling thread's notify). On wakeup it refills
    again and retries.

    Why a Condition rather than the prior ``with lock: ... lock.release()
    + time.sleep() + lock.acquire()`` dance: the manual release-inside-
    ``with`` pattern raises ``RuntimeError: release unlocked lock`` if
    a sibling thread also tries to refill / release in the same window
    — the context manager then tries to release a lock the manual call
    already gave back. ``Condition`` makes the lifetime explicit: the
    ``with self._cond:`` block owns the lock for the duration; sleeping
    happens via ``wait()`` which atomically drops the lock and reclaims
    it on wakeup.
    """

    capacity: float
    refill_per_sec: float
    tokens: float = 0.0
    last_refill: float = 0.0
    # ``Condition`` wraps a re-entrant ``RLock`` by default; we use it
    # purely as the lock + wait/notify pair. ``init=False`` so the
    # dataclass doesn't insist on a positional argument at construction.
    _cond: threading.Condition = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self._cond is None:
            self._cond = threading.Condition()
        self.tokens = self.capacity
        self.last_refill = time.monotonic()

    def _refill_locked(self, now: float) -> None:
        """Top up tokens based on elapsed monotonic time.

        Caller must hold ``self._cond``. If any tokens were added, notify
        waiters — they may now have enough to proceed.
        """
        elapsed = now - self.last_refill
        if elapsed <= 0:
            return
        before = self.tokens
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_sec)
        self.last_refill = now
        if self.tokens > before:
            # Some token quantum was added — wake any waiter that might
            # now be able to proceed. notify_all is cheap for our small
            # contended pools and avoids the "wrong waiter woken" edge.
            self._cond.notify_all()

    def acquire(self, timeout: float = 30.0) -> bool:
        """Consume one token. Returns ``False`` if ``timeout`` elapses first.

        Every code path exits with the condition lock released cleanly
        (handled by the ``with`` block); waiters are woken either by
        ``_refill_locked`` topping the bucket up, or by another thread
        releasing the lock at the end of its own ``acquire``.
        """
        deadline = time.monotonic() + timeout
        with self._cond:
            while True:
                now = time.monotonic()
                self._refill_locked(now)
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return True
                remaining = deadline - now
                if remaining <= 0:
                    return False
                # How long until we *could* have a fresh token?  Sleep
                # up to that interval (capped by the overall deadline).
                # ``Condition.wait`` atomically releases the lock and
                # reclaims it before returning, so no manual
                # release/acquire dance is needed.
                wait = (1.0 - self.tokens) / self.refill_per_sec
                self._cond.wait(timeout=min(wait, remaining))


# Public free-tier defaults. Tuned conservatively — easy to bump per
# install via env. Period in seconds.
_DEFAULT_BUCKETS: dict[str, tuple[float, float]] = {
    # source_key: (capacity, period_seconds)
    "virustotal":   (4, 60),       # 4 req/min
    "abuseipdb":    (40, 60),      # 1000 / day ~ 40 / hour, smoothed
    "ipqs":         (4, 60),       # cautious — free tier is monthly
    "shodan":       (1, 1),        # 1 req/sec
    "otx":          (10, 60),
    "urlscan":      (2, 60),       # very tight free tier
    "pulsedive":    (10, 60),
    "greynoise":    (10, 60),
    "abstract":     (10, 60),
    "censys":       (10, 60),
    # Blocklist / catalog fetches — large files refreshed on a long TTL
    # (24 h) not per-IOC, so a low-and-slow rate is appropriate.
    "tor":          (4, 3600),     # 4 / hour — exit list is daily
    "kev":          (4, 3600),     # 4 / hour — CISA catalog is daily
    "feodo":        (4, 3600),     # 4 / hour — abuse.ch blocklist
    "sslbl":        (4, 3600),     # 4 / hour — abuse.ch blocklist
    "urlhaus":      (4, 3600),     # 4 / hour — abuse.ch blocklist
    "threatfox":    (4, 3600),     # 4 / hour — abuse.ch blocklist
    # Per-IOC enrichment APIs — public, no-auth, no published quota.
    "epss":         (30, 60),      # FIRST.org — generous
    "asn":          (10, 60),      # RIPE Stat — generous, polite cap
    "ipinfo":       (20, 60),      # free tier ~50k / month
    "crtsh":        (4, 60),       # public CT search, can be slow
    "nvd":          (5, 30),       # NVD: 5 / 30 s unauthenticated
    "pdns":         (5, 60),       # Mnemonic free tier — be polite
    # Sandbox / submission APIs — caps per their published free tiers.
    "hybrid_analysis": (5, 60),    # public-key tier ~200 / hour
    "malwarebazaar": (10, 60),     # abuse.ch — generous
    "filescan_io":  (5, 60),       # community tier
    "joe_sandbox":  (4, 60),       # Joe Cloud free is very tight
    # Outbound webhook receivers (SIEM / ticketing / IR platforms). Most are
    # idempotent so a comfortable 10/sec ceiling keeps bursts polite while
    # still letting bulk enrichments fan out.
    "webhook":      (10, 1),
}

_buckets: dict[str, Bucket] = {}
_buckets_lock = threading.Lock()


def _env_override(source_key: str) -> tuple[float, float] | None:
    """Parse ``RATELIMIT_<KEY>=CAPACITY/PERIOD``. Returns None if unset."""
    raw = os.getenv(f"RATELIMIT_{source_key.upper()}")
    if not raw:
        return None
    try:
        cap_str, period_str = raw.split("/", 1)
        return (float(cap_str), float(period_str))
    except (ValueError, TypeError):
        return None


def _is_disabled(source_key: str) -> bool:
    return os.getenv(f"RATELIMIT_{source_key.upper()}_DISABLE", "").strip() in (
        "1", "true", "yes", "on"
    )


def get_bucket(source_key: str) -> Bucket | None:
    """Return (lazily-created) bucket for ``source_key`` or ``None`` when disabled."""
    if _is_disabled(source_key):
        return None
    with _buckets_lock:
        bucket = _buckets.get(source_key)
        if bucket is not None:
            return bucket
        config = _env_override(source_key) or _DEFAULT_BUCKETS.get(source_key)
        if config is None:
            return None
        capacity, period = config
        bucket = Bucket(capacity=capacity, refill_per_sec=capacity / period)
        _buckets[source_key] = bucket
        return bucket


def acquire(source_key: str, *, timeout: float = 30.0) -> bool:
    """Convenience wrapper. ``True`` if a token was consumed or no bucket exists."""
    bucket = get_bucket(source_key)
    if bucket is None:
        return True
    return bucket.acquire(timeout=timeout)


def reset() -> None:
    """Test-only: clear bucket registry so each test starts fresh."""
    with _buckets_lock:
        _buckets.clear()

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
    """A single token bucket. ``capacity`` is also the burst size."""

    capacity: float
    refill_per_sec: float
    tokens: float = 0.0
    last_refill: float = 0.0
    lock: threading.Lock = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.lock is None:
            self.lock = threading.Lock()
        self.tokens = self.capacity
        self.last_refill = time.monotonic()

    def _refill_locked(self, now: float) -> None:
        elapsed = now - self.last_refill
        if elapsed <= 0:
            return
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_sec)
        self.last_refill = now

    def acquire(self, timeout: float = 30.0) -> bool:
        """Consume one token. Returns ``False`` if ``timeout`` elapses first."""
        deadline = time.monotonic() + timeout
        with self.lock:
            while True:
                now = time.monotonic()
                self._refill_locked(now)
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return True
                # Tokens needed = 1 - tokens (positive fractional).
                wait = (1.0 - self.tokens) / self.refill_per_sec
                if now + wait > deadline:
                    return False
                # Release the lock while sleeping so other threads can
                # acquire if a token regenerates concurrently.
                self.lock.release()
                try:
                    time.sleep(min(wait, deadline - now))
                finally:
                    self.lock.acquire()


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

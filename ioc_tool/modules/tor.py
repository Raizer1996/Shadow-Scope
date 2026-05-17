"""Tor exit-node check — local cache of the public torbulkexitlist.

We mirror the Tor Project's authoritative list at
``check.torproject.org/torbulkexitlist`` to a local file and consult it
on every IP enrichment. The list moves slowly (exit relays are stable
on the order of days/weeks), so we refresh on a staleness window rather
than on every call.

Refresh policy:
  * file missing                           → fetch
  * file older than ``TOR_LIST_TTL_HOURS`` → fetch (default 24 h)
  * fetch failure                          → keep the stale file, never
                                             crash the caller

The env var ``TOR_LIST_TTL_HOURS`` overrides the default for users who
want a tighter (or looser) refresh cadence.
"""

import os
import time

from ..core import http

TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"
CACHE_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'tor_nodes.txt')

_DEFAULT_TTL_HOURS = 24.0

# Per-source bucket — exit list is refreshed on a 24h TTL, so a
# low-and-slow rate (4/hour) is plenty.
_SOURCE = "tor"


def _ttl_seconds() -> float:
    """Resolve the refresh TTL in seconds from ``TOR_LIST_TTL_HOURS``."""
    raw = os.getenv("TOR_LIST_TTL_HOURS", "").strip()
    if not raw:
        return _DEFAULT_TTL_HOURS * 3600
    try:
        hours = float(raw)
    except ValueError:
        return _DEFAULT_TTL_HOURS * 3600
    if hours <= 0:
        return _DEFAULT_TTL_HOURS * 3600
    return hours * 3600


def _cache_is_stale() -> bool:
    """True when the cache is missing or older than the TTL."""
    if not os.path.exists(CACHE_FILE):
        return True
    try:
        age = time.time() - os.path.getmtime(CACHE_FILE)
    except OSError:
        return True
    return age > _ttl_seconds()


def update_tor_list() -> bool:
    """Fetch the latest exit-node list. Returns True on success."""
    response = http.get(_SOURCE, TOR_EXIT_LIST_URL, timeout=5)
    if response is None:
        return False
    try:
        if response.status_code == 200:
            os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
            with open(CACHE_FILE, 'w') as f:
                f.write(response.text)
            return True
    except Exception:
        return False
    return False


def is_tor_node(ip: str) -> bool:
    """Return True if ``ip`` is a known Tor exit relay.

    Refreshes the cache when it's missing or stale, but never crashes
    on network failure — a stale cache is preferable to a noisy
    enrichment pipeline.
    """
    if _cache_is_stale():
        update_tor_list()

    try:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE) as f:
                for line in f:
                    if ip == line.strip():
                        return True
    except Exception:
        pass

    return False

"""abuse.ch Feodo Tracker enrichment.

Feodo Tracker is a free, no-auth botnet C2 blocklist maintained by
abuse.ch. It tracks live C2 infrastructure for the major banking-trojan
families (Emotet, Heodo, TrickBot, IcedID, Dridex). Same vendor as the
URLhaus, ThreatFox, MalwareBazaar, and SSLBL modules elsewhere in the
project.

The full blocklist is a single JSON file — we mirror it to disk and
look up enrichments against the local cache. Same pattern as the Tor
exit-list module: refresh on staleness, fall back to the stale copy
if the fetch fails.

API docs: https://feodotracker.abuse.ch/blocklist/
Feed URL: https://feodotracker.abuse.ch/downloads/ipblocklist.json

Returns ``None`` for IPs not in the list (the common case) or on
fetch / parse failure — never raises.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

from ..core import http

FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
CACHE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "data",
    "feodo_blocklist.json",
)
_DEFAULT_TTL_HOURS = 24.0
_TIMEOUT = 10  # seconds — preserve original tuned override

# Per-source bucket — blocklist refreshed on 24h TTL, low-and-slow.
_SOURCE = "feodo"


def _ttl_seconds() -> float:
    raw = os.getenv("FEODO_LIST_TTL_HOURS", "").strip()
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
    if not os.path.exists(CACHE_FILE):
        return True
    try:
        return (time.time() - os.path.getmtime(CACHE_FILE)) > _ttl_seconds()
    except OSError:
        return True


def refresh_blocklist() -> bool:
    """Fetch the Feodo Tracker JSON blocklist to local cache. True on success."""
    response = http.get(_SOURCE, FEED_URL, timeout=_TIMEOUT)
    if response is None:
        return False
    if response.status_code != 200:
        return False
    try:
        payload = response.json()
    except ValueError:
        return False
    if not isinstance(payload, list):
        return False
    try:
        os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
        with open(CACHE_FILE, "w") as f:
            json.dump(payload, f)
    except OSError:
        return False
    return True


def _load_index() -> dict[str, dict[str, Any]]:
    """Load the blocklist JSON and index it by ``ip_address``."""
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, list):
        return {}
    index: dict[str, dict[str, Any]] = {}
    for entry in data:
        if isinstance(entry, dict):
            ip = entry.get("ip_address")
            if isinstance(ip, str):
                index[ip] = entry
    return index


def enrich_ip(value: str) -> dict | None:
    """Return the Feodo Tracker entry for ``value`` or ``None`` if not listed.

    Refreshes the local cache on staleness, but never raises — a fetch
    failure with no prior cache yields ``None`` rather than crashing the
    orchestrator.
    """
    if _cache_is_stale():
        refresh_blocklist()
    index = _load_index()
    entry = index.get(value)
    if entry is None:
        return None
    # Return a stable subset — the upstream feed adds/removes fields
    # over time and we don't want surprises in our cache rows.
    return {
        "ip_address": entry.get("ip_address"),
        "port": entry.get("port"),
        "status": entry.get("status"),
        "malware": entry.get("malware"),
        "first_seen": entry.get("first_seen"),
        "last_online": entry.get("last_online"),
        "as_number": entry.get("as_number"),
        "as_name": entry.get("as_name"),
        "country": entry.get("country"),
    }

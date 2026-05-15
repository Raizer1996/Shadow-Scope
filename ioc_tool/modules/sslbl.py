"""abuse.ch SSL Blacklist (SSLBL) enrichment.

SSLBL is a free, no-auth blocklist of TLS certificate SHA-1 fingerprints
associated with malware C2 (Cobalt Strike, Quakbot, BazarLoader, etc.).
Same vendor / pattern as the URLhaus, ThreatFox, MalwareBazaar, and
Feodo modules.

We mirror the JSON feed to disk and check incoming SHA-1 hashes
against the local cache. SSLBL is keyed exclusively on SHA-1 — MD5 /
SHA-256 hashes never produce hits and return ``None`` without making a
network call.

API docs: https://sslbl.abuse.ch/blacklist/
Feed URL: https://sslbl.abuse.ch/blacklist/sslblacklist.json
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

import requests

FEED_URL = "https://sslbl.abuse.ch/blacklist/sslblacklist.json"
CACHE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "data",
    "sslbl_blacklist.json",
)
_DEFAULT_TTL_HOURS = 24.0
_TIMEOUT = 10


def _ttl_seconds() -> float:
    raw = os.getenv("SSLBL_LIST_TTL_HOURS", "").strip()
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
    try:
        response = requests.get(FEED_URL, timeout=_TIMEOUT)
    except requests.exceptions.RequestException:
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
    """Index entries by lowercased SHA-1."""
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
        if not isinstance(entry, dict):
            continue
        sha1 = entry.get("SHA1") or entry.get("sha1") or entry.get("SHA-1")
        if isinstance(sha1, str):
            index[sha1.lower()] = entry
    return index


def enrich_hash(value: str) -> dict | None:
    """Look up a SHA-1 fingerprint in SSLBL. MD5 / SHA-256 inputs return ``None``."""
    if len(value) != 40:
        return None  # SSLBL is SHA-1-only; short-circuit non-SHA1 inputs
    if _cache_is_stale():
        refresh_blocklist()
    entry = _load_index().get(value.lower())
    if entry is None:
        return None
    return {
        "sha1": value.lower(),
        "listing_date": entry.get("Listingdate") or entry.get("listing_date"),
        "malware": entry.get("Listingreason") or entry.get("malware"),
        "dst_ip": entry.get("DstIP") or entry.get("dst_ip"),
        "dst_port": entry.get("DstPort") or entry.get("dst_port"),
    }

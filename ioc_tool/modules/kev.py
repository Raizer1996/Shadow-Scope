"""CISA KEV (Known Exploited Vulnerabilities) catalog client.

CISA publishes a JSON catalog of CVEs that have been actively exploited
in the wild. We download the full catalog once, cache it on disk, and
do membership lookups locally — same pattern as the Tor exit-node list
(:mod:`ioc_tool.modules.tor`).

Catalog URL:
    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Refresh policy: re-download if the local file is missing or older than
24 hours. On network error during refresh, fall back to the existing
cached file if present; otherwise return an empty result.

Each catalog entry contains at minimum::

    {
        "cveID": "CVE-2024-...",
        "dateAdded": "2024-...",
        "vendorProject": "...",
        "product": "...",
        "vulnerabilityName": "...",
        "requiredAction": "...",
        "dueDate": "2024-...",
        "knownRansomwareCampaignUse": "Known" | "Unknown"
    }
"""

from __future__ import annotations

import json
import os
import time

from ..core import http

CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
CACHE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "cisa_kev.json"
)
REFRESH_SECONDS = 24 * 60 * 60  # 24 hours
TIMEOUT = 10  # seconds — preserve the original tuned override

# Per-source bucket — catalog is fetched on a 24h TTL, low-and-slow.
_SOURCE = "kev"


def _cache_is_stale() -> bool:
    """Return True when the on-disk cache is missing or older than 24 h."""
    if not os.path.exists(CACHE_FILE):
        return True
    try:
        mtime = os.path.getmtime(CACHE_FILE)
    except OSError:
        return True
    return (time.time() - mtime) > REFRESH_SECONDS


def _download_catalog() -> dict | None:
    """Fetch the catalog and persist it to ``CACHE_FILE``.

    Returns the parsed catalog dict on success, ``None`` on any failure.
    The cache file is only written when the parse succeeds — we never
    overwrite a previously-good cache with garbage.
    """
    response = http.get(_SOURCE, CATALOG_URL, timeout=TIMEOUT)
    if response is None:
        return None

    if response.status_code != 200:
        return None

    try:
        payload = response.json()
    except ValueError:
        return None

    if not isinstance(payload, dict):
        return None

    try:
        os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
        with open(CACHE_FILE, "w") as f:
            json.dump(payload, f)
    except OSError:
        # Couldn't persist — still return the in-memory copy so the
        # current call works. Next call will retry.
        pass

    return payload


def _read_cached_catalog() -> dict | None:
    """Load the previously-cached catalog from disk. ``None`` on error."""
    if not os.path.exists(CACHE_FILE):
        return None
    try:
        with open(CACHE_FILE) as f:
            payload = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _get_catalog() -> dict | None:
    """Return the catalog dict, refreshing the on-disk cache if stale.

    Refresh policy: re-download when the file is missing or >24 h old.
    On network failure during refresh, fall back to the existing cache
    if present; otherwise return ``None``.
    """
    if _cache_is_stale():
        fresh = _download_catalog()
        if fresh is not None:
            return fresh
        # Network failure: try the existing cached copy as a fallback.
        return _read_cached_catalog()

    return _read_cached_catalog()


def load_catalog() -> set[str]:
    """Return the set of CVE IDs in the CISA KEV catalog.

    Refreshes the on-disk cache if missing/stale (>24 h). Falls back to
    the existing cache on network failure. Returns an empty set if no
    catalog is available at all.
    """
    catalog = _get_catalog()
    if not catalog:
        return set()
    vulnerabilities = catalog.get("vulnerabilities") or []
    return {
        entry["cveID"]
        for entry in vulnerabilities
        if isinstance(entry, dict) and "cveID" in entry
    }


def get_kev_entry(value: str) -> dict | None:
    """Return the full KEV catalog entry for ``value``, or ``None``.

    The returned dict includes ``dateAdded``, ``vendorProject``,
    ``product``, ``vulnerabilityName``, ``requiredAction``,
    ``dueDate``, and ``knownRansomwareCampaignUse`` (plus whatever
    else CISA publishes on a given entry).
    """
    catalog = _get_catalog()
    if not catalog:
        return None
    vulnerabilities = catalog.get("vulnerabilities") or []
    for entry in vulnerabilities:
        if isinstance(entry, dict) and entry.get("cveID") == value:
            return entry
    return None

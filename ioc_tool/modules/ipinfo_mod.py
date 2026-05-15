"""IPinfo enrichment client.

Returns geolocation + ASN + carrier metadata for an IP. Free tier
without a key works for a few requests per day; setting
``IPINFO_API_KEY`` (token) raises the quota and unlocks privacy /
abuse / company endpoints.

Reads ``IPINFO_API_KEY`` first; falls back to the historical
``IP_INFO_API`` name so users with old ``.env`` files don't silently
stop seeing IPinfo data after upgrade.
"""

from __future__ import annotations

import os

import requests

BASE_URL = "https://ipinfo.io"
TIMEOUT = 10


def _api_key() -> str:
    return (
        os.getenv("IPINFO_API_KEY")
        or os.getenv("IP_INFO_API")  # legacy alias
        or ""
    ).strip()


def enrich_ip(ip: str) -> dict | None:
    """Fetch IPinfo data for ``ip``. Returns ``None`` on miss / network error.

    Anonymous queries return a limited subset; a token returns the full
    object (org, abuse, privacy, company). Either is useful — the
    dashboard surfaces whichever fields are present.
    """
    api_key = _api_key()
    params = {"token": api_key} if api_key else None
    try:
        response = requests.get(
            f"{BASE_URL}/{ip}",
            params=params,
            timeout=TIMEOUT,
            headers={"Accept": "application/json"},
        )
    except requests.exceptions.RequestException:
        return None
    if response.status_code != 200:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None

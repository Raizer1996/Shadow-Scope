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
    object (org, abuse, privacy, company). When the token carries the
    Privacy Detection tier we also fetch ``/privacy/{ip}`` and merge it
    under a ``privacy`` key — the dashboard surfaces ``privacy.service``
    (e.g. ``ProtonVPN``) when present.
    """
    api_key = _api_key()
    params = {"token": api_key} if api_key else None
    headers = {"Accept": "application/json"}
    try:
        response = requests.get(
            f"{BASE_URL}/{ip}",
            params=params,
            timeout=TIMEOUT,
            headers=headers,
        )
    except requests.exceptions.RequestException:
        return None
    if response.status_code != 200:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None

    # If we have a token, also hit Privacy Detection to surface VPN brand /
    # proxy / tor / relay / hosting flags. Silently no-op if the token tier
    # doesn't include it (403/404/empty).
    if api_key and not isinstance(payload.get("privacy"), dict):
        try:
            priv = requests.get(
                f"{BASE_URL}/{ip}/privacy",
                params=params,
                timeout=TIMEOUT,
                headers=headers,
            )
            if priv.status_code == 200:
                pdata = priv.json()
                if isinstance(pdata, dict):
                    payload["privacy"] = pdata
        except (requests.exceptions.RequestException, ValueError):
            pass

    return payload

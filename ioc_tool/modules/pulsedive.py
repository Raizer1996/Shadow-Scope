"""Pulsedive enrichment client.

Pulsedive is a free threat-intelligence aggregator with its own built-in
risk score (0-100, surfaced under ``risk``: ``unknown`` / ``none`` /
``low`` / ``medium`` / ``high`` / ``critical``). Anonymous queries are
rate-limited but otherwise functional — an API key (``PULSEDIVE_API_KEY``)
unlocks higher quota.

API docs: https://pulsedive.com/api/
Endpoint: ``GET /info.php?indicator=<value>&pretty=1[&key=...]``

Returns the parsed JSON on a hit, ``None`` on miss / non-200 / network
error — never raises. Supports IP, domain, and URL IOC types.
"""

from __future__ import annotations

import os

import requests

BASE_URL = "https://pulsedive.com/api/info.php"
TIMEOUT = 10


def enrich(value: str, ioc_type: str) -> dict | None:
    """Look up an IP / domain / URL in Pulsedive.

    The free endpoint accepts the indicator as a query parameter and
    returns either an indicator object (hit) or an ``{"error": ...}``
    envelope. We treat the error envelope as ``None`` so the analyst
    sees a clean miss rather than a spurious match.
    """
    if ioc_type not in {"ip", "domain", "url"}:
        return None

    params = {"indicator": value, "pretty": "1"}
    api_key = os.getenv("PULSEDIVE_API_KEY", "").strip()
    if api_key:
        params["key"] = api_key

    try:
        response = requests.get(BASE_URL, params=params, timeout=TIMEOUT)
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
    if payload.get("error"):
        return None
    # Strip the heavyweight fields — properties / attributes can balloon
    # the cache row by KB. Keep the analyst-facing summary.
    return {
        "indicator": payload.get("indicator"),
        "type": payload.get("type"),
        "risk": payload.get("risk"),
        "risk_recommended": payload.get("risk_recommended"),
        "manualrisk": payload.get("manualrisk"),
        "stamp_added": payload.get("stamp_added"),
        "stamp_updated": payload.get("stamp_updated"),
        "stamp_seen": payload.get("stamp_seen"),
        "threats": payload.get("threats") or [],
        "feeds": payload.get("feeds") or [],
        "comments": payload.get("comments") or [],
    }

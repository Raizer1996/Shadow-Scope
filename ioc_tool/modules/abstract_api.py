"""AbstractAPI IP Geolocation enrichment.

AbstractAPI's IP-geolocation endpoint augments the basic IPinfo/Shodan
geo data with explicit anonymisation flags (Tor / VPN / proxy / relay /
hosting / residential proxy) — useful as a second opinion alongside
IPQS and the Tor exit list.

Free tier: 20K req/month. Higher tiers + the "Security" addon unlock
the anonymisation flags.

API: https://app.abstractapi.com/api/ip-geolocation/documentation
Endpoint: ``GET https://ipgeolocation.abstractapi.com/v1/?api_key=KEY&ip_address=IP``

Returns the parsed JSON on success, ``None`` on miss / network error /
malformed response / quota exceeded. Never raises.
"""

from __future__ import annotations

import os

import requests

BASE_URL = "https://ipgeolocation.abstractapi.com/v1/"
TIMEOUT = 10


def enrich_ip(ip: str) -> dict | None:
    """Look up an IP on AbstractAPI's geolocation+security endpoint."""
    api_key = os.getenv("ABSTRACT_API_KEY", "").strip()
    if not api_key:
        return None
    try:
        response = requests.get(
            BASE_URL,
            params={"api_key": api_key, "ip_address": ip},
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
    if not isinstance(payload, dict) or payload.get("error"):
        return None
    return payload

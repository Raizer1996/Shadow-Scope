"""AbstractAPI IP Intelligence enrichment.

AbstractAPI's IP-intelligence endpoint returns geolocation + security
flags (Tor / VPN / proxy / relay / hosting / residential proxy / abuser)
plus ASN + connection metadata. Useful as a second-opinion source
alongside IPQS, GreyNoise, and the Tor exit list.

Env-var resolution (first non-empty wins):
  1. ``ABSTRACT_IP_INTELLIGENCE`` — current product name on the
     AbstractAPI dashboard
  2. ``ABSTRACT_API_KEY``         — historical generic alias used by
     earlier versions of this module
  3. ``ABSTRACT_IP_API_KEY``      — alternate alias some setups use

API docs: https://app.abstractapi.com/api/ip-intelligence/documentation
Endpoint: ``https://ip-intelligence.abstractapi.com/v1/?api_key=KEY&ip_address=IP``

Returns the parsed JSON on success, ``None`` on miss / network error /
malformed response / quota exceeded. Never raises.
"""

from __future__ import annotations

import os

from ..core import http

BASE_URL = "https://ip-intelligence.abstractapi.com/v1/"
TIMEOUT = 10  # tuned override — endpoint is fast

# Per-source bucket key — uses the existing ``abstract`` registry entry
# (default 10 req/min) which matches AbstractAPI's free-tier ceiling.
_SOURCE = "abstract"


def _api_key() -> str:
    for name in ("ABSTRACT_IP_INTELLIGENCE", "ABSTRACT_API_KEY", "ABSTRACT_IP_API_KEY"):
        v = os.getenv(name, "").strip()
        if v:
            return v
    return ""


def enrich_ip(ip: str) -> dict | None:
    """Look up an IP on AbstractAPI's IP-intelligence endpoint."""
    api_key = _api_key()
    if not api_key:
        return None
    response = http.get(
        _SOURCE,
        BASE_URL,
        params={"api_key": api_key, "ip_address": ip},
        timeout=TIMEOUT,
        headers={"Accept": "application/json"},
    )
    if response is None:
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

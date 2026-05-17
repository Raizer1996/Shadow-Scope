"""GreyNoise Community API enrichment client.

GreyNoise classifies IP addresses by whether they're **internet background
noise** (mass scanners like Censys, Shodan, Project Sonar, Mirai botnet
nodes, etc.) versus **targeted** activity aimed at the querier.

In SOC triage this is a major false-positive killer — a sizable fraction
of routine IP alerts are benign internet-wide scanning, and GreyNoise
tells you that immediately so the analyst can move on.

API docs: https://docs.greynoise.io/reference/community-api

Endpoint (free Community tier, 50 lookups/day per key)::

    GET https://api.greynoise.io/v3/community/<ip>
    Header: key: <API_KEY>
    Header: Accept: application/json

Response (hit)::

    {
      "ip": "8.8.8.8",
      "noise": false,
      "riot": true,
      "classification": "benign",
      "name": "Google Public DNS",
      "link": "https://viz.greynoise.io/...",
      "last_seen": "2024-12-01",
      "message": "Success"
    }

Response (no info / 404)::

    {
      "ip": "...",
      "noise": false,
      "riot": false,
      "classification": "unknown",
      "message": "IP not observed scanning the internet or contained in RIOT data set"
    }

Per project convention API failures (missing key, network error, non-200)
return ``None`` and never raise.
"""

from __future__ import annotations

import os

from ..core import http

BASE_URL = "https://api.greynoise.io/v3/community"
TIMEOUT = 10  # tuned override — Community endpoint is fast

# Per-source bucket key — registry default caps GreyNoise at 10 req/min;
# the free Community tier is 50 lookups/day.
_SOURCE = "greynoise"


def enrich_ip(value: str) -> dict | None:
    """Look up an IP in the GreyNoise Community API.

    Returns the full response dict on success — even when the
    ``classification`` field is ``"unknown"``, because that's still
    useful signal for scoring (a known-unobserved IP differs from a
    network-error miss). Returns ``None`` when:

    - the ``GREYNOISE_API_KEY`` env var is unset / empty
    - the HTTP request raises ``requests.exceptions.RequestException``
    - the response status code is not 200
    - the response body is not valid JSON
    """
    api_key = os.getenv("GREYNOISE_API_KEY")
    if not api_key:
        return None

    headers = {
        "key": api_key,
        "Accept": "application/json",
    }

    response = http.get(
        _SOURCE,
        f"{BASE_URL}/{value}",
        headers=headers,
        timeout=TIMEOUT,
    )
    if response is None:
        return None

    if response.status_code != 200:
        return None

    try:
        return response.json()
    except ValueError:
        return None

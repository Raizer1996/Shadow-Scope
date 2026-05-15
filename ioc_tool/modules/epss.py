"""FIRST.org EPSS (Exploit Prediction Scoring System) enrichment client.

EPSS surfaces a probability (0.0–1.0) that a CVE will be exploited in
the wild over the next 30 days, plus a percentile rank against all
known CVEs. Free, no API key.

API docs: https://www.first.org/epss/api

Response shape::

    {
        "status": "OK",
        "data": [
            {
                "cve": "CVE-2024-...",
                "epss": "0.97412",
                "percentile": "0.99876",
                "date": "2024-..."
            }
        ]
    }

Following the project convention: API failures return ``None`` and
never raise.
"""

from __future__ import annotations

import requests

BASE_URL = "https://api.first.org/data/v1/epss"
TIMEOUT = 10  # seconds


def enrich_cve(value: str) -> dict | None:
    """Look up a CVE in EPSS.

    Returns the first entry from ``data[]`` on a hit (a dict with
    ``cve``, ``epss``, ``percentile``, ``date`` keys) or ``None`` on
    no-hit / network error / non-200 status / malformed payload.
    """
    try:
        response = requests.get(
            BASE_URL,
            params={"cve": value},
            timeout=TIMEOUT,
        )
    except requests.exceptions.RequestException:
        return None

    if response.status_code != 200:
        return None

    try:
        payload = response.json()
    except ValueError:
        return None

    data = payload.get("data")
    if not data or not isinstance(data, list):
        return None

    first = data[0]
    if not isinstance(first, dict):
        return None
    return first

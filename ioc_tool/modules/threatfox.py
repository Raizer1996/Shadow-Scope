"""abuse.ch ThreatFox enrichment client.

ThreatFox is a free, community-maintained database of fresh IOCs
(IPs, domains, URLs, hashes) tied to malware families, botnet C2,
and other malicious infrastructure. No API key required.

API docs: https://threatfox.abuse.ch/api/

Single POST endpoint:
- ``/api/v1/`` — JSON body ``{"query": "search_ioc", "search_term": "<value>"}``

Following the project convention: API failures return ``None`` and
never raise. A successful HTTP 200 with ``query_status != "ok"``
(``no_result`` / ``illegal_search_term`` / etc.) is also treated as a
miss → ``None``.

On a hit, the wire response contains a ``data`` array — we surface
only the first entry (``data[0]``) to keep the return shape flat and
consistent with the other enrichment modules.
"""

from __future__ import annotations

from typing import Optional

import requests

BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"
TIMEOUT = 10  # seconds


def enrich(value: str) -> Optional[dict]:
    """Look up any IOC (ip, domain, url, hash) in ThreatFox.

    Returns the first matching entry from ``data[]`` on a hit
    (``query_status == "ok"``), or ``None`` on no-hit / network
    error / non-200 status / malformed payload.
    """
    try:
        response = requests.post(
            BASE_URL,
            json={"query": "search_ioc", "search_term": value},
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

    if payload.get("query_status") != "ok":
        return None

    data = payload.get("data")
    if not data or not isinstance(data, list):
        return None

    first = data[0]
    if not isinstance(first, dict):
        return None
    return first

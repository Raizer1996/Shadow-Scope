"""abuse.ch URLhaus enrichment client.

URLhaus is a free, community-maintained database of malicious URLs
(phishing, malware drops, C2 panels). No API key required.

API docs: https://urlhaus-api.abuse.ch/

Two POST endpoints are supported:
- ``/v1/url/`` — body ``url=<full-url>`` — looks up a specific URL
- ``/v1/host/`` — body ``host=<domain-or-ip>`` — looks up a host's URL history

Both helpers follow the project convention: API failures return ``None``
and never raise. A successful HTTP 200 with ``query_status != "ok"``
(typically ``no_results``) is also treated as a miss → ``None``.
"""

from __future__ import annotations

from ..core import http

BASE_URL = "https://urlhaus-api.abuse.ch/v1"
TIMEOUT = 10  # seconds — preserve original tuned override

# Per-source bucket — abuse.ch is generous; per-IOC lookups are cheap.
_SOURCE = "urlhaus"


def enrich_url(value: str) -> dict | None:
    """Look up a URL in URLhaus.

    Returns the parsed response dict on a hit (``query_status == "ok"``),
    or ``None`` on no-hit / network error / non-200 status.
    """
    response = http.post(
        _SOURCE,
        f"{BASE_URL}/url/",
        data={"url": value},
        timeout=TIMEOUT,
    )
    if response is None:
        return None

    if response.status_code != 200:
        return None

    try:
        payload = response.json()
    except ValueError:
        return None

    if payload.get("query_status") != "ok":
        return None

    return payload


def enrich_host(value: str) -> dict | None:
    """Look up a domain or IP host in URLhaus.

    Returns the response dict (typically including ``url_count`` and a
    ``urls`` array of historical malicious URLs) on a hit, or ``None``
    on no-hit / error.
    """
    response = http.post(
        _SOURCE,
        f"{BASE_URL}/host/",
        data={"host": value},
        timeout=TIMEOUT,
    )
    if response is None:
        return None

    if response.status_code != 200:
        return None

    try:
        payload = response.json()
    except ValueError:
        return None

    if payload.get("query_status") != "ok":
        return None

    return payload

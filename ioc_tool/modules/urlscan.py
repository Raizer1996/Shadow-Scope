"""URLscan.io enrichment client.

URLscan.io is an on-demand URL scanning service — submit a URL and it
visits the page in a sandboxed browser, captures a screenshot, the
full HTTP transaction tree, JavaScript, and any redirects. For
ShadowScope we use only the **search** API which queries the public
archive of *previously-submitted* scans. Submitting a fresh scan takes
10+ seconds and doesn't fit a synchronous enrichment workflow; reading
historical scans is instant.

API docs: https://urlscan.io/docs/api/

Endpoint shape::

    GET https://urlscan.io/api/v1/search/?q=<lucene-query>
    Header: API-Key: <key>   # optional — anon allowed at lower quota

Free-tier quota:

- 100 unauthenticated requests / day
- 200 authenticated requests / day (+ a search-API allowance that's
  generous in practice)

So a missing ``URLSCAN_API_KEY`` is **not** a hard failure — the module
still issues the request, just without the auth header. The user simply
hits the lower quota sooner.

Per-IOC-type Lucene query mapping:

- ``ip``     → ``page.ip:"<value>"``
- ``domain`` → ``domain:"<value>"``
- ``url``    → ``page.url:"<value>"``
- ``hash``   → unsupported (URLscan indexes URLs, not files) → ``None``

A zero-history response (``total == 0``) is still a 200 with a valid
body — that's a *negative* signal (we looked, nothing was there) so the
module surfaces it; only missing-type, network errors, and non-200s
collapse to ``None``.
"""

from __future__ import annotations

import os

import requests

BASE_URL = "https://urlscan.io/api/v1/search/"
TIMEOUT = 10  # seconds

# Map ShadowScope's internal IOC type names onto URLscan Lucene query fields.
_QUERY_FIELD = {
    "ip": "page.ip",
    "domain": "domain",
    "url": "page.url",
}


def enrich(value: str, ioc_type: str) -> dict | None:
    """Search URLscan.io historical scans for an IOC.

    ``ioc_type`` is the ShadowScope-internal type: ``'ip'``,
    ``'domain'``, or ``'url'``. ``'hash'`` is explicitly **not** supported
    by URLscan (it indexes URLs, not files) and short-circuits to
    ``None`` without making a request.

    Returns the full search response dict — including the top-level
    ``total`` count and ``results`` list — on a successful 200, even
    when ``total == 0``. A confirmed-absent indicator is still useful
    signal versus a network-error miss.

    The ``URLSCAN_API_KEY`` env var is **optional**. When present it is
    sent as the ``API-Key`` header (raising the daily quota). When
    missing, the request still goes out unauthenticated — URLscan's
    public search API allows anonymous reads at a lower quota.

    Returns ``None`` when:

    - ``ioc_type`` is not one of ``ip`` / ``domain`` / ``url``
    - the HTTP request raises ``requests.exceptions.RequestException``
    - the response status code is not 200
    - the response body is not valid JSON
    """
    field = _QUERY_FIELD.get(ioc_type)
    if not field:
        return None

    headers = {"Accept": "application/json"}
    api_key = os.getenv("URLSCAN_API_KEY")
    if api_key:
        headers["API-Key"] = api_key

    params = {"q": f'{field}:"{value}"'}

    try:
        response = requests.get(
            BASE_URL,
            headers=headers,
            params=params,
            timeout=TIMEOUT,
        )
    except requests.exceptions.RequestException:
        return None

    if response.status_code != 200:
        return None

    try:
        return response.json()
    except ValueError:
        return None

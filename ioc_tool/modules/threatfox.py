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

from ..core import http
from . import _abusech

BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"
TIMEOUT = 10  # seconds — preserve original tuned override

# Per-source bucket — abuse.ch is generous; per-IOC lookups are cheap.
_SOURCE = "threatfox"


def enrich(value: str) -> dict | None:
    """Look up any IOC (ip, domain, url, hash) in ThreatFox.

    Returns the highest-confidence *exact* match from ``data[]`` on a hit
    (``query_status == "ok"``), or ``None`` on no-hit / network
    error / non-200 status / malformed payload.
    """
    if not _abusech.configured():
        return None  # abuse.ch answers 401 without an Auth-Key; skip the round-trip
    response = http.post(
        _SOURCE,
        BASE_URL,
        json={"query": "search_ioc", "search_term": value},
        headers=_abusech.auth_headers(),
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

    data = payload.get("data")
    if not data or not isinstance(data, list):
        return None
    # ``search_ioc`` is a *substring* search: "google.com" returns
    # sites.google.com/... and drive.google.com/... malware URLs. Taking
    # data[0] turned every popular apex into a ThreatFox "hit" (80). Only an
    # entry whose IOC *is* the queried value counts; the rest are related
    # IOCs, reported as a count for pivoting but never scored.
    exact = [d for d in data if isinstance(d, dict) and _is_exact(d, value)]
    if not exact:
        return None
    best = max(exact, key=lambda d: _conf(d))
    related = len(data) - len(exact)
    if related:
        best = {**best, "related_hits": related}
    return best


def _conf(entry: dict) -> int:
    try:
        return int(entry.get("confidence_level") or 0)
    except (TypeError, ValueError):
        return 0


def _is_exact(entry: dict, value: str) -> bool:
    """True when ``entry['ioc']`` denotes exactly ``value`` (not a sub/superstring)."""
    ioc = str(entry.get("ioc") or "").strip().lower()
    want = (value or "").strip().lower()
    if not ioc or not want:
        return False
    if ioc == want:
        return True
    kind = str(entry.get("ioc_type") or "")
    if kind == "ip:port":
        return ioc.rsplit(":", 1)[0] == want
    if kind == "url":
        return ioc.rstrip("/") == want.rstrip("/")
    return False

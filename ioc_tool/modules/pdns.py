"""Passive DNS (PDNS) — first-seen / last-seen / IP age enrichment.

Surfaces historical resolution data for IP IOCs from public passive-DNS
collectors. The signal is **info-only** — first/last-seen tell an analyst
how long an IP has been answering DNS queries for some hostname, which
is useful context (brand-new infrastructure vs. long-lived backbone)
but doesn't by itself constitute "malicious". We never push the
composite score from this source.

Primary provider: **Mnemonic PassiveDNS** (free tier, no auth required
for low-volume queries). REST endpoint::

    https://api.mnemonic.no/pdns/v3/<query>

Response is a JSON envelope::

    {
        "data": [
            {"query": "...", "answer": "...",
             "firstSeenTimestamp": 1647260400000,   # epoch ms
             "lastSeenTimestamp":  1684157400000,
             "count": 12},
            ...
        ]
    }

Secondary provider hook: **CIRCL Passive DNS** — newline-delimited JSON
behind HTTP basic auth. Activated only when ``CIRCL_USERNAME`` /
``CIRCL_PASSWORD`` env vars are set. v1 keeps Mnemonic as the only
implemented path; the CIRCL env hooks are left as placeholders in
``ioc_tool/.env.example`` for a later expansion.

Module output schema::

    {
        "first_seen": "2024-03-14T12:00:00Z",   # ISO 8601, UTC
        "last_seen":  "2026-05-15T08:42:00Z",
        "age_days":   794,
        "record_count": 12,
        "top_rrnames": ["example.com", "other.example.com"],  # max 5
        "source": "mnemonic",
    }

Returns ``{}`` (NOT ``None``) on soft-fail so the orchestrator records
an empty info-only row instead of repeatedly hitting the upstream for
every cache miss. The cache layer treats ``None`` as "no row"; an empty
dict still lets the cache short-circuit the next call.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..core import http

# Mnemonic free tier — anonymous, very low rate. We cap to 5/min via the
# rate-limit bucket below (see core/ratelimit._DEFAULT_BUCKETS).
_MNEMONIC_BASE = "https://api.mnemonic.no/pdns/v3"
_SOURCE = "pdns"
_TIMEOUT_S = 10.0

# How many distinct rrnames to surface. The full list can be hundreds of
# entries for popular CDN edge IPs; the analyst really just needs to know
# "did this IP serve a small handful of names or thousands?"
_MAX_RRNAMES = 5


def _epoch_ms_to_iso(value: Any) -> str | None:
    """Mnemonic timestamps are epoch milliseconds. Normalise → ISO-UTC."""
    if value is None:
        return None
    try:
        seconds = float(value) / 1000.0
    except (TypeError, ValueError):
        return None
    try:
        dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    # Drop microseconds for a tidy ``YYYY-MM-DDTHH:MM:SSZ`` shape.
    return dt.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _age_days(first_seen_ms: Any) -> int | None:
    """Compute whole-day age from epoch-ms first-seen."""
    if first_seen_ms is None:
        return None
    try:
        seconds = float(first_seen_ms) / 1000.0
    except (TypeError, ValueError):
        return None
    try:
        first = datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    delta = datetime.now(tz=timezone.utc) - first
    return max(delta.days, 0)


def _parse_mnemonic(payload: dict[str, Any]) -> dict[str, Any]:
    """Reduce a Mnemonic PDNS envelope to our compact schema.

    Returns ``{}`` when the envelope has no usable records — callers
    rely on the soft-fail convention.
    """
    if not isinstance(payload, dict):
        return {}
    rows = payload.get("data")
    if not isinstance(rows, list) or not rows:
        return {}

    first_seen_ms: int | None = None
    last_seen_ms: int | None = None
    total_count = 0
    rrname_counts: dict[str, int] = {}

    for row in rows:
        if not isinstance(row, dict):
            continue

        # Mnemonic field name varies by API version — accept both.
        fs = row.get("firstSeenTimestamp")
        if fs is None:
            fs = row.get("time_first")
        ls = row.get("lastSeenTimestamp")
        if ls is None:
            ls = row.get("time_last")

        try:
            fs_int = int(fs) if fs is not None else None
        except (TypeError, ValueError):
            fs_int = None
        try:
            ls_int = int(ls) if ls is not None else None
        except (TypeError, ValueError):
            ls_int = None

        if fs_int is not None and (first_seen_ms is None or fs_int < first_seen_ms):
            first_seen_ms = fs_int
        if ls_int is not None and (last_seen_ms is None or ls_int > last_seen_ms):
            last_seen_ms = ls_int

        try:
            count = int(row.get("count", 1) or 1)
        except (TypeError, ValueError):
            count = 1
        total_count += count

        rrname = row.get("query") or row.get("rrname")
        if isinstance(rrname, str) and rrname:
            rrname_counts[rrname] = rrname_counts.get(rrname, 0) + count

    if first_seen_ms is None and last_seen_ms is None and not rrname_counts:
        return {}

    top_rrnames = [
        name
        for name, _ in sorted(rrname_counts.items(), key=lambda kv: -kv[1])
    ][:_MAX_RRNAMES]

    result: dict[str, Any] = {
        "first_seen": _epoch_ms_to_iso(first_seen_ms),
        "last_seen": _epoch_ms_to_iso(last_seen_ms),
        "age_days": _age_days(first_seen_ms),
        "record_count": total_count,
        "top_rrnames": top_rrnames,
        "source": "mnemonic",
    }
    return result


def enrich_ip(ip: str) -> dict[str, Any]:
    """Query Mnemonic free PDNS for ``ip``. IP IOCs only.

    Returns the parsed dict on success, an **empty dict** on soft-fail
    (no records / bucket exhausted / HTTP error / malformed JSON). The
    empty-dict convention is intentional — info-only sources don't push
    the composite score, but we still want to persist a row so the
    cache short-circuits the next call.
    """
    if not ip:
        return {}

    url = f"{_MNEMONIC_BASE}/{ip}"
    response = http.get(_SOURCE, url, timeout=_TIMEOUT_S)
    if response is None:
        return {}
    if response.status_code != 200:
        return {}
    try:
        payload = response.json()
    except ValueError:
        return {}

    return _parse_mnemonic(payload)

"""ctlogs.dev certificate-transparency enrichment — primary CT source.

Replaces crt.sh as the first CT backend: ~50 ms answers, proper JSON,
paging, and no 502s on large zones. crt.sh stays wired as the fallback
(see ``core.enrich._ct_fetch``) for when ctlogs is unreachable or over
quota.

Output is the **same shape** the crt.sh module produces, so the scorer
(``score.calculate_crtsh_score``), the dashboard synthesis and the cache
rows (source key ``crtsh``, display ``crt.sh``) keep working unchanged.
A ``provider`` field says which backend answered.

Limits (https://api.ctlogs.dev/#auth): keyless or free key = 100 requests
per UTC hour, one in flight at a time; free key = 10 000 credits/month.
Every plan sees certificates valid now or expired within the last 90 days —
``total`` is therefore a 90-day count, not all-time like crt.sh.

Two calls per domain (2 credits):

* ``GET /v1/hosts/{domain}``   — one row per hostname with a recent cert
  (subdomain list, per-host cert counts, first/last seen).
* ``GET /v1/domain/{domain}``  — newest certificates for the apex itself
  (issuer sample + most-recent issuance). Skipped if the first call fails.

Env: ``CTLOGS_API_KEY`` (optional, Bearer). Works without it on the
shared anonymous pool.
"""

from __future__ import annotations

import contextlib
import os
from typing import Any
from urllib.parse import quote

from ..core import http

BASE_URL = "https://api.ctlogs.dev/v1"
TIMEOUT = 10.0
MAX_SUBDOMAINS_KEPT = 50
MAX_ISSUERS_KEPT = 5

# Bucket key — see core/ratelimit._DEFAULT_BUCKETS ("ctlogs": 90/hour keeps
# a bulk run under the 100/hour anonymous + free-key ceiling).
_SOURCE = "ctlogs"


def _headers() -> dict[str, str]:
    key = os.getenv("CTLOGS_API_KEY", "").strip()
    headers = {"Accept": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    return headers


def _get_json(path: str) -> dict[str, Any] | None:
    """GET ``/v1/<path>``; ``None`` on any non-200, non-JSON or non-dict answer.

    ctlogs answers 422 for zones too large to list newest-first (amazonaws-
    scale), 429 when a keyless caller already has a request in flight or is
    past 100/hour, 5xx when busy. All of those soft-fail here so the
    orchestrator can fall back to crt.sh.
    """
    resp = http.get(_SOURCE, f"{BASE_URL}/{path}", headers=_headers(), timeout=TIMEOUT)
    if resp is None or resp.status_code != 200:
        return None
    try:
        payload = resp.json()
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None


def enrich_domain(value: str) -> dict | None:
    """CT summary for ``value``: subdomains seen in the last 90 days, cert
    counts, issuer sample and the most recent issuance. ``None`` when the
    API fails or has never seen the domain."""
    domain = (value or "").strip().lower().rstrip(".")
    if not domain:
        return None
    enc = quote(domain, safe="")

    hosts_payload = _get_json(f"hosts/{enc}")
    if hosts_payload is None:
        return None
    hosts = hosts_payload.get("hosts")
    if not isinstance(hosts, list) or not hosts:
        return None

    subdomains: set[str] = set()
    total_certs = 0
    newest_host: dict[str, Any] | None = None
    for row in hosts:
        if not isinstance(row, dict):
            continue
        name = str(row.get("host") or "").strip().lower()
        with contextlib.suppress(TypeError, ValueError):
            total_certs += int(row.get("certs") or 0)
        if name and name != domain:
            subdomains.add(name)
        last_seen = row.get("last_seen")
        if isinstance(last_seen, str) and (
            newest_host is None or last_seen > str(newest_host.get("last_seen") or "")
        ):
            newest_host = row

    # Second call: issuer sample + newest certificate for the apex. Optional —
    # a failure here must not throw away the subdomain data we already have.
    issuers: dict[str, int] = {}
    most_recent: dict[str, Any] | None = None
    domain_payload = _get_json(f"domain/{enc}")
    rows = domain_payload.get("rows") if domain_payload else None
    if isinstance(rows, list):
        for cert in rows:
            if not isinstance(cert, dict):
                continue
            issuer = str(cert.get("issuer") or "unknown")
            issuers[issuer] = issuers.get(issuer, 0) + 1
            nb = cert.get("not_before")
            if isinstance(nb, str) and (
                most_recent is None or nb > str(most_recent.get("not_before") or "")
            ):
                most_recent = {
                    "not_before": nb,
                    "issuer": cert.get("issuer"),
                    "common_name": cert.get("match") or domain,
                }
    if most_recent is None and newest_host is not None:
        most_recent = {
            "not_before": newest_host.get("last_seen"),
            "issuer": None,
            "common_name": newest_host.get("host"),
        }

    top_issuers = sorted(issuers.items(), key=lambda kv: -kv[1])[:MAX_ISSUERS_KEPT]
    return {
        "provider": "ctlogs",
        "history_window_days": hosts_payload.get("history_window_days", 90),
        "total": total_certs,
        "unique_subdomains": sorted(subdomains)[:MAX_SUBDOMAINS_KEPT],
        "subdomain_count": len(subdomains),
        "host_count": len(hosts),
        "truncated": bool(hosts_payload.get("has_next")),
        "top_issuers": [{"issuer": name, "count": n} for name, n in top_issuers],
        "most_recent": most_recent,
    }

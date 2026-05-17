"""crt.sh certificate-transparency enrichment.

crt.sh is a free, public certificate-transparency search interface run
by Sectigo. For any domain we can pull every certificate that's ever
been issued for it (or any subdomain) — useful for:

* Subdomain enumeration (pivot from a known apex to attacker-registered
  subdomains for cred-phishing).
* Spotting fresh issuances (very new certificate ⇒ very new
  infrastructure ⇒ correlate with NRD).
* Identifying odd CAs (a Let's Encrypt cert for a Fortune-500 brand
  alongside DigiCert issuance is a hint).

No API key required. The JSON endpoint can be slow on popular apexes —
we cap response size and apply a generous timeout.

API: https://crt.sh/?q=<domain>&output=json
"""

from __future__ import annotations

from typing import Any

from ..core import http

BASE_URL = "https://crt.sh/"
TIMEOUT = 20  # seconds — crt.sh can be slow under load (preserve tuned override)
MAX_RESULTS_KEPT = 50  # keep the diff compact when caching

# Per-source bucket — public CT search; cap politely since it's slow.
_SOURCE = "crtsh"


def enrich_domain(value: str) -> dict | None:
    """Look up certificates issued for ``value`` (and subdomains).

    Returns ``None`` on network failure or empty result set. On a hit,
    returns a small summary dict with the unique subdomain list, the
    most-recent certificate, and a sample of issuers — enough to drive
    risk scoring without bloating the cache.
    """
    response = http.get(
        _SOURCE,
        BASE_URL,
        params={"q": f"%.{value}", "output": "json"},
        timeout=TIMEOUT,
    )
    if response is None:
        return None
    if response.status_code != 200:
        return None
    try:
        entries = response.json()
    except ValueError:
        return None
    if not isinstance(entries, list) or not entries:
        return None

    subdomains: set[str] = set()
    issuers: dict[str, int] = {}
    most_recent_date: str | None = None
    most_recent_entry: dict[str, Any] | None = None

    for entry in entries[:MAX_RESULTS_KEPT * 4]:  # scan more than we keep
        if not isinstance(entry, dict):
            continue
        name = entry.get("name_value") or ""
        for line in str(name).split("\n"):
            line = line.strip().lower()
            if line and line != value.lower():
                subdomains.add(line)

        issuer = entry.get("issuer_name") or "unknown"
        issuers[issuer] = issuers.get(issuer, 0) + 1

        not_before = entry.get("not_before")
        if isinstance(not_before, str) and (
            most_recent_date is None or not_before > most_recent_date
        ):
            most_recent_date = not_before
            most_recent_entry = entry

    # Keep the cache lean — full subdomain explosion can be huge.
    sorted_subs = sorted(subdomains)[:MAX_RESULTS_KEPT]
    top_issuers = sorted(issuers.items(), key=lambda x: -x[1])[:5]

    return {
        "total": len(entries),
        "unique_subdomains": sorted_subs,
        "subdomain_count": len(subdomains),
        "top_issuers": [{"issuer": name, "count": n} for name, n in top_issuers],
        "most_recent": {
            "not_before": (most_recent_entry or {}).get("not_before"),
            "issuer": (most_recent_entry or {}).get("issuer_name"),
            "common_name": (most_recent_entry or {}).get("common_name"),
        } if most_recent_entry else None,
    }

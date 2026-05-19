"""ASN enrichment.

Primary provider: **RIPE Stat** — public, no-auth, no-quota REST API
maintained by the RIPE NCC. Wider availability than the previous
bgpview.io path (which Pi-hole / restrictive DNS sometimes blocks
inside containers).

Endpoint: ``https://stat.ripe.net/data/as-overview/data.json?resource=AS<n>``

We additionally query ``/data/announced-prefixes/data.json`` for the
list of announced prefixes — useful for analysts who pivot from an ASN
to its address space (a future "expand to prefix list" UI element will
consume this).

Returns the analyst-facing summary fields on success, ``None`` on
miss / network error / unexpected payload. Never raises.
"""

from __future__ import annotations

import re

from ..core import http

BASE_URL = "https://stat.ripe.net/data"
TIMEOUT = 10  # RIPE Stat is fast (<1s typical); cap so a tail latency doesn't gate enrich

# Per-source bucket — RIPE Stat is generous, polite cap.
_SOURCE = "asn"


def _normalize_asn(value: str) -> str | None:
    digits = re.sub(r"(?i)^as(n)?", "", value.strip())
    return digits if digits.isdigit() else None


def _fetch(path: str, params: dict) -> dict | None:
    response = http.get(_SOURCE, f"{BASE_URL}/{path}", params=params, timeout=TIMEOUT)
    if response is None:
        return None
    if response.status_code != 200:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        return None
    data = payload.get("data")
    return data if isinstance(data, dict) else None


def enrich(value: str) -> dict | None:
    """Look up an ASN on RIPE Stat. Returns analyst-facing summary fields."""
    digits = _normalize_asn(value)
    if digits is None:
        return None

    overview = _fetch("as-overview/data.json", {"resource": f"AS{digits}"})
    if overview is None:
        return None

    # Optional secondary call for announced prefix count. Failure is
    # non-fatal — we still return the overview if it landed.
    prefixes_count: int | None = None
    pfx = _fetch("announced-prefixes/data.json", {"resource": f"AS{digits}"})
    if pfx and isinstance(pfx.get("prefixes"), list):
        prefixes_count = len(pfx["prefixes"])

    holder = overview.get("holder") or ""
    return {
        "asn": int(digits),
        "name": holder.split(",")[0] if "," in holder else holder,
        "description_short": holder,
        "country_code": (overview.get("resource") or {}) if isinstance(overview.get("resource"), dict) else None,
        # RIPE Stat overview doesn't include country in this endpoint;
        # the dashboard's IP-geo block carries it for IP IOCs. Kept the
        # field for API back-compat with the bgpview shape.
        "rir_name": "RIPE NCC",
        "date_allocated": None,
        "website": None,
        "looking_glass": overview.get("looking_glass"),
        "type": overview.get("type"),
        "is_active": overview.get("announced"),
        "block_resource": (overview.get("block") or {}).get("resource") if isinstance(overview.get("block"), dict) else None,
        "block_name": (overview.get("block") or {}).get("name") if isinstance(overview.get("block"), dict) else None,
        "announced_prefixes_count": prefixes_count,
        "raw": overview,
    }

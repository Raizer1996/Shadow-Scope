"""ASN enrichment via the free bgpview.io API.

bgpview.io exposes per-ASN metadata (name, description, country, RIR,
date allocated, prefix counts) and per-prefix data through a no-key
REST API. We use the ``/asn/{n}`` endpoint to surface the analyst-
useful summary fields.

API: https://api.bgpview.io/asn/{asn_number}
"""

from __future__ import annotations

import re
from typing import Any

import requests

BASE_URL = "https://api.bgpview.io"
TIMEOUT = 15


def enrich(value: str) -> dict | None:
    """Look up an ASN (``AS12345`` form) on bgpview.io.

    Returns the summary fields on success, ``None`` on miss / network
    error / unexpected payload shape. Never raises.
    """
    digits = re.sub(r'(?i)^as(n)?', '', value.strip())
    if not digits.isdigit():
        return None

    try:
        response = requests.get(f"{BASE_URL}/asn/{digits}", timeout=TIMEOUT)
    except requests.exceptions.RequestException:
        return None
    if response.status_code != 200:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        return None
    data = payload.get("data") or {}
    if not isinstance(data, dict):
        return None

    rir = (data.get("rir_allocation") or {})
    raw_emails: Any = data.get("email_contacts") or []
    raw_abuse: Any = data.get("abuse_contacts") or []
    return {
        "asn": data.get("asn"),
        "name": data.get("name"),
        "description_short": data.get("description_short"),
        "country_code": data.get("country_code"),
        "rir_name": rir.get("rir_name"),
        "date_allocated": rir.get("date_allocated"),
        "website": data.get("website"),
        "looking_glass": data.get("looking_glass"),
        "traffic_estimation": data.get("traffic_estimation"),
        "email_contacts": list(raw_emails) if isinstance(raw_emails, list) else [],
        "abuse_contacts": list(raw_abuse) if isinstance(raw_abuse, list) else [],
    }

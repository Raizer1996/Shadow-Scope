"""Censys Platform v3 Host enrichment.

Wraps ``https://api.platform.censys.io/v3/global/asset/host/{ip}`` — the
new Censys Platform Personal Access Token endpoint that replaced the
legacy Search-v2 API-ID + Secret auth. Single PAT via ``CENSYS_API_KEY``
(bearer header).

Returns the raw ``result`` block from the v2 response, which carries:

* ``services[]`` — port + service_name + transport_protocol + extended_service_name
  + observed_at + banner, plus optional ``tls``, ``http``, ``ssh``, ``software[]``
* ``location`` — country / city / coordinates
* ``autonomous_system`` — asn + name + country_code + bgp_prefix
* ``operating_system`` — guessed OS family / vendor / product / version
* ``dns`` — reverse_dns names
* ``last_updated_at``

Info-only source — never contributes to the composite risk score; only feeds
data fields the UI surfaces (JARM, full cert chain, OS fingerprint, service
versions). 500 free queries/month, so callers must rely on the 24h cache TTL.
"""

from __future__ import annotations

import os
from typing import Any

import requests

BASE_URL = "https://api.platform.censys.io/v3"
_TIMEOUT = 10


def host_lookup(ip: str) -> dict[str, Any]:
    """Look up an IP in Censys Platform Hosts. Returns ``{}`` when no key configured."""
    token = os.getenv("CENSYS_API_KEY")
    if not token:
        return {}

    try:
        resp = requests.get(
            f"{BASE_URL}/global/asset/host/{ip}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=_TIMEOUT,
        )
    except requests.RequestException as exc:
        return {"error": f"request failed: {exc}"}

    if resp.status_code == 401:
        return {"error": "Censys: 401 unauthorized — check CENSYS_API_KEY"}
    if resp.status_code == 403:
        return {"error": "Censys: 403 forbidden — token lacks Hosts access"}
    if resp.status_code == 404:
        return {}
    if resp.status_code == 429:
        return {"error": "Censys: 429 quota exhausted"}
    if resp.status_code != 200:
        return {"error": f"Censys: HTTP {resp.status_code}"}

    body = resp.json() or {}
    if not isinstance(body, dict):
        return {}
    # Platform v3 wraps the host record under {"result": {"resource": {...}, "extensions": {...}}}.
    # Unwrap to ``resource`` so downstream code reads flat keys (services, autonomous_system,
    # location, dns, whois) the same way it would from the legacy v2 ``result``.
    result = body.get("result") or {}
    resource = result.get("resource") if isinstance(result, dict) else None
    return resource if isinstance(resource, dict) else (result if isinstance(result, dict) else {})

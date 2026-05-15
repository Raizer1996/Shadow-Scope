"""AlienVault OTX (Open Threat Exchange) enrichment client.

OTX is a community-driven threat-intelligence platform built around
**pulses** — analyst-curated reports that bundle a campaign / threat
actor / family with the IOCs that identify it, plus tags, references,
and (sometimes) a named adversary. Looking up an IOC returns the list
of pulses that mention it: the longer that list, the more widely-
reported the threat.

API docs: https://otx.alienvault.com/api/v1/indicators/

Endpoint shape (single GET per IOC type)::

    GET https://otx.alienvault.com/api/v1/indicators/<type>/<value>/general
    Header: X-OTX-API-KEY: <key>

ShadowScope-internal type → OTX path-segment mapping:

- ``ip``     → ``IPv4``
- ``domain`` → ``domain``
- ``url``    → ``url``
- ``hash``   → ``file``

A "no pulses" hit (``pulse_info.count == 0``) is still an HTTP 200 with
useful body — that's a negative signal, not an error, so the module
surfaces it. Only missing keys, network errors, and non-200 statuses
collapse to ``None``.
"""

from __future__ import annotations

import os

import requests

BASE_URL = "https://otx.alienvault.com/api/v1/indicators"
TIMEOUT = 10  # seconds

# Map ShadowScope's internal IOC type names onto OTX's path segments.
_TYPE_PATH = {
    "ip": "IPv4",
    "domain": "domain",
    "url": "url",
    "hash": "file",
}


def enrich(value: str, ioc_type: str) -> dict | None:
    """Look up an IOC in AlienVault OTX.

    ``ioc_type`` is the ShadowScope-internal type: ``'ip'``, ``'domain'``,
    ``'url'``, or ``'hash'``. The module maps that onto the appropriate
    OTX path segment (``IPv4`` / ``domain`` / ``url`` / ``file``).

    Returns the full response dict (including ``pulse_info``) on
    success, even when ``pulse_info.count`` is ``0`` — a known-clean
    indicator is still useful signal versus a network-error miss.

    Returns ``None`` when:

    - the ``OTX_API_KEY`` env var is unset / empty
    - the IOC type is not one of the four supported by this module
    - the HTTP request raises ``requests.exceptions.RequestException``
    - the response status code is not 200
    - the response body is not valid JSON
    """
    api_key = os.getenv("OTX_API_KEY")
    if not api_key:
        return None

    path_type = _TYPE_PATH.get(ioc_type)
    if not path_type:
        return None

    headers = {
        "X-OTX-API-KEY": api_key,
        "Accept": "application/json",
    }

    try:
        response = requests.get(
            f"{BASE_URL}/{path_type}/{value}/general",
            headers=headers,
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

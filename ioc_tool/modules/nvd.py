"""NIST NVD (National Vulnerability Database) CVE enrichment client.

The NVD ``/rest/json/cves/2.0`` endpoint returns canonical CVE metadata:
descriptions, CVSS v3.1 base score + severity, publication date, and
configurations. No API key is required for low-volume use (an optional
``apiKey`` header bumps the rate limit; we don't wire one in but the
plumbing is straightforward — set ``NVD_API_KEY`` and pass it as a
header).

API docs: https://nvd.nist.gov/developers/vulnerabilities

Response shape (truncated):

    {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-...",
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                        ]
                    },
                    "descriptions": [{"lang": "en", "value": "..."}]
                }
            }
        ]
    }

Following the project convention: API failures return ``None`` and
never raise.
"""

from __future__ import annotations

from ..core import http

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT = 10  # seconds — preserve original tuned override

# Per-source bucket — NVD: 5 / 30s unauthenticated.
_SOURCE = "nvd"


def enrich_cve(value: str) -> dict | None:
    """Look up a CVE in the NIST NVD.

    Returns the first ``vulnerabilities[0]["cve"]`` dict on a hit, or
    ``None`` when:

    - the HTTP request fails or the bucket refuses a token
    - the response status code is not 200
    - the response body is not valid JSON
    - ``vulnerabilities`` is missing / empty
    """
    response = http.get(
        _SOURCE,
        BASE_URL,
        params={"cveId": value},
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

    vulnerabilities = payload.get("vulnerabilities")
    if not vulnerabilities or not isinstance(vulnerabilities, list):
        return None

    first = vulnerabilities[0]
    if not isinstance(first, dict):
        return None

    cve = first.get("cve")
    if not isinstance(cve, dict):
        return None

    return cve

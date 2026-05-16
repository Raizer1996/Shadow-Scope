import base64
import os

from ..core import http

VT_API_KEY = os.getenv('VT_API_KEY')
BASE_URL = 'https://www.virustotal.com/api/v3'

# Per-source key for the rate-limit bucket. The default config in
# ratelimit.py caps VT at 4 req/min to match the public free tier.
_SOURCE = 'virustotal'


def get_vt_headers():
    return {
        "x-apikey": os.getenv('VT_API_KEY')
    }


def _fetch_attributes(endpoint: str) -> dict | None:
    """Common path: GET an attributes object from the VT API.

    Returns the ``data.attributes`` dict on 200, ``None`` on any other
    response (including a refused token / 429 retry exhaustion).
    """
    if not os.getenv('VT_API_KEY'):
        return None
    response = http.get(_SOURCE, f"{BASE_URL}/{endpoint}", headers=get_vt_headers())
    if response is None or response.status_code != 200:
        return None
    return response.json().get('data', {}).get('attributes', {})


def enrich_ip(ip):
    return _fetch_attributes(f"ip_addresses/{ip}")


def enrich_domain(domain):
    return _fetch_attributes(f"domains/{domain}")


def enrich_hash(file_hash):
    return _fetch_attributes(f"files/{file_hash}")


def enrich_url(target_url):
    # VT requires base64 encoding of URL without padding
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    return _fetch_attributes(f"urls/{url_id}")

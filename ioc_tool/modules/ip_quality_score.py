import os

from ..core import http

BASE_URL = "https://www.ipqualityscore.com/api/json/ip"

# Per-source bucket key. Registry default keeps IPQS at 4 req/min — the
# free tier is monthly-capped so smoothing matters more than rps.
_SOURCE = 'ipqs'


def enrich_ip(ip):
    api_key = os.getenv('IP_QUALITY_SCORE')
    if not api_key:
        return None

    url = f"{BASE_URL}/{api_key}/{ip}"

    response = http.get(_SOURCE, url)
    if response is None:
        return None
    if response.status_code == 200:
        try:
            return response.json()
        except ValueError:
            return None
    return None

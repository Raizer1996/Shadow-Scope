import os

from ..core import http

BASE_URL = "https://api.shodan.io"

# Per-source bucket key. Default keeps Shodan at 1 req/sec which matches
# the free-tier hard cap.
_SOURCE = 'shodan'


def host_search(ip):
    api_key = os.getenv('SHODAN_API_KEY')
    if not api_key:
        return {"error": "Missing SHODAN_API_KEY"}

    url = f"{BASE_URL}/shodan/host/{ip}?key={api_key}"

    response = http.get(_SOURCE, url)
    if response is None:
        return {"error": "request failed"}
    if response.status_code == 200:
        return response.json()
    return {"error": f"Status {response.status_code}"}

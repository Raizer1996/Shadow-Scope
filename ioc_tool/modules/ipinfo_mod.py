import os

import requests

BASE_URL = "https://ipinfo.io"

def enrich_ip(ip):
    api_key = os.getenv('IP_INFO_API')
    if not api_key:
        return None

    url = f"{BASE_URL}/{ip}"
    params = {'token': api_key}

    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception:
        return None

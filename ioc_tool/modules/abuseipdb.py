import os

from ..core import http

BASE_URL = 'https://api.abuseipdb.com/api/v2'

# Per-source key for the rate-limit bucket. Default caps AbuseIPDB at
# ~40 req/min — the free tier allows 1000 lookups/day.
_SOURCE = 'abuseipdb'


def enrich_ip(ip):
    api_key = os.getenv('ABUSEIPDB_API_KEY')
    if not api_key:
        return None

    url = f"{BASE_URL}/check"
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }

    response = http.get(_SOURCE, url, headers=headers, params=params)
    if response is None:
        return None
    if response.status_code == 200:
        return response.json().get('data', {})
    return None

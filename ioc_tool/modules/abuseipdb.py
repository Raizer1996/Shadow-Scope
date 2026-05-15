import os

import requests

BASE_URL = 'https://api.abuseipdb.com/api/v2'

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

    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        return response.json().get('data', {})
    return None

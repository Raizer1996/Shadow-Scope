import requests
import os
import base64

VT_API_KEY = os.getenv('VT_API_KEY')
BASE_URL = 'https://www.virustotal.com/api/v3'

def get_vt_headers():
    return {
        "x-apikey": os.getenv('VT_API_KEY')
    }

def enrich_ip(ip):
    if not os.getenv('VT_API_KEY'):
        return None
    url = f"{BASE_URL}/ip_addresses/{ip}"
    response = requests.get(url, headers=get_vt_headers())
    if response.status_code == 200:
        return response.json().get('data', {}).get('attributes', {})
    return None

def enrich_domain(domain):
    if not os.getenv('VT_API_KEY'):
        return None
    url = f"{BASE_URL}/domains/{domain}"
    response = requests.get(url, headers=get_vt_headers())
    if response.status_code == 200:
        return response.json().get('data', {}).get('attributes', {})
    return None

def enrich_hash(file_hash):
    if not os.getenv('VT_API_KEY'):
        return None
    url = f"{BASE_URL}/files/{file_hash}"
    response = requests.get(url, headers=get_vt_headers())
    if response.status_code == 200:
        return response.json().get('data', {}).get('attributes', {})
    return None

def enrich_url(target_url):
    if not os.getenv('VT_API_KEY'):
        return None
    # VT requires base64 encoding of URL without padding
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    url = f"{BASE_URL}/urls/{url_id}"
    response = requests.get(url, headers=get_vt_headers())
    if response.status_code == 200:
        return response.json().get('data', {}).get('attributes', {})
    return None

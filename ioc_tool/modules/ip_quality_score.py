import requests
import os

BASE_URL = "https://www.ipqualityscore.com/api/json/ip"

def enrich_ip(ip):
    api_key = os.getenv('IP_QUALITY_SCORE')
    if not api_key:
        return None
        
    url = f"{BASE_URL}/{api_key}/{ip}"
    
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception:
        return None

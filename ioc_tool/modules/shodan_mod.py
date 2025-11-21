import requests
import os

BASE_URL = "https://api.shodan.io"

def host_search(ip):
    api_key = os.getenv('SHODAN_API_KEY')
    if not api_key:
        return {"error": "Missing SHODAN_API_KEY"}
        
    url = f"{BASE_URL}/shodan/host/{ip}?key={api_key}"
    
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        return {"error": f"Status {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

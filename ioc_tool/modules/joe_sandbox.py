import os

from ..core import http

API_KEY = os.getenv('JOE_SANDBOX_CLOUD_API_KEY')
BASE_URL = "https://jbxcloud.joesecurity.org/api"

# Per-source bucket — Joe Cloud free tier is very tight.
_SOURCE = 'joe_sandbox'

def submit_file(file_path):
    key = os.getenv('JOE_SANDBOX_CLOUD_API_KEY')
    if not key:
        return {"error": "Missing JOE_SANDBOX_CLOUD_API_KEY"}

    # Correct Endpoint
    url = "https://jbxcloud.joesecurity.org/api/v2/analysis/submit"

    headers = {
        "Accept": "application/json",
        "apikey": key
    }

    try:
        with open(file_path, 'rb') as f:
            files = {'file': f}
            data = {'acceptTOS': 1}

            response = http.post(_SOURCE, url, headers=headers, files=files, data=data)
            if response is None:
                return {"error": "request failed"}
            if response.status_code == 200:
                return response.json()
            return {"error": f"Status {response.status_code}: {response.text}"}
    except Exception as e:
        return {"error": str(e)}

def submit_url(target_url):
    key = os.getenv('JOE_SANDBOX_CLOUD_API_KEY')
    if not key:
        return {"error": "Missing JOE_SANDBOX_CLOUD_API_KEY"}

    url = "https://jbxcloud.joesecurity.org/api/v2/analysis/submit"

    headers = {
        "Accept": "application/json",
        "apikey": key
    }

    data = {
        'url': target_url,
        'acceptTOS': 1
    }

    try:
        response = http.post(_SOURCE, url, headers=headers, data=data)
        if response is None:
            return {"error": "request failed"}
        if response.status_code == 200:
            return response.json()
        return {"error": f"Status {response.status_code}: {response.text}"}
    except Exception as e:
        return {"error": str(e)}

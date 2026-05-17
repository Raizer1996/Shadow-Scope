import os

from ..core import http

API_KEY = os.getenv('HYBRID_ANALYSIS_API_KEY')
BASE_URL = "https://www.hybrid-analysis.com/api/v2"

# Per-source bucket — Falcon Sandbox public-key tier is ~200/hour.
_SOURCE = 'hybrid_analysis'

def get_headers():
    return {
        "api-key": os.getenv('HYBRID_ANALYSIS_API_KEY'),
        "User-Agent": "Falcon Sandbox",
        "Accept": "application/json"
    }

def submit_file(file_path):
    if not os.getenv('HYBRID_ANALYSIS_API_KEY'):
        return {"error": "Missing HYBRID_ANALYSIS_API_KEY"}

    # Using /submit/file which is the standard submission endpoint
    url = f"{BASE_URL}/submit/file"
    try:
        with open(file_path, 'rb') as f:
            files = {'file': f}
            # 'environment_id' is often required, usually '100' (Windows 7) or '120' (Windows 10)
            # 'scan_type' might not be needed or should be 'all'
            data = {'environment_id': '120'}

            response = http.post(_SOURCE, url, headers=get_headers(), files=files, data=data)
            if response is None:
                return {"error": "request failed"}
            if response.status_code in [200, 201]:
                return response.json()
            return {"error": f"Status {response.status_code} at {url}: {response.text}"}
    except Exception as e:
        return {"error": str(e)}

def submit_url(target_url):
    if not os.getenv('HYBRID_ANALYSIS_API_KEY'):
        return {"error": "Missing HYBRID_ANALYSIS_API_KEY"}

    # Correct endpoint for standard keys
    url = f"{BASE_URL}/submit/url"
    data = {
        'url': target_url,
        'environment_id': '120' # Often required for URLs too
    }

    try:
        response = http.post(_SOURCE, url, headers=get_headers(), data=data)
        if response is None:
            return {"error": "request failed"}
        if response.status_code in [200, 201]:
            return response.json()
        return {"error": f"Status {response.status_code} at {url}: {response.text}"}
    except Exception as e:
        return {"error": str(e)}

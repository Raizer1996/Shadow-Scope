import requests
import os

BASE_URL = "https://www.filescan.io/api"

def get_headers():
    return {
        'X-Api-Key': os.getenv('FILE_SCAN_IO'),
        'User-Agent': 'ShadowScope-CLI'
    }

def submit_file(file_path):
    if not os.getenv('FILE_SCAN_IO'):
        return {"error": "Missing FILE_SCAN_IO API Key"}
        
    url = f"{BASE_URL}/scan/file"
    try:
        with open(file_path, 'rb') as f:
            files = {'file': f}
            # FileScan.IO often requires minimal params, or just the file
            response = requests.post(url, headers=get_headers(), files=files)
            
            if response.status_code == 200:
                data = response.json()
                flow_id = data.get('flow_id')
                if flow_id:
                    # Specific report URL is hard to guess/undocumented.
                    # Pointing to the dashboard is safer.
                    return {
                        "message": "Submission Successful", 
                        "flow_id": flow_id,
                        "dashboard_link": "https://www.filescan.io/me/reports"
                    }
                return data
            return {"error": f"Status {response.status_code}: {response.text}"}
    except Exception as e:
        return {"error": str(e)}

def submit_url(target_url):
    if not os.getenv('FILE_SCAN_IO'):
        return {"error": "Missing FILE_SCAN_IO API Key"}
        
    url = f"{BASE_URL}/scan/url"
    data = {'url': target_url}
    
    try:
        response = requests.post(url, headers=get_headers(), data=data)
        if response.status_code == 200:
            data = response.json()
            flow_id = data.get('flow_id')
            if flow_id:
                return {
                    "message": "Submission Successful", 
                    "flow_id": flow_id,
                    "dashboard_link": "https://www.filescan.io/me/reports"
                }
            return data
        return {"error": f"Status {response.status_code}: {response.text}"}
    except Exception as e:
        return {"error": str(e)}

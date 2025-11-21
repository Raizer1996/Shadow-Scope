import requests
import os

# Load env vars manually since we are in a script
def load_env():
    with open('ioc_tool/.env', 'r') as f:
        for line in f:
            if '=' in line:
                k, v = line.strip().split('=', 1)
                os.environ[k] = v

load_env()

HA_KEY = os.getenv('HYBRID_ANALYSIS_API_KEY')
JOE_KEY = os.getenv('JOE_SANDBOX_CLOUD_API_KEY')

print(f"HA Key present: {bool(HA_KEY)}")
print(f"Joe Key present: {bool(JOE_KEY)}")

# --- Hybrid Analysis Debug ---
print("\n--- Testing Hybrid Analysis ---")
ha_base = "https://www.hybrid-analysis.com/api/v2"
ha_endpoints = [
    "/quick-scan/file",
    "/submit/file",
    "/quick-scan"
]

files = {'file': ('test.txt', b'test content')}
headers = {
    "User-Agent": "Falcon Sandbox",
    "api-key": HA_KEY
}

for ep in ha_endpoints:
    url = ha_base + ep
    print(f"Testing {url}...")
    try:
        # Try 1: Just file
        res = requests.post(url, headers=headers, files=files)
        print(f"  [File Only] {res.status_code}: {res.text[:100]}")
        
        # Try 2: With scan_type
        res = requests.post(url, headers=headers, files=files, data={'scan_type': 'all'})
        print(f"  [With scan_type] {res.status_code}: {res.text[:100]}")
        
        # Try 3: With environment_id
        res = requests.post(url, headers=headers, files=files, data={'environment_id': 100})
        print(f"  [With env_id] {res.status_code}: {res.text[:100]}")
    except Exception as e:
        print(f"  Error: {e}")

# --- Joe Sandbox Debug ---
print("\n--- Testing Joe Sandbox ---")
joe_base = "https://jbxcloud.joesecurity.org/api"
joe_paths = [
    "/v2/submission/sample",
    "/v2/submit/sample",
    "/v2/analysis/submit",
    "/v2/submission/new",
    "/v2/samples/submit"
]

for path in joe_paths:
    url = joe_base + path
    print(f"Testing {url}...")
    try:
        # Joe Sandbox v2 usually takes apikey as param
        data = {'apikey': JOE_KEY, 'accept-tac': 1}
        files = {'sample': ('test.txt', b'test content')}
        res = requests.post(url, data=data, files=files)
        print(f"  {res.status_code}: {res.text[:100]}")
    except Exception as e:
        print(f"  Error: {e}")

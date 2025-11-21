import requests
import os

TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"
CACHE_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'tor_nodes.txt')

def update_tor_list():
    try:
        response = requests.get(TOR_EXIT_LIST_URL, timeout=5)
        if response.status_code == 200:
            with open(CACHE_FILE, 'w') as f:
                f.write(response.text)
            return True
    except Exception:
        return False
    return False

def is_tor_node(ip):
    # Check if cache exists, if not or old, try to update (simple logic: just check existence for now)
    if not os.path.exists(CACHE_FILE):
        update_tor_list()
        
    try:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, 'r') as f:
                for line in f:
                    if ip == line.strip():
                        return True
    except Exception:
        pass
        
    return False

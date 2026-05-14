import re
import ipaddress

from .defang import refang


def detect_type(value):
    value = refang(value.strip())
    
    # IP Address
    try:
        ipaddress.ip_address(value)
        return 'ip'
    except ValueError:
        pass
    
    # Hash (MD5, SHA1, SHA256)
    if re.match(r'^[a-fA-F0-9]{32}$', value):
        return 'hash' # MD5
    if re.match(r'^[a-fA-F0-9]{40}$', value):
        return 'hash' # SHA1
    if re.match(r'^[a-fA-F0-9]{64}$', value):
        return 'hash' # SHA256
        
    # Email
    if re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', value):
        return 'email'
        
    # URL (Simple check)
    if re.match(r'^https?://', value):
        return 'url'
        
    # Domain (Fallback, basic regex)
    if re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', value):
        return 'domain'
        
    return 'unknown'

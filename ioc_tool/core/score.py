from datetime import datetime

def calculate_vt_score(stats):
    """
    VirusTotal score = (# of positives / total vendors) * 100
    """
    if not stats:
        return 0
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0) # Treating suspicious as half-bad or just bad? Req says positives.
    # Usually 'malicious' is the count of positives.
    
    total = sum(stats.values())
    if total == 0:
        return 0
        
    # Using malicious count as positives
    return int((malicious / total) * 100)

def calculate_abuseipdb_score(data):
    """
    AbuseIPDB score = Abuse IP Confidence Score
    """
    if not data:
        return 0
    return data.get('abuseConfidenceScore', 0)

def calculate_whois_score(creation_date):
    """
    Domain age < 30 days -> 90
    Domain age 30-180 days -> 60
    Domain age > 6 months -> 10
    """
    if not creation_date:
        return 50 # Unknown age risk
        
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
        
    if isinstance(creation_date, str):
        try:
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            try:
                creation_date = datetime.fromisoformat(creation_date)
            except:
                return 50 # Parse error
                
    if not isinstance(creation_date, datetime):
        return 50

    age = (datetime.now() - creation_date).days
    
    if age < 30:
        return 90
    elif age <= 180:
        return 60
    else:
        return 10

def calculate_urlhaus_score(data):
    """
    URLhaus presence = strong malicious signal.

    - None / no data -> 0
    - Hit with url_status='online' -> 95
    - Hit with url_status='offline' -> 70
    - Otherwise hit -> 80
    """
    if not data:
        return 0
    status = data.get('url_status')
    if status == 'online':
        return 95
    if status == 'offline':
        return 70
    return 80

def calculate_greynoise_score(data: dict | None) -> int:
    """GreyNoise: malicious=90, benign/riot=0, unknown=0, none=0.

    Mapping:
    - ``classification == 'malicious'`` -> 90 (known-bad scanner / actor)
    - ``classification == 'benign'`` (noise=True or riot=True) -> 0
      (intentional false-positive dampener: known benign scanners +
      Real Internet Observation Trust services pull the average down)
    - ``classification == 'unknown'`` -> 0 (no observation, no signal)
    - missing / ``None`` -> 0
    """
    if not data:
        return 0
    classification = data.get("classification")
    if classification == "malicious":
        return 90
    return 0


def calculate_final_risk(scores):
    """
    Average of all module scores
    """
    if not scores:
        return 0
    return int(sum(scores) / len(scores))

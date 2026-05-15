from datetime import datetime


def calculate_vt_score(stats):
    """
    VirusTotal score = (# of positives / total vendors) * 100
    """
    if not stats:
        return 0
    malicious = stats.get('malicious', 0)
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
            except (ValueError, TypeError):
                return 50

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

def calculate_threatfox_score(data: dict | None) -> int:
    """ThreatFox hit signals known-malicious infrastructure.

    Score is bucketed by abuse.ch's own ``confidence_level`` (0–100)
    so we don't second-guess the curator:

    - ``None`` / empty payload -> 0
    - hit with ``confidence_level >= 75`` -> 95
    - hit with ``confidence_level >= 50`` -> 80
    - hit (lower / missing confidence) -> 60
    """
    if not data:
        return 0
    confidence = data.get("confidence_level")
    try:
        confidence_int = int(confidence) if confidence is not None else 0
    except (TypeError, ValueError):
        confidence_int = 0

    if confidence_int >= 75:
        return 95
    if confidence_int >= 50:
        return 80
    return 60


def calculate_malwarebazaar_score(data: dict | None) -> int:
    """MalwareBazaar hit means the hash is a known malicious sample.

    - ``None`` / empty payload -> 0
    - any hit -> 95
    """
    if not data:
        return 0
    return 95


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


def calculate_otx_score(data: dict | None) -> int:
    """AlienVault OTX pulse count + reputation drive risk.

    OTX surfaces analyst-curated **pulses** that reference an IOC; the
    more pulses, the more widely-reported the threat. Negative
    ``reputation`` (OTX's own community signal) tilts the score up.

    Mapping:

    - ``None`` / no data → ``0``
    - ``pulse_info.count == 0`` and ``reputation >= 0`` → ``0``
    - ``pulse_info.count`` 1–2 → ``50``
    - ``pulse_info.count`` 3–9 → ``75``
    - ``pulse_info.count >= 10`` → ``90``
    - Negative ``reputation`` (``< 0``) bumps the score by ``+10``
      (capped at ``100``)
    """
    if not data:
        return 0

    pulse_info = data.get("pulse_info") or {}
    try:
        pulse_count = int(pulse_info.get("count", 0) or 0)
    except (TypeError, ValueError):
        pulse_count = 0

    try:
        reputation = int(data.get("reputation", 0) or 0)
    except (TypeError, ValueError):
        reputation = 0

    if pulse_count == 0 and reputation >= 0:
        return 0

    if pulse_count >= 10:
        base = 90
    elif pulse_count >= 3:
        base = 75
    elif pulse_count >= 1:
        base = 50
    else:
        # pulse_count == 0 but reputation < 0 — still a (weak) signal
        base = 0

    if reputation < 0:
        base += 10

    return min(base, 100)


def calculate_urlscan_score(data: dict | None) -> int:
    """URLscan.io historical search → risk signal.

    URLscan indexes URL scans (page visits, redirects, screenshots) and
    surfaces a per-result ``verdicts.overall.malicious`` boolean plus
    tags. Presence of *any* malicious-verdict result is a strong signal.
    Bare presence in the public archive — even without a malicious
    verdict — is a mild signal: public submissions often happen because
    someone was suspicious of the URL.

    Mapping:

    - ``None`` / no data → ``0``
    - ``total == 0`` → ``0`` (we looked and found nothing — neutral)
    - any result with ``verdicts.overall.malicious == True`` → ``90``
    - otherwise (history exists, no malicious verdict) → ``30``
    """
    if not data:
        return 0

    try:
        total = int(data.get("total", 0) or 0)
    except (TypeError, ValueError):
        total = 0
    if total == 0:
        return 0

    results = data.get("results") or []
    for entry in results:
        if not isinstance(entry, dict):
            continue
        verdicts = entry.get("verdicts") or {}
        overall = verdicts.get("overall") or {}
        if overall.get("malicious") is True:
            return 90

    return 30


def calculate_nvd_score(data: dict | None) -> int:
    """Map NVD CVSS v3.1 baseScore (0.0–10.0) onto 0–100 risk.

    Returns 0 when the payload is missing or the CVSS v3.1 metric block
    cannot be located (older CVEs sometimes only carry v2 — we don't
    fall back, the EPSS and KEV signals cover those gaps).
    """
    if not data:
        return 0
    try:
        cvss = data["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
        return int(round(cvss * 10))
    except (KeyError, IndexError, TypeError):
        return 0


def calculate_epss_score(data: dict | None) -> int:
    """Map EPSS exploit-probability (0.0–1.0) onto 0–100.

    Top-percentile floor: when ``percentile >= 0.99`` we floor the
    score at 70 even if the raw probability rounds lower — being in
    the top 1% of CVEs by exploit likelihood is a strong signal in its
    own right.
    """
    if not data:
        return 0
    try:
        epss = float(data.get("epss", 0))
        pct = float(data.get("percentile", 0))
        result = int(round(epss * 100))
        if pct >= 0.99:
            result = max(result, 70)
        return result
    except (ValueError, TypeError):
        return 0


def calculate_kev_score(data: dict | None) -> int:
    """CISA KEV listing = known-exploited. Hit → 100. Miss/None → 0."""
    if not data:
        return 0
    return 100


def calculate_feodo_score(data: dict | None) -> int:
    """Feodo Tracker hit = live botnet C2. Online status weighs heavier than offline.

    - ``None`` / no data            → 0
    - status == 'offline_24h'+     → 70
    - status == 'online' or other  → 95
    """
    if not data:
        return 0
    status = (data.get("status") or "").lower()
    if "offline" in status:
        return 70
    return 95


def calculate_sslbl_score(data: dict | None) -> int:
    """SSLBL hit = malicious TLS cert. Always a strong signal — score 95."""
    if not data:
        return 0
    return 95


def calculate_crtsh_score(data: dict | None) -> int:
    """crt.sh data is informational by default — used for pivots, not risk-tier.

    We emit a modest score when the issuance count is *very* large (the
    target domain is heavily certificated, which mildly correlates with
    spread-out attacker infrastructure / phishing kits), but in general
    crt.sh is info-only and should not push composite tiers around.
    """
    if not data:
        return 0
    total = int(data.get("total") or 0)
    if total >= 1000:
        return 30
    if total >= 100:
        return 15
    return 0


def calculate_pulsedive_score(data: dict | None) -> int:
    """Map Pulsedive's ``risk`` string into our 0–100 scale.

    Pulsedive uses a coarse tier rather than a numeric score. We map:

    - ``critical`` → 95
    - ``high``     → 80
    - ``medium``   → 55
    - ``low``      → 25
    - ``none`` / ``unknown`` / missing → 0
    """
    if not data:
        return 0
    risk = str(data.get("risk") or "").strip().lower()
    return {
        "critical": 95,
        "high": 80,
        "medium": 55,
        "low": 25,
    }.get(risk, 0)


def calculate_final_risk(scores):
    """
    Average of all module scores
    """
    if not scores:
        return 0
    return int(sum(scores) / len(scores))

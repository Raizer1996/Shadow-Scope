"""Serialization helpers for enrichment results.

This module turns the dict structure returned by
:func:`ioc_tool.core.enrich.enrich_ioc` into machine-readable formats
that SOC pipelines can pipe into SIEMs, spreadsheets, and ticket
systems.

Pure stdlib (``json`` + ``csv``). Both functions are pure: they take
results, return a string. No printing, no file I/O.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import date, datetime
from typing import Any, Dict, List


# CSV columns — keep this list authoritative. Tests assert on it.
CSV_COLUMNS: List[str] = [
    "ioc",
    "type",
    "final_score",
    "risk_tier",
    "vt_malicious",
    "vt_total",
    "abuseipdb_score",
    "ipqs_fraud_score",
    "shodan_tags",
    "shodan_ports",
    "ipinfo_org",
    "ipinfo_country",
    "tor",
    "whois_creation_date",
    "urlhaus_threat",
    "threatfox_threat_type",
    "threatfox_malware",
    "malwarebazaar_signature",
    "malwarebazaar_file_type",
    "greynoise_classification",
    "greynoise_name",
]


def _risk_tier(score: int) -> str:
    """Map a 0-100 final score to a tier label.

    Matches the tier table in ``docs/ARCHITECTURE.md`` and the
    color-coding used in ``ui/cli.py``: Safe / Low / Medium / High /
    Critical.
    """
    if score is None:
        return "Safe"
    try:
        s = int(score)
    except (TypeError, ValueError):
        return "Safe"

    if s >= 80:
        return "Critical"
    if s >= 60:
        return "High"
    if s >= 40:
        return "Medium"
    if s >= 20:
        return "Low"
    return "Safe"


def _json_default(obj: Any) -> Any:
    """Fallback encoder for non-JSON-native types.

    Handles datetimes (ISO 8601) and falls back to ``str()`` for
    anything else so we never raise ``TypeError`` in the middle of a
    pipeline.
    """
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    return str(obj)


def to_json(results: List[Dict[str, Any]]) -> str:
    """Serialize enrichment results as pretty-printed JSON (indent=2).

    Includes every key in every module dict — nothing is dropped.
    Non-JSON-native values (datetimes, etc.) are coerced via
    :func:`_json_default`.
    """
    return json.dumps(results, indent=2, default=_json_default, sort_keys=False)


def to_csv(results: List[Dict[str, Any]]) -> str:
    """Flatten enrichment results to CSV (one row per IOC).

    Columns are defined by :data:`CSV_COLUMNS`. Missing values become
    empty strings, never ``None`` or ``"null"``.
    """
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()

    for res in results or []:
        row = _flatten_result(res)
        writer.writerow(row)

    return buf.getvalue()


def _flatten_result(result: Dict[str, Any]) -> Dict[str, str]:
    """Reduce a single enrichment dict to the CSV column dict.

    Every value is coerced to ``str`` so the CSV writer never chokes
    on lists / ints / None. Empty/missing fields end up as ``""``.
    """
    modules = (result or {}).get("modules", {}) or {}
    final_score = (result or {}).get("final_score", 0) or 0

    row: Dict[str, str] = {col: "" for col in CSV_COLUMNS}
    row["ioc"] = _s(result.get("ioc"))
    row["type"] = _s(result.get("type"))
    row["final_score"] = _s(final_score)
    row["risk_tier"] = _risk_tier(final_score)

    # VirusTotal — stats live under modules.VirusTotal.data.last_analysis_stats
    vt = modules.get("VirusTotal") or {}
    vt_data = vt.get("data") or {}
    stats = vt_data.get("last_analysis_stats") or {}
    if stats:
        row["vt_malicious"] = _s(stats.get("malicious", 0))
        total = sum(v for v in stats.values() if isinstance(v, (int, float)))
        row["vt_total"] = _s(total)

    # AbuseIPDB
    abuse = modules.get("AbuseIPDB") or {}
    abuse_data = abuse.get("data") or {}
    if "abuseConfidenceScore" in abuse_data:
        row["abuseipdb_score"] = _s(abuse_data.get("abuseConfidenceScore"))

    # IPQS — score lives on the module dict itself, fraud_score key matches enrich.py
    ipqs = modules.get("IPQS") or {}
    ipqs_data = ipqs.get("data") or {}
    if "fraud_score" in ipqs_data:
        row["ipqs_fraud_score"] = _s(ipqs_data.get("fraud_score"))

    # Shodan — tags and ports are both lists
    shodan = modules.get("Shodan") or {}
    shodan_data = shodan.get("data") or {}
    tags = shodan_data.get("tags")
    ports = shodan_data.get("ports")
    if tags:
        row["shodan_tags"] = ",".join(str(t) for t in tags)
    if ports:
        row["shodan_ports"] = ",".join(str(p) for p in ports)

    # IPinfo
    ipinfo = modules.get("IPinfo") or {}
    ipinfo_data = ipinfo.get("data") or {}
    if ipinfo_data.get("org"):
        row["ipinfo_org"] = _s(ipinfo_data.get("org"))
    if ipinfo_data.get("country"):
        row["ipinfo_country"] = _s(ipinfo_data.get("country"))

    # TOR — presence of the module key signals a hit
    if "TOR" in modules:
        row["tor"] = "true"

    # URLhaus (abuse.ch) — threat type if hit
    urlhaus = modules.get("URLhaus") or {}
    urlhaus_data = urlhaus.get("data") or {}
    threat = urlhaus_data.get("threat")
    if threat:
        row["urlhaus_threat"] = _s(threat)

    # ThreatFox (abuse.ch) — threat_type + malware family if hit
    threatfox = modules.get("ThreatFox") or {}
    threatfox_data = threatfox.get("data") or {}
    if threatfox_data.get("threat_type"):
        row["threatfox_threat_type"] = _s(threatfox_data.get("threat_type"))
    if threatfox_data.get("malware"):
        row["threatfox_malware"] = _s(threatfox_data.get("malware"))

    # MalwareBazaar (abuse.ch) — signature (malware family) + file_type
    malwarebazaar = modules.get("MalwareBazaar") or {}
    malwarebazaar_data = malwarebazaar.get("data") or {}
    if malwarebazaar_data.get("signature"):
        row["malwarebazaar_signature"] = _s(malwarebazaar_data.get("signature"))
    if malwarebazaar_data.get("file_type"):
        row["malwarebazaar_file_type"] = _s(malwarebazaar_data.get("file_type"))

    # GreyNoise — classification + name (Censys, Shodan, Mirai, ...)
    greynoise = modules.get("GreyNoise") or {}
    greynoise_data = greynoise.get("data") or {}
    if greynoise_data.get("classification"):
        row["greynoise_classification"] = _s(greynoise_data.get("classification"))
    if greynoise_data.get("name"):
        row["greynoise_name"] = _s(greynoise_data.get("name"))

    # WHOIS
    whois = modules.get("WHOIS") or {}
    whois_data = whois.get("data") or {}
    creation = whois_data.get("creation_date")
    if creation:
        if isinstance(creation, list):
            creation = creation[0] if creation else ""
        if isinstance(creation, (datetime, date)):
            creation = creation.isoformat()
        row["whois_creation_date"] = _s(creation)

    return row


def _s(value: Any) -> str:
    """Stringify a value for CSV output. ``None`` → ``""``."""
    if value is None:
        return ""
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)

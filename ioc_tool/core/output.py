"""Serialization helpers for enrichment results.

This module turns the dict structure returned by
:func:`ioc_tool.core.enrich.enrich_ioc` into machine-readable formats
that SOC pipelines can pipe into SIEMs, spreadsheets, and ticket
systems.

Pure stdlib (``json`` + ``csv`` + ``uuid``). Every emitter is pure:
takes results, returns a string. No printing, no file I/O.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import date, datetime, timezone
from typing import Any

# CSV columns — keep this list authoritative. Tests assert on it.
CSV_COLUMNS: list[str] = [
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
    "otx_pulse_count",
    "otx_first_pulse",
    "otx_adversary",
    "urlscan_total",
    "urlscan_malicious",
    "urlscan_first_result",
    "greynoise_classification",
    "greynoise_name",
    "nvd_cvss",
    "nvd_severity",
    "epss_score",
    "epss_percentile",
    "kev_in_catalog",
    "kev_ransomware",
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


def to_json(results: list[dict[str, Any]]) -> str:
    """Serialize enrichment results as pretty-printed JSON (indent=2).

    Includes every key in every module dict — nothing is dropped.
    Non-JSON-native values (datetimes, etc.) are coerced via
    :func:`_json_default`.
    """
    return json.dumps(results, indent=2, default=_json_default, sort_keys=False)


def to_csv(results: list[dict[str, Any]]) -> str:
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


def _flatten_result(result: dict[str, Any]) -> dict[str, str]:
    """Reduce a single enrichment dict to the CSV column dict.

    Every value is coerced to ``str`` so the CSV writer never chokes
    on lists / ints / None. Empty/missing fields end up as ``""``.
    """
    modules = (result or {}).get("modules", {}) or {}
    final_score = (result or {}).get("final_score", 0) or 0

    row: dict[str, str] = {col: "" for col in CSV_COLUMNS}
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

    # AlienVault OTX — pulse count + first pulse name + adversary
    otx = modules.get("OTX") or {}
    otx_data = otx.get("data") or {}
    otx_pulse_info = otx_data.get("pulse_info") or {}
    if "count" in otx_pulse_info:
        row["otx_pulse_count"] = _s(otx_pulse_info.get("count"))
    otx_pulses = otx_pulse_info.get("pulses") or []
    if otx_pulses:
        first_pulse = otx_pulses[0] or {}
        if first_pulse.get("name"):
            row["otx_first_pulse"] = _s(first_pulse.get("name"))
        if first_pulse.get("adversary"):
            row["otx_adversary"] = _s(first_pulse.get("adversary"))

    # URLscan.io — total hits + first result link + malicious flag
    urlscan = modules.get("URLscan") or {}
    urlscan_data = urlscan.get("data") or {}
    if urlscan_data:
        try:
            us_total = int(urlscan_data.get("total", 0) or 0)
        except (TypeError, ValueError):
            us_total = 0
        row["urlscan_total"] = _s(us_total)
        us_results = urlscan_data.get("results") or []
        if us_results:
            first = us_results[0] if isinstance(us_results[0], dict) else {}
            link = first.get("result")
            if link:
                row["urlscan_first_result"] = _s(link)
        is_malicious = False
        for entry in us_results:
            if not isinstance(entry, dict):
                continue
            verdicts = entry.get("verdicts") or {}
            overall = verdicts.get("overall") or {}
            if overall.get("malicious") is True:
                is_malicious = True
                break
        if is_malicious:
            row["urlscan_malicious"] = "yes"

    # GreyNoise — classification + name (Censys, Shodan, Mirai, ...)
    greynoise = modules.get("GreyNoise") or {}
    greynoise_data = greynoise.get("data") or {}
    if greynoise_data.get("classification"):
        row["greynoise_classification"] = _s(greynoise_data.get("classification"))
    if greynoise_data.get("name"):
        row["greynoise_name"] = _s(greynoise_data.get("name"))

    # NVD — CVSS v3.1 baseScore + severity
    nvd = modules.get("NVD") or {}
    nvd_data = nvd.get("data") or {}
    nvd_metrics = nvd_data.get("metrics") or {}
    cvss_v31 = nvd_metrics.get("cvssMetricV31") or []
    if cvss_v31:
        cvss_inner = (cvss_v31[0] or {}).get("cvssData") or {}
        base_score = cvss_inner.get("baseScore")
        if base_score is not None:
            row["nvd_cvss"] = _s(base_score)
        severity = cvss_inner.get("baseSeverity")
        if severity:
            row["nvd_severity"] = _s(severity)

    # EPSS — exploit-probability score + percentile (as "NN.NNN%")
    epss = modules.get("EPSS") or {}
    epss_data = epss.get("data") or {}
    if epss_data.get("epss") is not None:
        row["epss_score"] = _s(epss_data.get("epss"))
    if epss_data.get("percentile") is not None:
        try:
            pct_val = float(epss_data.get("percentile") or 0)
            row["epss_percentile"] = f"{pct_val * 100:.3f}%"
        except (TypeError, ValueError):
            pass

    # CISA KEV — catalog membership + ransomware-campaign flag
    kev = modules.get("KEV") or {}
    kev_data = kev.get("data") or {}
    if kev_data:
        row["kev_in_catalog"] = "yes"
        if kev_data.get("knownRansomwareCampaignUse") == "Known":
            row["kev_ransomware"] = "yes"

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


# ---------------------------------------------------------------------------
# STIX 2.1 export
# ---------------------------------------------------------------------------
#
# STIX (Structured Threat Information eXpression) 2.1 is the OASIS
# standard for sharing threat intelligence between platforms (MISP,
# OpenCTI, Anomali, TheHive, AlienVault OTX, …). A "bundle" wraps a
# list of SDOs (STIX Domain Objects); for IOC sharing the relevant
# SDOs are ``indicator`` (the pattern) plus optionally ``observed-data``
# (the raw sighting). We emit indicators with one STIX pattern per IOC,
# tagged with our composite risk score and per-source detections.
#
# We deliberately hand-roll the STIX JSON rather than depending on the
# 3rd-party ``stix2`` library — its dependency tree is heavy (antlr4,
# pytz, simplejson, pyjwt) and we only need a tiny slice (the bundle
# wrapper + indicator SDO). The shapes below match the STIX 2.1
# specification verbatim and validate against the OASIS reference
# parser; reviewers can spot-check via https://oasis-open.github.io/
# cti-documentation/stix/intro.

# Map our IOC type names to STIX 2.1 cyber-observable types in pattern.
_STIX_OBSERVABLE = {
    "ip": "ipv4-addr",
    "domain": "domain-name",
    "url": "url",
    "email": "email-addr",
    # Hashes are special — the type depends on length, but in STIX they
    # all live under "file:hashes.<algo>" so we keep one branch.
    "hash": "file",
}

# Hash algorithm names that STIX 2.1 recognises (must match
# stix-vocab/hash-algorithm-ov enumeration).
_STIX_HASH_ALG = {
    32: "MD5",
    40: "SHA-1",
    64: "SHA-256",
}


def _stix_pattern(ioc: str, ioc_type: str) -> str | None:
    """Build a STIX 2.1 pattern expression for the given IOC.

    Returns ``None`` for unsupported types (e.g. ``cve`` — STIX has its
    own ``vulnerability`` SDO that we'd need to model separately).
    """
    if ioc_type == "hash":
        algo = _STIX_HASH_ALG.get(len(ioc))
        if not algo:
            return None
        return f"[file:hashes.'{algo}' = '{ioc}']"

    observable = _STIX_OBSERVABLE.get(ioc_type)
    if not observable:
        return None

    field = "value" if observable != "email-addr" else "value"
    return f"[{observable}:{field} = '{ioc}']"


def _stix_labels(final_score: int, modules: dict[str, Any]) -> list[str]:
    """Derive STIX ``indicator_types`` labels from our score + module signals.

    STIX 2.1 enumerates: ``malicious-activity``, ``anomalous-activity``,
    ``benign``, ``compromised``, ``unknown``. We map by score tier and
    by which sources contributed positives.
    """
    labels: list[str] = []
    if final_score >= 60:
        labels.append("malicious-activity")
    elif final_score >= 30:
        labels.append("anomalous-activity")
    else:
        labels.append("unknown")

    heuristics = modules.get("Heuristics", {}).get("data", {}) if modules else {}
    if heuristics.get("typosquat") or heuristics.get("idn"):
        labels.append("anomalous-activity")
    return list(dict.fromkeys(labels))  # de-dupe, preserve order


def _stix_indicator(result: dict[str, Any], created_iso: str) -> dict[str, Any] | None:
    """Build a single STIX 2.1 ``indicator`` SDO from one enrichment result."""
    ioc = result.get("ioc")
    ioc_type = result.get("type", "")
    pattern = _stix_pattern(ioc, ioc_type) if ioc else None
    if pattern is None:
        return None

    final_score = int(result.get("final_score") or 0)
    modules = result.get("modules") or {}
    labels = _stix_labels(final_score, modules)

    # Stable indicator IDs from a name namespace — same IOC always produces
    # the same indicator UUID so re-enrichment doesn't create duplicates.
    namespace = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
    indicator_id = f"indicator--{uuid.uuid5(namespace, f'{ioc_type}:{ioc}')}"

    description_parts: list[str] = [f"ShadowScope composite score: {final_score} ({_risk_tier(final_score)})"]
    for source, entry in (modules or {}).items():
        if not isinstance(entry, dict):
            continue
        src_score = entry.get("score")
        if src_score:
            description_parts.append(f"{source}: {src_score}")

    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": created_iso,
        "modified": created_iso,
        "name": f"{ioc_type}: {ioc}",
        "description": " | ".join(description_parts),
        "indicator_types": labels,
        "pattern": pattern,
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": created_iso,
        "labels": [f"shadowscope:score:{final_score}", f"shadowscope:tier:{_risk_tier(final_score).lower()}"],
        "external_references": [
            {
                "source_name": "ShadowScope",
                "description": "Composite IOC enrichment + risk scoring",
            }
        ],
    }


def to_stix(results: list[dict[str, Any]]) -> str:
    """Serialize enrichment results as a STIX 2.1 bundle (one indicator per IOC).

    Unsupported IOC types (currently ``cve``) are silently dropped from
    the bundle — STIX has separate SDOs for those and we don't model
    them yet. Empty input → an empty bundle, which is still valid STIX.
    """
    created_iso = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    objects: list[dict[str, Any]] = []
    for result in results or []:
        indicator = _stix_indicator(result, created_iso)
        if indicator is not None:
            objects.append(indicator)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
    return json.dumps(bundle, indent=2, default=_json_default)


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------
#
# Markdown is the lingua franca for case documentation — analyst-friendly,
# pasteable into TheHive / Jira / Notion / Slack, source-controllable.
# Format: one top section per IOC with a score banner, a per-module table,
# heuristic flags, and the optional LLM summary. No external rendering
# library — just f-strings.


def _md_score_banner(score: int) -> str:
    """Return a coloured-square banner reflecting the risk tier."""
    tier = _risk_tier(score)
    icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "Safe": "⚪"}.get(tier, "⚪")
    return f"{icon} **{tier}** — composite score `{score}/100`"


def _md_module_table(modules: dict[str, Any]) -> str:
    """Render per-source rows as a Markdown table. Empty input → empty string."""
    if not modules:
        return ""
    rows = ["| Source | Score | Notes |", "|---|---|---|"]
    for name, entry in modules.items():
        if not isinstance(entry, dict):
            continue
        score = entry.get("score", 0)
        data = entry.get("data") or {}
        # Pick a couple of useful keys per source — keep it terse.
        note_parts: list[str] = []
        if name == "VirusTotal":
            stats = data.get("last_analysis_stats") or {}
            if stats:
                note_parts.append(f"{stats.get('malicious', 0)}/{sum(stats.values())} engines")
        elif name == "AbuseIPDB":
            conf = data.get("abuseConfidenceScore")
            if conf is not None:
                note_parts.append(f"confidence {conf}")
        elif name == "Heuristics":
            for key in ("nrd", "dga", "typosquat", "idn"):
                if key in data:
                    note_parts.append(key)
        elif name == "WHOIS":
            creation = data.get("creation_date")
            if creation:
                note_parts.append(f"created {creation}")
        notes = ", ".join(note_parts) if note_parts else ""
        rows.append(f"| {name} | {score} | {notes} |")
    return "\n".join(rows)


def _md_heuristics_block(modules: dict[str, Any]) -> str:
    """Surface heuristic flags (NRD / DGA / typosquat / IDN) as a bullet list."""
    h = (modules.get("Heuristics") or {}).get("data") or {}
    if not h:
        return ""
    lines: list[str] = ["**Heuristics:**"]
    if "nrd" in h:
        nrd = h["nrd"]
        lines.append(f"- NRD: {nrd['bucket']} (age {nrd['age_days']}d, created {nrd['created']})")
    if "dga" in h:
        dga = h["dga"]
        lines.append(
            f"- DGA: score {dga['score']}, entropy {dga['entropy']}, "
            f"consonant-run {dga['longest_consonant_run']}"
        )
    if "typosquat" in h:
        t = h["typosquat"]
        confusables = ", ".join(t["confusables"]) if t["confusables"] else "—"
        lines.append(f"- Typosquat of `{t['match']}` (distance {t['distance']}, confusables: {confusables})")
    if "idn" in h:
        idn = h["idn"]
        suffix = " — **MIXED-SCRIPT HOMOGRAPH**" if idn.get("mixed_script") else ""
        lines.append(f"- IDN: unicode=`{idn.get('unicode')}`{suffix}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Source agreement matrix
# ---------------------------------------------------------------------------
#
# Across N sources, how many flagged the IOC vs how many missed? The
# matrix is the analyst's anti-false-positive lens: a 90 from a single
# source against 7 sources reporting 0 is suspicious *of the source*,
# not of the IOC. Strong consensus (5/8 flag) is harder to argue away.
#
# We treat any source returning a score > 0 as "flagged". Info-only
# sources (Shodan, IPinfo, Allowlist) don't contribute either way —
# they have no opinion on risk. The Heuristics pseudo-module is also
# excluded so the matrix reflects external evidence only.

# Modules that are info-only / not opinion sources. Score is incidental
# (or zero by design) and shouldn't push the agreement numerator either way.
_NON_OPINION_MODULES = frozenset({"Shodan", "IPinfo", "Allowlist", "Heuristics", "crt.sh"})


def consensus_summary(result: dict[str, Any]) -> dict[str, Any]:
    """Compute a per-IOC source-agreement summary.

    Returns:
        {
            "sources_total": int,           # opinion sources that returned data
            "sources_flagged": int,         # of those, how many scored > 0
            "sources_missed": int,          # sources_total - sources_flagged
            "consensus": "none"|"low"|"medium"|"high",
            "rows": [{"source": name, "score": int, "flagged": bool}, ...]
        }

    ``consensus`` is a coarse tier derived from the flagged fraction:
    >= 70 % → high, >= 40 % → medium, > 0 → low, == 0 → none.
    """
    modules = (result or {}).get("modules") or {}
    rows: list[dict[str, Any]] = []
    for name, entry in modules.items():
        if name in _NON_OPINION_MODULES:
            continue
        if not isinstance(entry, dict):
            continue
        score = int(entry.get("score") or 0)
        rows.append({"source": name, "score": score, "flagged": score > 0})

    total = len(rows)
    flagged = sum(1 for r in rows if r["flagged"])
    if total == 0:
        consensus = "none"
    else:
        fraction = flagged / total
        if fraction >= 0.70:
            consensus = "high"
        elif fraction >= 0.40:
            consensus = "medium"
        elif fraction > 0:
            consensus = "low"
        else:
            consensus = "none"

    return {
        "sources_total": total,
        "sources_flagged": flagged,
        "sources_missed": total - flagged,
        "consensus": consensus,
        "rows": rows,
    }


def _md_consensus_block(result: dict[str, Any]) -> str:
    """Render the consensus summary as a Markdown section. Empty when no sources ran."""
    summary = consensus_summary(result)
    if summary["sources_total"] == 0:
        return ""
    flagged = summary["sources_flagged"]
    total = summary["sources_total"]
    consensus = summary["consensus"]
    icon = {"high": "🔴", "medium": "🟠", "low": "🟡", "none": "🟢"}.get(consensus, "⚪")
    return (
        f"**Source agreement:** {icon} `{flagged}/{total}` sources flagged "
        f"(consensus: **{consensus}**)"
    )


def to_markdown(
    results: list[dict[str, Any]],
    include_summaries: dict[int, str | None] | None = None,
) -> str:
    """Render enrichment results as a Markdown case-doc report.

    ``include_summaries`` (optional) maps result-index → LLM-summary
    string; populated keys get an "LLM Verdict" block per IOC. Pass
    ``None`` to skip LLM rendering even when summaries exist upstream.
    """
    if not results:
        return "# ShadowScope Report\n\n_No IOCs enriched._\n"

    now_iso = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    parts: list[str] = [
        "# ShadowScope Report",
        "",
        f"_Generated {now_iso} — {len(results)} IOC(s)_",
        "",
        "---",
    ]

    for idx, result in enumerate(results):
        ioc = result.get("ioc", "?")
        ioc_type = result.get("type", "?")
        score = int(result.get("final_score") or 0)
        modules = result.get("modules") or {}

        parts.append("")
        parts.append(f"## `{ioc}` _(type: {ioc_type})_")
        parts.append("")
        parts.append(_md_score_banner(score))
        parts.append("")

        table = _md_module_table(modules)
        if table:
            parts.append(table)
            parts.append("")

        consensus_block = _md_consensus_block(result)
        if consensus_block:
            parts.append(consensus_block)
            parts.append("")

        heuristics_block = _md_heuristics_block(modules)
        if heuristics_block:
            parts.append(heuristics_block)
            parts.append("")

        if include_summaries is not None:
            verdict = include_summaries.get(idx)
            if verdict:
                parts.append("**LLM Verdict:**")
                parts.append("")
                parts.append(f"> {verdict}")
                parts.append("")

        parts.append("---")

    return "\n".join(parts) + "\n"

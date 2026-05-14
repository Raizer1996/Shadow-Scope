"""LLM-generated natural-language verdict for enriched IOCs.

This module is **purely additive** — it never blocks or breaks core
enrichment. It calls a local Ollama HTTP server (default
``http://localhost:11434``) with a model-agnostic prompt built from the
result dict produced by :func:`ioc_tool.core.enrich.enrich_ioc` and
returns a 2-3 sentence analyst-grade verdict.

If Ollama is unreachable, returns ``None`` so callers can degrade
gracefully — never raises, never logs API keys (none involved), never
prints anything.

Environment variables (all optional):

* ``OLLAMA_BASE_URL`` — base URL of the Ollama server.
  Default: ``http://localhost:11434``
* ``OLLAMA_MODEL``    — model name to query.
  Default: ``llama3.2``
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import requests

DEFAULT_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = "llama3.2"
DEFAULT_TIMEOUT = 30
DEFAULT_NUM_PREDICT = 200
DEFAULT_TEMPERATURE = 0.2


# ---------------------------------------------------------------------------
# Risk tier helper — keep in sync with ioc_tool.core.output._risk_tier
# ---------------------------------------------------------------------------


def _tier_for_score(score: Any) -> str:
    """Map a 0-100 final score to a tier label.

    Mirrors the table in ``docs/ARCHITECTURE.md`` (Safe / Low / Medium /
    High / Critical). Safe-by-default on weird inputs so the prompt never
    looks malformed.
    """
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


# ---------------------------------------------------------------------------
# Per-source signal extractor
# ---------------------------------------------------------------------------


def _summarize_module(source: str, payload: Dict[str, Any]) -> str:
    """Return a one-line ``Source: <score> + 1-3 facts`` summary.

    Token-efficient by design — we keep each line tight so the whole
    prompt stays well under context windows for tiny local models.
    """
    score = payload.get("score", 0)
    data = payload.get("data") or {}
    parts: List[str] = []

    if source == "VirusTotal":
        stats = data.get("last_analysis_stats") or {}
        if stats:
            malicious = stats.get("malicious", 0)
            total = sum(v for v in stats.values() if isinstance(v, (int, float)))
            parts.append(f"{malicious}/{total} malicious")
    elif source == "AbuseIPDB":
        conf = data.get("abuseConfidenceScore")
        if conf is not None:
            parts.append(f"confidence {conf}")
        usage = data.get("usageType")
        if usage:
            parts.append(str(usage))
    elif source == "Shodan":
        tags = data.get("tags") or []
        if tags:
            parts.append("tags: " + ",".join(str(t) for t in tags[:3]))
        ports = data.get("ports") or []
        if ports:
            parts.append("ports: " + ",".join(str(p) for p in ports[:5]))
    elif source == "IPQS":
        fraud = data.get("fraud_score")
        if fraud is not None:
            parts.append(f"fraud_score {fraud}")
    elif source == "IPinfo":
        org = data.get("org")
        if org:
            parts.append(str(org))
        country = data.get("country")
        if country:
            parts.append(f"country {country}")
    elif source == "TOR":
        parts.append("Tor exit node")
    elif source == "WHOIS":
        creation = data.get("creation_date")
        if creation:
            parts.append(f"created {creation}")
    elif source == "URLhaus":
        threat = data.get("threat")
        if threat:
            parts.append(f"threat={threat}")
        tags = data.get("tags") or []
        if tags:
            parts.append("tags: " + ",".join(str(t) for t in tags[:3]))
    elif source == "ThreatFox":
        threat = data.get("threat_type")
        if threat:
            parts.append(f"threat_type={threat}")
        malware = data.get("malware")
        if malware:
            parts.append(f"malware={malware}")
    elif source == "MalwareBazaar":
        sig = data.get("signature")
        if sig:
            parts.append(f"signature={sig}")
        ftype = data.get("file_type")
        if ftype:
            parts.append(f"type={ftype}")
    elif source == "GreyNoise":
        classification = data.get("classification")
        if classification:
            parts.append(f"class={classification}")
        name = data.get("name")
        if name:
            parts.append(str(name))
    elif source == "OTX":
        pulse_info = data.get("pulse_info") or {}
        count = pulse_info.get("count")
        if count:
            parts.append(f"{count} pulses")
        pulses = pulse_info.get("pulses") or []
        if pulses:
            first_name = (pulses[0].get("name") or "").strip()
            if first_name:
                if len(first_name) > 60:
                    first_name = first_name[:57] + "..."
                parts.append(first_name)
    elif source == "URLscan":
        total = data.get("total")
        if total:
            parts.append(f"{total} scans")
        for entry in data.get("results") or []:
            if not isinstance(entry, dict):
                continue
            verdicts = entry.get("verdicts") or {}
            overall = verdicts.get("overall") or {}
            if overall.get("malicious") is True:
                parts.append("malicious verdict")
                break
    elif source == "NVD":
        metrics = data.get("metrics") or {}
        cvss_v31 = metrics.get("cvssMetricV31") or []
        if cvss_v31:
            cvss_data = (cvss_v31[0] or {}).get("cvssData") or {}
            base = cvss_data.get("baseScore")
            sev = cvss_data.get("baseSeverity")
            if base is not None:
                parts.append(f"CVSS {base}")
            if sev:
                parts.append(str(sev))
    elif source == "EPSS":
        epss_val = data.get("epss")
        if epss_val is not None:
            parts.append(f"EPSS {epss_val}")
        pct = data.get("percentile")
        if pct is not None:
            try:
                parts.append(f"percentile {float(pct) * 100:.1f}%")
            except (TypeError, ValueError):
                pass
    elif source == "KEV":
        parts.append("listed in CISA KEV")
        if data.get("knownRansomwareCampaignUse") == "Known":
            parts.append("ransomware")

    # Fallback if nothing matched — still show score so prompt isn't empty.
    detail = "; ".join(parts) if parts else "data present"
    return f"{source}: score={score}; {detail}"


def _build_prompt(result: Dict[str, Any]) -> str:
    """Construct the LLM prompt from an enrichment result dict.

    The output stays under ~600 chars even for IOCs with every source
    hit. Private/testable — exposed for the unit test that asserts the
    prompt contains the IOC value, final score, and at least one source.
    """
    ioc = result.get("ioc") or "<unknown>"
    ioc_type = result.get("type") or "unknown"
    final_score = result.get("final_score", 0)
    tier = _tier_for_score(final_score)

    modules = result.get("modules") or {}
    source_lines: List[str] = []
    for source, payload in modules.items():
        if not isinstance(payload, dict):
            continue
        source_lines.append(_summarize_module(source, payload))

    if not source_lines:
        source_lines.append("(no source signals)")

    sources_block = "\n".join(source_lines)

    return (
        "You are a SOC analyst. Given the following IOC enrichment data, "
        "write a concise 2-3 sentence verdict explaining the risk level "
        "and the dominant signals driving the score. Recommend a clear "
        "next action. Avoid bullet points or headers — just plain prose.\n"
        "\n"
        f"IOC: {ioc}\n"
        f"Type: {ioc_type}\n"
        f"Composite risk score: {final_score}/100 ({tier})\n"
        "\n"
        "Per-source signals:\n"
        f"{sources_block}\n"
        "\n"
        "Verdict:"
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def summarize(
    result: Dict[str, Any],
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Optional[str]:
    """Generate a 2-3 sentence natural-language verdict for an enriched IOC.

    Calls the local Ollama HTTP API (``POST /api/generate``) with a
    model-agnostic prompt built from ``result``. Pure additive feature —
    any failure (connection error, timeout, non-200, malformed JSON,
    missing ``response`` field) returns ``None`` instead of raising so
    the caller can degrade gracefully.

    Args:
        result: dict returned by :func:`enrich_ioc` / :func:`enrich_ioc_async`.
        model: Ollama model name. Defaults to env ``OLLAMA_MODEL`` or
            ``llama3.2``.
        base_url: Ollama base URL. Defaults to env ``OLLAMA_BASE_URL``
            or ``http://localhost:11434``.
        timeout: HTTP timeout in seconds (default 30).

    Returns:
        The stripped text response from the model, or ``None`` on any
        failure.
    """
    if not isinstance(result, dict):
        return None

    chosen_model = model or os.getenv("OLLAMA_MODEL") or DEFAULT_MODEL
    chosen_base = (base_url or os.getenv("OLLAMA_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
    url = f"{chosen_base}/api/generate"

    try:
        prompt = _build_prompt(result)
    except Exception:
        return None

    body = {
        "model": chosen_model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": DEFAULT_TEMPERATURE,
            "num_predict": DEFAULT_NUM_PREDICT,
        },
    }

    try:
        response = requests.post(url, json=body, timeout=timeout)
    except requests.exceptions.RequestException:
        return None
    except Exception:
        return None

    if response.status_code != 200:
        return None

    try:
        payload = response.json()
    except ValueError:
        return None

    text = payload.get("response") if isinstance(payload, dict) else None
    if not isinstance(text, str):
        return None

    stripped = text.strip()
    return stripped or None

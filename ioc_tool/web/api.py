"""FastAPI REST API for ShadowScope.

Thin HTTP wrapper around the existing enrichment pipeline. The
underlying async orchestrator (:func:`ioc_tool.core.enrich.enrich_ioc_async`)
is reused as-is — this module only:

* parses request bodies / query params,
* refangs input,
* routes to the right helper (``enrich`` / ``show`` / ``extract``),
* applies the optional output defang,
* serialises the result dict as JSON.

# Auth model

Bearer token via the ``SHADOWSCOPE_API_TOKEN`` env var. Unset = no auth
(suitable for localhost-only homelab use). ``/health`` is always public so
container healthchecks don't need the token.

# CORS

Permissive by default (``*``) — override via ``SHADOWSCOPE_CORS_ORIGINS``
(comma-separated origins).

# Integration

Designed to be consumed by the homelab "secops web service" which embeds
ShadowScope as a callable HTTP API. Endpoints intentionally mirror CLI
verbs (`enrich`, `show`, `extract`) so downstream consumers can map
verbatim from CLI scripts to HTTP calls.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ..core import database, enrich, extractor, output, parser
from ..core import defang as defang_mod
from ..core import llm as llm_mod

API_VERSION = "0.9.0"

# Static assets for the dashboard UI. The directory holds index.html,
# styles.css, app.js — all served verbatim, no build step.
STATIC_DIR = Path(__file__).parent / "static"


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------


def require_token(authorization: str | None = Header(None)) -> None:
    """Bearer-token auth dependency.

    Token comes from ``SHADOWSCOPE_API_TOKEN``. If unset, all requests are
    allowed through (homelab localhost convenience). When set, every
    protected endpoint requires ``Authorization: Bearer <token>``.

    Error messages are deliberately generic — we never leak whether a
    token is configured at all via response bodies.
    """
    expected = os.getenv("SHADOWSCOPE_API_TOKEN")
    if not expected:
        return  # auth disabled
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or malformed Authorization header",
        )
    if authorization[7:] != expected:
        raise HTTPException(status_code=403, detail="Invalid token")


# ---------------------------------------------------------------------------
# Pydantic request / response models
# ---------------------------------------------------------------------------


class BulkEnrichRequest(BaseModel):
    """Request body for ``POST /enrich/bulk``."""

    iocs: list[str] = Field(
        ...,
        description="List of IOC strings to enrich (auto-detected, refanged)",
    )


class ExtractRequest(BaseModel):
    """Request body for ``POST /extract``."""

    text: str = Field(
        ...,
        description="Free-form text blob — IOCs are auto-extracted and enriched",
    )


class HealthResponse(BaseModel):
    status: str


class ServiceInfoResponse(BaseModel):
    name: str
    version: str
    endpoints: list[str]


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _apply_output_defang(result: dict[str, Any], should_defang: bool) -> dict[str, Any]:
    """Optionally defang the ``ioc`` field on a single enrichment result."""
    if should_defang and isinstance(result, dict) and isinstance(result.get("ioc"), str):
        result = dict(result)  # don't mutate caller's reference
        result["ioc"] = defang_mod.defang(result["ioc"])
    return result


async def _attach_summaries(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run ``llm.summarize`` for each result concurrently and inject ``llm_summary``.

    Summarisation is network I/O against Ollama — we parallelise via
    ``asyncio.gather(asyncio.to_thread(...))`` so a batch of N IOCs only
    pays one round-trip's worth of wall-clock latency. Failures land as
    ``None`` and the key is omitted.
    """
    if not results:
        return results
    tasks = [asyncio.to_thread(llm_mod.summarize, r) for r in results]
    summaries = await asyncio.gather(*tasks, return_exceptions=True)
    enriched: list[dict[str, Any]] = []
    for r, s in zip(results, summaries, strict=True):
        merged = dict(r)
        if isinstance(s, str) and s:
            merged["llm_summary"] = s
        enriched.append(merged)
    return enriched


async def _enrich_one(ioc: str) -> dict[str, Any]:
    """Refang → detect type → run async enrichment. Raises HTTPException on unknown type."""
    refanged = defang_mod.refang(ioc)
    ioc_type = parser.detect_type(refanged)
    if ioc_type == "unknown":
        raise HTTPException(
            status_code=400,
            detail=f"Unable to detect IOC type for value: {ioc!r}. "
                   "Supported types: ip, domain, url, hash, email.",
        )
    return await enrich.enrich_ioc_async(refanged, ioc_type)


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------


def _cors_origins() -> list[str]:
    """Parse ``SHADOWSCOPE_CORS_ORIGINS`` (comma-separated) → list. Default: ``["*"]``."""
    raw = os.getenv("SHADOWSCOPE_CORS_ORIGINS", "*")
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    return parts or ["*"]


app = FastAPI(
    title="ShadowScope API",
    description="REST API over the ShadowScope IOC enrichment pipeline.",
    version=API_VERSION,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount the dashboard static assets at /static so CSS/JS resolve with stable
# absolute paths regardless of where the UI is reached from.
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


class ServiceInfoResponseWithUI(ServiceInfoResponse):
    """Service info plus a ``ui`` pointer to the dashboard route."""

    ui: str


@app.get("/", response_model=ServiceInfoResponseWithUI, dependencies=[Depends(require_token)])
def root() -> ServiceInfoResponseWithUI:
    """Service banner — version + endpoint list + dashboard pointer."""
    return ServiceInfoResponseWithUI(
        name="ShadowScope",
        version=API_VERSION,
        endpoints=[
            "GET /",
            "GET /health",
            "GET /enrich?ioc=<value>[&defang=true]",
            "POST /enrich/bulk",
            "POST /extract",
            "GET /show?ioc=<value>[&defang=true]",
            "GET /sources",
            "GET /ui",
        ],
        ui="/ui",
    )


@app.get("/ui", include_in_schema=False)
def ui() -> FileResponse:
    """Serve the brutalist dashboard (default).

    The HTML itself is harmless — the JSON data behind it is auth-gated by
    the ``require_token`` dependency on each fetch the JS makes. The route
    intentionally has **no** auth dependency so an unauthenticated browser
    can still load the shell and prompt the user for a token.

    The current build is a React+Babel-standalone prototype using mock data
    from ``shared/data.js``. Backend wiring lands in a follow-up.
    """
    return FileResponse(STATIC_DIR / "index.html", media_type="text/html")


@app.get("/ui-classic", include_in_schema=False)
def ui_classic() -> FileResponse:
    """Serve the legacy vanilla dashboard at ``/ui-classic``.

    Kept reachable so the previous backend-wired UI stays available while
    the brutalist React prototype gets its API integration. Will be
    removed once the brutalist UI is fully wired to the real endpoints.
    """
    return FileResponse(STATIC_DIR / "classic" / "index.html", media_type="text/html")


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Liveness check — always public so healthchecks don't need a token."""
    return HealthResponse(status="ok")


# ---------------------------------------------------------------------------
# UI shape adapter
# ---------------------------------------------------------------------------
#
# The brutalist React dashboard expects each result with a few extra
# fields the raw orchestrator doesn't emit: a stable client-side ``id``,
# pre-computed ``agreement`` summary, per-module ``detail`` one-liners,
# and a ``prev_score`` for the score-delta strip. Rather than mutate the
# orchestrator (which the CLI consumes), we synthesise those fields here.

def _ui_detail(source: str, score: int, data: dict[str, Any]) -> str:
    """Return a terse per-source detail summary for the dashboard table."""
    data = data or {}
    if source == "VirusTotal":
        stats = (data.get("last_analysis_stats") or {})
        total = sum(int(v or 0) for v in stats.values())
        mal = int(stats.get("malicious") or 0)
        if total:
            return f"{mal} / {total} engines malicious"
    elif source == "AbuseIPDB":
        conf = data.get("abuseConfidenceScore")
        reports = data.get("totalReports")
        if conf is not None:
            tail = f" · {reports} reports" if reports else ""
            return f"confidence {conf}{tail}"
    elif source == "URLhaus":
        threat = data.get("threat")
        tags = data.get("tags") or []
        if threat:
            tag_part = f" · tag={tags[0]}" if tags else ""
            return f"threat={threat}{tag_part}"
    elif source == "ThreatFox":
        malware = data.get("malware")
        confidence = data.get("confidence_level")
        if malware:
            return f"{malware} · confidence {confidence}" if confidence else str(malware)
    elif source == "Pulsedive":
        risk = data.get("risk")
        threats = data.get("threats") or []
        if risk:
            t = threats[0].get("name") if threats and isinstance(threats[0], dict) else ""
            tail = f" · {t}" if t else ""
            return f"risk={risk}{tail}"
    elif source == "WHOIS":
        creation = data.get("creation_date")
        if creation:
            return f"created {creation}"
    elif source == "GreyNoise":
        cls = data.get("classification") or data.get("noise")
        if cls is not None:
            return f"classification={cls}"
    elif source == "Feodo":
        malware = data.get("malware")
        status = data.get("status")
        if malware or status:
            return f"{malware or 'C2'} · {status or 'listed'}"
    elif source == "SSLBL":
        return data.get("malware") or "malicious cert hash"
    elif source == "Heuristics":
        parts = []
        if "nrd" in data and isinstance(data["nrd"], dict):
            age = data["nrd"].get("age_days")
            parts.append(f"NRD({age}d)" if age is not None else "NRD")
        if "dga" in data and isinstance(data["dga"], dict):
            parts.append(f"DGA={data['dga'].get('score', 0)}")
        if "typosquat" in data and isinstance(data["typosquat"], dict):
            parts.append(f"typo→{data['typosquat'].get('match', '?')}")
        if "idn" in data and isinstance(data["idn"], dict):
            mixed = data["idn"].get("mixed_script")
            parts.append("IDN-mixed" if mixed else "IDN")
        if parts:
            return " · ".join(parts)
    elif source == "OTX":
        pulse = (data.get("pulse_info") or {}).get("count")
        if pulse:
            return f"{pulse} pulses"
    elif source == "URLscan":
        scans = data.get("total")
        if scans:
            return f"{scans} scans"
    elif source == "crt.sh":
        certs = data.get("total")
        subs = data.get("subdomain_count")
        if certs:
            return f"{certs} certs · {subs or 0} subdomains"
    return "—" if score == 0 else ""


def _ui_record_id(ioc: str, ioc_type: str) -> str:
    """Stable client-side ID — same IOC always renders to the same row in the UI."""
    digest = hashlib.sha1(f"{ioc_type}:{ioc}".encode()).hexdigest()[:12]
    return f"ioc_{digest}"


def _to_ui_shape(result: dict[str, Any], prev_score: int | None) -> dict[str, Any]:
    """Add ``id``, ``agreement``, per-module ``detail``, and ``enriched_at`` to a raw enrichment."""
    ioc = result.get("ioc", "")
    ioc_type = result.get("type", "")
    modules_raw = result.get("modules") or {}
    modules_ui: dict[str, Any] = {}
    for source, entry in modules_raw.items():
        if not isinstance(entry, dict):
            continue
        score = int(entry.get("score") or 0)
        data = entry.get("data") or {}
        modules_ui[source] = {
            "score": score,
            "detail": _ui_detail(source, score, data),
            "data": data,
        }

    return {
        "id": _ui_record_id(ioc, ioc_type),
        "ioc": ioc,
        "type": ioc_type,
        "final_score": int(result.get("final_score") or 0),
        "prev_score": prev_score if prev_score is not None else int(result.get("final_score") or 0),
        "enriched_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "agreement": output.consensus_summary(result),
        "modules": modules_ui,
    }


@app.get("/api/ui/enrich", dependencies=[Depends(require_token)])
async def ui_enrich(
    ioc: str = Query(..., description="IOC value (auto-detected, refanged)"),
    defang: bool = Query(False, description="Defang the returned ioc field"),
    summary: bool = Query(False, description="Attach llm_summary via local Ollama"),
    no_cache: bool = Query(False, description="Bypass the SQLite cache"),
) -> dict[str, Any]:
    """Enrich + reshape for the brutalist dashboard.

    Adds the UI-only fields (id, agreement, per-module detail, prev_score)
    around the raw orchestrator output. The dashboard's ``onEnrich`` calls
    this endpoint rather than ``/enrich`` so the JSX doesn't have to know
    about the synthesis logic.
    """
    refanged = defang_mod.refang(ioc)
    ioc_type = parser.detect_type(refanged)
    if ioc_type == "unknown":
        raise HTTPException(
            status_code=400,
            detail=f"Unable to detect IOC type for value: {ioc!r}.",
        )

    # Grab the previous composite from iocs.last_score BEFORE re-enrich, so
    # the dashboard can show a delta on subsequent enrichments.
    database.init_db()
    prev_score: int | None = None
    ioc_id = database.get_ioc_id(refanged)
    if ioc_id is not None:
        conn = database.get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT last_score FROM iocs WHERE id = ?", (ioc_id,))
        row = cur.fetchone()
        conn.close()
        if row and row[0] is not None:
            prev_score = int(row[0])

    result = await enrich.enrich_ioc_async(refanged, ioc_type, no_cache=no_cache)
    if defang:
        result = _apply_output_defang(result, True)
    if summary:
        verdict = await asyncio.to_thread(llm_mod.summarize, result)
        if isinstance(verdict, str) and verdict:
            result = dict(result)
            result["llm_summary"] = verdict

    shaped = _to_ui_shape(result, prev_score)
    if "llm_summary" in result:
        shaped["llm_summary"] = result["llm_summary"]
    return shaped


@app.get("/enrich", dependencies=[Depends(require_token)])
async def enrich_single(
    ioc: str = Query(..., description="IOC value (auto-detected, refanged)"),
    defang: bool = Query(False, description="Defang the returned ioc field"),
    summary: bool = Query(
        False,
        description="Attach an llm_summary field via local Ollama (optional)",
    ),
) -> dict[str, Any]:
    """Enrich a single IOC. Type is auto-detected and defanged input is refanged."""
    result = await _enrich_one(ioc)
    result = _apply_output_defang(result, defang)
    if summary:
        verdict = await asyncio.to_thread(llm_mod.summarize, result)
        if isinstance(verdict, str) and verdict:
            result = dict(result)
            result["llm_summary"] = verdict
    return result


@app.post("/enrich/bulk", dependencies=[Depends(require_token)])
async def enrich_bulk(
    payload: BulkEnrichRequest,
    defang: bool = Query(False, description="Defang the returned ioc fields"),
    summary: bool = Query(
        False,
        description="Attach an llm_summary field via local Ollama (optional)",
    ),
) -> list[dict[str, Any]]:
    """Enrich many IOCs concurrently.

    Unknown-type entries are dropped (with no exception) so a single bad
    value in a batch doesn't break the whole request. Each accepted IOC
    runs through the existing async pipeline via ``asyncio.gather``.
    """
    tasks = []
    for raw in payload.iocs:
        refanged = defang_mod.refang(raw)
        ioc_type = parser.detect_type(refanged)
        if ioc_type == "unknown":
            continue
        tasks.append(enrich.enrich_ioc_async(refanged, ioc_type))

    if not tasks:
        return []

    raw_results = await asyncio.gather(*tasks, return_exceptions=True)
    results: list[dict[str, Any]] = []
    for item in raw_results:
        if isinstance(item, BaseException):
            # Never crash the whole batch — match the CLI contract.
            continue
        results.append(_apply_output_defang(item, defang))
    if summary:
        results = await _attach_summaries(results)
    return results


@app.post("/extract", dependencies=[Depends(require_token)])
async def extract_and_enrich(
    payload: ExtractRequest,
    defang: bool = Query(False, description="Defang the returned ioc fields"),
    summary: bool = Query(
        False,
        description="Attach an llm_summary field via local Ollama (optional)",
    ),
) -> dict[str, Any]:
    """Extract IOCs from a free-form text blob, then enrich each.

    Mirrors ``shadowscope enrich --text "..."`` — same extractor, same
    enrichment pipeline. The response carries both the raw extraction
    bucket dict (so callers can show what was pulled) and the enrichment
    results.
    """
    extracted = extractor.extract_iocs(payload.text or "")

    # Flatten across buckets, preserving order — same shape the CLI uses.
    iocs_to_process: list[str] = []
    for bucket in extracted.values():
        iocs_to_process.extend(bucket)

    tasks = []
    for raw in iocs_to_process:
        refanged = defang_mod.refang(raw)
        ioc_type = parser.detect_type(refanged)
        if ioc_type == "unknown":
            continue
        tasks.append(enrich.enrich_ioc_async(refanged, ioc_type))

    raw_results = await asyncio.gather(*tasks, return_exceptions=True) if tasks else []
    results: list[dict[str, Any]] = []
    for item in raw_results:
        if isinstance(item, BaseException):
            continue
        results.append(_apply_output_defang(item, defang))

    if summary:
        results = await _attach_summaries(results)

    return {"extracted": extracted, "results": results}


@app.get("/show", dependencies=[Depends(require_token)])
def show_cached(
    ioc: str = Query(..., description="IOC value to look up in the cache"),
    defang: bool = Query(False, description="Defang the returned ioc field"),
) -> dict[str, Any]:
    """Return the cached enrichment for an IOC without refetching.

    404 if the IOC has never been enriched (no row in ``iocs`` table).
    """
    refanged = defang_mod.refang(ioc)
    ioc_id = database.get_ioc_id(refanged)
    if not ioc_id:
        raise HTTPException(
            status_code=404,
            detail=f"IOC {refanged!r} not found in cache",
        )

    # Pull every cached source row for this IOC. We don't re-fetch — this
    # is the "show" semantic. Each source gets its latest cached row.
    import json as _json

    ioc_type = parser.detect_type(refanged)
    modules: dict[str, dict[str, Any]] = {}
    scores: list[int] = []

    # Iterate over every source the orchestrator might have written.
    # We deliberately query the DB directly here rather than calling the
    # orchestrator, to honour the "show = no refetch" contract.
    for source_key, display_name in (
        ("virustotal", "VirusTotal"),
        ("abuseipdb", "AbuseIPDB"),
        ("shodan", "Shodan"),
        ("ipqs", "IPQS"),
        ("ipinfo", "IPinfo"),
        ("greynoise", "GreyNoise"),
        ("urlhaus", "URLhaus"),
        ("threatfox", "ThreatFox"),
        ("malwarebazaar", "MalwareBazaar"),
        ("otx", "OTX"),
        ("urlscan", "URLscan"),
        ("whois", "WHOIS"),
    ):
        row = database.get_latest_enrichment(ioc_id, source_key)
        if row is None:
            continue
        try:
            data = _json.loads(row["data"])
        except (TypeError, ValueError):
            data = {}
        modules[display_name] = {"score": row["score"], "data": data}
        scores.append(row["score"] or 0)

    from ..core import score as score_mod
    final_score = score_mod.calculate_final_risk(scores)

    result: dict[str, Any] = {
        "ioc": refanged,
        "type": ioc_type,
        "modules": modules,
        "final_score": final_score,
    }
    return _apply_output_defang(result, defang)


@app.get("/sources", dependencies=[Depends(require_token)])
def list_sources() -> dict[str, bool]:
    """List every configured source and whether its key is present.

    Returns a flat ``{source_name: key_is_set}`` dict. Never returns the
    key itself — that would leak secrets into HTTP responses.

    Sources that need no API key (URLhaus, ThreatFox, MalwareBazaar, Tor,
    WHOIS) report ``True`` unconditionally.
    """
    return {
        "virustotal": bool(os.getenv("VT_API_KEY")),
        "abuseipdb": bool(os.getenv("ABUSEIPDB_API_KEY")),
        "shodan": bool(os.getenv("SHODAN_API_KEY")),
        "ipqs": bool(os.getenv("IPQS_API_KEY")),
        "ipinfo": bool(os.getenv("IPINFO_API_KEY")),
        "greynoise": bool(os.getenv("GREYNOISE_API_KEY")),
        "otx": bool(os.getenv("OTX_API_KEY")),
        "urlscan": bool(os.getenv("URLSCAN_API_KEY")),
        "hybrid_analysis": bool(os.getenv("HYBRID_ANALYSIS_API_KEY")),
        "joe_sandbox": bool(os.getenv("JOE_SANDBOX_CLOUD_API_KEY")),
        "filescan_io": bool(os.getenv("FILE_SCAN_IO")),
        # No-key-required sources are always available
        "urlhaus": True,
        "threatfox": True,
        "malwarebazaar": True,
        "tor": True,
        "whois": True,
    }

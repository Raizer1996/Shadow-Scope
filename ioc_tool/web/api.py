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
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ..core import database, defang as defang_mod, enrich, extractor, parser

API_VERSION = "0.9.0"

# Static assets for the dashboard UI. The directory holds index.html,
# styles.css, app.js — all served verbatim, no build step.
STATIC_DIR = Path(__file__).parent / "static"


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------


def require_token(authorization: Optional[str] = Header(None)) -> None:
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

    iocs: List[str] = Field(
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
    endpoints: List[str]


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _apply_output_defang(result: Dict[str, Any], should_defang: bool) -> Dict[str, Any]:
    """Optionally defang the ``ioc`` field on a single enrichment result."""
    if should_defang and isinstance(result, dict) and isinstance(result.get("ioc"), str):
        result = dict(result)  # don't mutate caller's reference
        result["ioc"] = defang_mod.defang(result["ioc"])
    return result


async def _enrich_one(ioc: str) -> Dict[str, Any]:
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


def _cors_origins() -> List[str]:
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
    """Serve the dashboard single-page UI.

    The HTML itself is harmless — the JSON data behind it is auth-gated by
    the ``require_token`` dependency on each fetch the JS makes. The route
    intentionally has **no** auth dependency so an unauthenticated browser
    can still load the shell and prompt the user for a token.
    """
    return FileResponse(STATIC_DIR / "index.html", media_type="text/html")


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Liveness check — always public so healthchecks don't need a token."""
    return HealthResponse(status="ok")


@app.get("/enrich", dependencies=[Depends(require_token)])
async def enrich_single(
    ioc: str = Query(..., description="IOC value (auto-detected, refanged)"),
    defang: bool = Query(False, description="Defang the returned ioc field"),
) -> Dict[str, Any]:
    """Enrich a single IOC. Type is auto-detected and defanged input is refanged."""
    result = await _enrich_one(ioc)
    return _apply_output_defang(result, defang)


@app.post("/enrich/bulk", dependencies=[Depends(require_token)])
async def enrich_bulk(
    payload: BulkEnrichRequest,
    defang: bool = Query(False, description="Defang the returned ioc fields"),
) -> List[Dict[str, Any]]:
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
    results: List[Dict[str, Any]] = []
    for item in raw_results:
        if isinstance(item, Exception):
            # Never crash the whole batch — match the CLI contract.
            continue
        results.append(_apply_output_defang(item, defang))
    return results


@app.post("/extract", dependencies=[Depends(require_token)])
async def extract_and_enrich(
    payload: ExtractRequest,
    defang: bool = Query(False, description="Defang the returned ioc fields"),
) -> Dict[str, Any]:
    """Extract IOCs from a free-form text blob, then enrich each.

    Mirrors ``shadowscope enrich --text "..."`` — same extractor, same
    enrichment pipeline. The response carries both the raw extraction
    bucket dict (so callers can show what was pulled) and the enrichment
    results.
    """
    extracted = extractor.extract_iocs(payload.text or "")

    # Flatten across buckets, preserving order — same shape the CLI uses.
    iocs_to_process: List[str] = []
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
    results: List[Dict[str, Any]] = []
    for item in raw_results:
        if isinstance(item, Exception):
            continue
        results.append(_apply_output_defang(item, defang))

    return {"extracted": extracted, "results": results}


@app.get("/show", dependencies=[Depends(require_token)])
def show_cached(
    ioc: str = Query(..., description="IOC value to look up in the cache"),
    defang: bool = Query(False, description="Defang the returned ioc field"),
) -> Dict[str, Any]:
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
    modules: Dict[str, Dict[str, Any]] = {}
    scores: List[int] = []

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

    result: Dict[str, Any] = {
        "ioc": refanged,
        "type": ioc_type,
        "modules": modules,
        "final_score": final_score,
    }
    return _apply_output_defang(result, defang)


@app.get("/sources", dependencies=[Depends(require_token)])
def list_sources() -> Dict[str, bool]:
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

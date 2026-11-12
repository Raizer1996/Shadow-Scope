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

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import __version__
from ..core import database, enrich, extractor, output, parser, userlists
from ..core import defang as defang_mod
from ..core import llm as llm_mod
from . import _synthesis, eventbus

API_VERSION = __version__  # single source: ioc_tool/__init__.py

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


class UiExtractRequest(BaseModel):
    """Request body for ``POST /api/ui/extract`` (Batch tab paste box)."""

    text: str = Field(..., max_length=256_000, description="Pasted list, log excerpt or report")


class ExtractRequest(BaseModel):
    """Request body for ``POST /extract``."""

    text: str = Field(
        ...,
        description="Free-form text blob — IOCs are auto-extracted and enriched",
    )


class CachePerSourceRow(BaseModel):
    source: str
    rows: int


class CacheStatsResponse(BaseModel):
    """Snapshot of the enrichment cache for the active workspace."""

    db_path: str
    db_size_bytes: int
    ioc_count: int
    enrichment_count: int
    oldest_timestamp: str | None
    newest_timestamp: str | None
    per_source: list[CachePerSourceRow]


class CachePruneRequest(BaseModel):
    """Request body for ``POST /api/cache/prune``."""

    older_than_days: float | None = Field(
        default=None,
        description="Retention window in days (float supported). Defaults to RETENTION_DAYS env or 90.",
    )
    keep_last: int | None = Field(
        default=None,
        description="After age-pruning, cap rows per (ioc, source) to the newest N.",
    )


class CachePruneResponse(BaseModel):
    used_older_than_days: float
    used_keep_last: int
    removed_by_age: int
    removed_by_keep_last: int


class CacheClearRequest(BaseModel):
    """Request body for ``POST /api/cache/clear``.

    Exactly one of ``source`` / ``ioc`` / ``all`` must be set, mirroring
    the CLI's safety check so callers can't accidentally wipe everything.
    """

    source: str | None = None
    ioc: str | None = None
    all: bool = False


class CacheClearResponse(BaseModel):
    scope: str  # human-readable description of what was deleted
    removed: int


class HealthResponse(BaseModel):
    status: str
    version: str


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


# Loopback origins used as the safe default when SHADOWSCOPE_API_TOKEN is
# set but no explicit SHADOWSCOPE_CORS_ORIGINS was provided. Mirrors the
# default port ``shadowscope serve`` binds to (8765).
_DEFAULT_LOOPBACK_ORIGINS: tuple[str, ...] = (
    "http://localhost:8765",
    "http://127.0.0.1:8765",
)


def _cors_origins() -> list[str]:
    """Resolve allowed CORS origins.

    Behaviour:
    * ``SHADOWSCOPE_CORS_ORIGINS`` set → use it verbatim (comma-separated).
    * Token configured (``SHADOWSCOPE_API_TOKEN`` set) and no origins
      override → default to loopback only (``http://localhost:8765``,
      ``http://127.0.0.1:8765``). Tightens the permissive ``*`` legacy
      default when auth is on so a stolen token can't be replayed
      cross-origin from arbitrary pages.
    * No token and no override → ``["*"]`` (open dev install).
    """
    raw = os.getenv("SHADOWSCOPE_CORS_ORIGINS")
    if raw is not None:
        parts = [p.strip() for p in raw.split(",") if p.strip()]
        if parts:
            return parts
    if os.getenv("SHADOWSCOPE_API_TOKEN"):
        return list(_DEFAULT_LOOPBACK_ORIGINS)
    return ["*"]


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


@app.on_event("startup")
async def _attach_eventbus() -> None:
    """Bind the in-process event bus to FastAPI's running loop.

    The enrichment pipeline calls ``eventbus.publish`` from sync code;
    that publisher needs a loop reference to dispatch onto. We grab the
    loop at startup so the bus stays decoupled from the web layer's
    request lifecycle.
    """
    eventbus.attach(asyncio.get_running_loop())


@app.on_event("shutdown")
async def _detach_eventbus() -> None:
    eventbus.detach()


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
def ui() -> HTMLResponse:
    """Serve the brutalist dashboard (default).

    The HTML itself is harmless — the JSON data behind it is auth-gated by
    the ``require_token`` dependency on each fetch the JS makes. The route
    intentionally has **no** auth dependency so an unauthenticated browser
    can still load the shell.

    The shell is served from disk with one injection: ``window.SHADOWSCOPE_VERSION``
    so the UI badge always shows the running package version instead of a
    hard-coded string.
    """
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    inject = f'<script>window.SHADOWSCOPE_VERSION = "{API_VERSION}";</script>\n</head>'
    html = html.replace("</head>", inject, 1)
    return HTMLResponse(
        html,
        headers={"Cache-Control": "no-cache, must-revalidate"},
    )


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Liveness check — always public so healthchecks don't need a token."""
    return HealthResponse(status="ok", version=API_VERSION)


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
    if source == "Blocklist":
        note = f" · {data['note']}" if data.get("note") else ""
        return f"on your blocklist via {data.get('match', '?')}{note}"
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
    elif source == "AbstractAPI":
        sec = data.get("security") or {}
        loc = data.get("location") or {}
        parts = []
        if sec.get("is_tor"):
            parts.append("Tor")
        if sec.get("is_vpn"):
            parts.append("VPN")
        if sec.get("is_proxy"):
            parts.append("proxy")
        if sec.get("is_relay"):
            parts.append("relay")
        if sec.get("is_abuse"):
            parts.append("abuse")
        country = loc.get("country_code") or loc.get("country") or ""
        if parts:
            return ("/".join(parts) + (f" · {country}" if country else "")) or "—"
        return country or "—"
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
            via = data.get("provider")
            tail = f" · {via}" if via and via != "crt.sh" else ""
            return f"{certs} certs · {subs or 0} subdomains{tail}"
    return "—" if score == 0 else ""


def _ui_record_id(ioc: str, ioc_type: str) -> str:
    """Stable client-side ID — same IOC always renders to the same row in the UI."""
    digest = hashlib.sha1(f"{ioc_type}:{ioc}".encode()).hexdigest()[:12]
    return f"ioc_{digest}"


def _synthesize_geo(modules_raw: dict[str, Any]) -> dict[str, Any] | None:
    """Build a unified geo block for the dashboard from Shodan + IPinfo data.

    Returns ``None`` when no geo data is available (e.g. non-IP IOC, or both
    sources empty). The dashboard renders the IP CORE + NETWORK GEO panels
    only when this is populated.
    """
    shodan = (modules_raw.get("Shodan") or {}).get("data") or {}
    ipinfo = (modules_raw.get("IPinfo") or {}).get("data") or {}

    lat = shodan.get("latitude") or ipinfo.get("loc", "").split(",")[0] if ipinfo.get("loc") else shodan.get("latitude")
    lon = shodan.get("longitude") or (ipinfo.get("loc", "").split(",")[1] if ipinfo.get("loc") else None)
    try:
        lat = float(lat) if lat is not None and lat != "" else None
        lon = float(lon) if lon is not None and lon != "" else None
    except (TypeError, ValueError):
        lat = lon = None

    country = shodan.get("country_code") or ipinfo.get("country")
    if not country and not lat and not lon:
        return None

    return {
        "country": country,
        "country_name": shodan.get("country_name") or ipinfo.get("country") or "",
        "city": shodan.get("city") or ipinfo.get("city") or "",
        "region": shodan.get("region_code") or ipinfo.get("region") or "",
        "lat": lat,
        "lon": lon,
        "asn": shodan.get("asn") or ipinfo.get("org", "").split()[0] if ipinfo.get("org", "").startswith("AS") else shodan.get("asn") or "",
        "org": shodan.get("org") or shodan.get("isp") or ipinfo.get("org") or "",
        "hostnames": shodan.get("hostnames") or ([ipinfo.get("hostname")] if ipinfo.get("hostname") else []),
        "ports": _synthesis.synth_ports(modules_raw),
        "tags": shodan.get("tags") or [],
    }


def _to_ui_shape(result: dict[str, Any], prev_score: int | None) -> dict[str, Any]:
    """Add ``id``, ``agreement``, per-module ``detail``, ``enriched_at``, and ``geo`` to a raw enrichment."""
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

    shaped: dict[str, Any] = {
        "id": _ui_record_id(ioc, ioc_type),
        "ioc": ioc,
        "type": ioc_type,
        "final_score": int(result.get("final_score") or 0),
        "prev_score": prev_score if prev_score is not None else int(result.get("final_score") or 0),
        "enriched_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "agreement": output.consensus_summary(result),
        "modules": modules_ui,
        "degraded": bool(result.get("degraded")),
        "unavailable": result.get("unavailable") or {},
    }
    # Look up the case_name attached to this IOC (if any). The CaseChip
    # + Cases tab consume this. Skip when the IOC isn't in the DB yet —
    # /show / /api/ui/enrich both write the iocs row before calling
    # this reshaper, but we stay defensive.
    ioc_id = database.get_ioc_id(ioc)
    if ioc_id is not None:
        # Real "fetched" time per source (newest cache row), replacing the
        # dashboard's old hash-derived placeholder. Sources that are computed
        # locally and never persisted (TOR, Heuristics) simply have none.
        if "degraded" not in result:
            stored = database.get_last_unavailable(ioc_id)
            shaped["degraded"] = bool(stored)
            shaped["unavailable"] = stored
            shaped["agreement"]["sources_unavailable"] = len(stored)
        listed = userlists.match(ioc, ioc_type)
        shaped["listed"] = (
            {"id": listed["id"], "list": listed["list"], "pattern": listed["pattern"], "note": listed["note"]}
            if listed else None
        )
        shaped["verdict"] = database.get_verdict(ioc_id)
        shaped["notes"] = database.list_notes(ioc_id)
        shaped["watch"] = database.watch_get(ioc_id)
        fetched = database.get_latest_fetch_times(ioc_id)
        key_by_display = {display: key for key, display in _CACHED_SOURCES}
        for source, entry in modules_ui.items():
            ts = fetched.get(key_by_display.get(source, ""))
            if ts:
                entry["fetched_at"] = ts.replace(" ", "T")[:19] + "Z" if "T" not in ts else ts[:19] + "Z"
        tags = database.get_tags_for_ioc(ioc_id)
        case_name = next((t["case_name"] for t in tags if t.get("case_name")), None)
        if case_name:
            shaped["case"] = case_name
    if ioc_type == "ip":
        geo = _synthesize_geo(modules_raw)
        if geo is not None:
            shaped["geo"] = geo
        anon = _synthesis.synth_anon(modules_raw)
        if anon is not None:
            shaped["anon"] = anon
        core = _synthesis.synth_core_ip(modules_raw)
        if core is not None:
            shaped["core"] = core
    elif ioc_type == "domain":
        core = _synthesis.synth_core_domain(modules_raw)
        if core is not None:
            shaped["core"] = core
    elif ioc_type == "hash":
        core = _synthesis.synth_core_hash(modules_raw)
        if core is not None:
            shaped["core"] = core
    elif ioc_type == "cve":
        core = _synthesis.synth_core_cve(modules_raw)
        if core is not None:
            shaped["core"] = core
    return shaped


# Canonical source_key → display_name mapping. Mirrors the order in
# ``core.enrich.enrich_ioc_async`` so every source that writes to SQLite
# can be read back by display name. Tor is intentionally absent — it's
# evaluated against a local exit-node list, never persisted as an
# enrichment row. Used by ``/show`` and ``/api/ui/recent`` to reconstruct
# modules dicts straight from the cache without re-fetching.
_CACHED_SOURCES: tuple[tuple[str, str], ...] = (
    ("virustotal",    "VirusTotal"),
    ("abuseipdb",     "AbuseIPDB"),
    ("shodan",        "Shodan"),
    ("ipqs",          "IPQS"),
    ("ipinfo",        "IPinfo"),
    ("rdns",          "rDNS"),
    ("censys",        "Censys"),
    ("abstract",      "AbstractAPI"),
    ("greynoise",     "GreyNoise"),
    ("urlhaus",       "URLhaus"),
    ("threatfox",     "ThreatFox"),
    ("otx",           "OTX"),
    ("urlscan",       "URLscan"),
    ("pulsedive",     "Pulsedive"),
    ("malwarebazaar", "MalwareBazaar"),
    ("feodo",         "Feodo"),
    ("sslbl",         "SSLBL"),
    ("crtsh",         "crt.sh"),
    ("whois",         "WHOIS"),
    ("asn_bgpview",   "ASN"),
    ("nvd",           "NVD"),
    ("epss",          "EPSS"),
    ("kev",           "KEV"),
)


def _build_modules_from_cache(ioc_id: int) -> tuple[dict[str, Any], list[tuple[str, int]]]:
    """Reconstruct a ``modules`` dict + per-source scores from SQLite rows.

    Shared by ``/show`` and ``/api/ui/recent``. Returns the same shape the
    orchestrator emits so downstream reshapers (``_to_ui_shape``) work
    unchanged. Rows with un-parseable JSON degrade silently to an empty
    data dict — the score is still kept so the composite stays honest.
    """
    import json as _json
    modules: dict[str, dict[str, Any]] = {}
    scores: list[tuple[str, int]] = []
    for source_key, display_name in _CACHED_SOURCES:
        row = database.get_latest_enrichment(ioc_id, source_key)
        if row is None:
            continue
        try:
            data = _json.loads(row["data"])
        except (TypeError, ValueError):
            data = {}
        modules[display_name] = {"score": row["score"], "data": data}
        scores.append((display_name, row["score"] or 0))  # named → real weight, not the 0.5 default
    # The user's blocklist is checked live, not read from cache: an entry added
    # or removed a moment ago must show on already-cached indicators.
    if modules:
        ident = database.get_ioc_identity(ioc_id)
        block = userlists.block_hit(ident[0], ident[1]) if ident else None
        if block is not None:
            modules[userlists.BLOCK_SOURCE] = {"score": 100, "data": block}
            scores.append((userlists.BLOCK_SOURCE, 100))
    return modules, scores


_SOURCE_REGISTRY: list[dict[str, Any]] = [
    # (id, env var or None for no-auth, IOC types it covers)
    {"id": "VirusTotal",    "env": "VT_API_KEY",                "types": ["ip", "domain", "url", "hash"]},
    {"id": "AbuseIPDB",     "env": "ABUSEIPDB_API_KEY",         "types": ["ip"]},
    {"id": "Shodan",        "env": "SHODAN_API_KEY",            "types": ["ip"]},
    {"id": "IPQS",          "env": "IPQS_API_KEY",              "types": ["ip"]},
    {"id": "IPinfo",        "env": "IPINFO_API_KEY",            "types": ["ip"],            "anonymous_ok": True},
    {"id": "Censys",        "env": "CENSYS_API_KEY",            "types": ["ip"]},
    {"id": "GreyNoise",     "env": "GREYNOISE_API_KEY",         "types": ["ip"]},
    {"id": "OTX",           "env": "OTX_API_KEY",               "types": ["ip", "domain", "url", "hash"]},
    {"id": "URLscan",       "env": "URLSCAN_API_KEY",           "types": ["ip", "domain", "url"]},
    {"id": "Pulsedive",     "env": "PULSEDIVE_API_KEY",         "types": ["ip", "domain", "url"], "anonymous_ok": True},
    {"id": "AbstractAPI",   "env": "ABSTRACT_IP_INTELLIGENCE",  "types": ["ip"]},
    {"id": "URLhaus",       "env": "ABUSECH_AUTH_KEY",                        "types": ["url", "domain", "ip"]},
    {"id": "ThreatFox",     "env": "ABUSECH_AUTH_KEY",                        "types": ["ip", "domain", "url", "hash"]},
    {"id": "MalwareBazaar", "env": "ABUSECH_AUTH_KEY",                        "types": ["hash"]},
    {"id": "Feodo",         "env": None,                        "types": ["ip"]},
    {"id": "SSLBL",         "env": None,                        "types": ["hash"]},
    {"id": "WHOIS",         "env": None,                        "types": ["domain"]},
    {"id": "crt.sh",        "env": "CTLOGS_API_KEY",            "types": ["domain"],        "anonymous_ok": True},
    {"id": "Tor",           "env": None,                        "types": ["ip"]},
    {"id": "NVD",           "env": "NVD_API_KEY",               "types": ["cve"],           "anonymous_ok": True},
    {"id": "EPSS",          "env": None,                        "types": ["cve"]},
    {"id": "KEV",           "env": None,                        "types": ["cve"]},
    {"id": "ASN",           "env": None,                        "types": ["asn"]},
    {"id": "Heuristics",    "env": None,                        "types": ["domain"], "local": True},
]


@app.get("/api/ui/usage", dependencies=[Depends(require_token)])
def ui_usage() -> dict[str, Any]:
    """Requests sent to each source by this install: today, 7 days, this month.

    A local tally (``core/usage.py``), not the provider's own counter. Where
    a quota is known or set through ``SHADOWSCOPE_QUOTAS`` the row carries
    ``quota: {limit, period, used, left, pct, assumed}``.
    """
    from ..core import usage as usage_mod

    database.init_db()
    return usage_mod.summary()


@app.get("/api/ui/sources", dependencies=[Depends(require_token)])
def ui_sources() -> dict[str, Any]:
    """Real-time source status — drives the dashboard's OPS / Sources panel.

    Reports per-source: key state (present / missing / anonymous / local /
    none-required), supported IOC types, and human-readable status that
    the UI colour-codes.

    Status semantics:
      ``ok``        — key present (or none required) and module installed
      ``anonymous`` — works without a key but a key would unlock more
      ``no_key``    — key required but not present in env
      ``local``     — runs locally, no upstream HTTP at all
    """
    sources: list[dict[str, Any]] = []
    for src in _SOURCE_REGISTRY:
        env_name = src.get("env")
        if src.get("local"):
            status = "local"
            key = "local"
        elif env_name is None:
            status = "anonymous"
            key = "none-required"
        elif os.getenv(env_name, "").strip():
            status = "ok"
            key = "present"
        elif src.get("anonymous_ok"):
            status = "anonymous"
            key = "anonymous"
        else:
            status = "no_key"
            key = "missing"

        sources.append({
            "id": src["id"],
            "status": status,
            "key": key,
            "env": env_name,
            "ioc_types": src["types"],
        })

    return {
        "sources": sources,
        "total": len(sources),
        "ok": sum(1 for s in sources if s["status"] in ("ok", "local")),
        "anonymous": sum(1 for s in sources if s["status"] == "anonymous"),
        "no_key": sum(1 for s in sources if s["status"] == "no_key"),
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


@app.get("/api/ui/enrich/stream", dependencies=[Depends(require_token)])
async def ui_enrich_stream(
    ioc: str = Query(..., description="IOC value (auto-detected, refanged)"),
    defang: bool = Query(False, description="Defang the ioc field on the final event"),
    no_cache: bool = Query(False, description="Bypass the SQLite cache"),
) -> StreamingResponse:
    """Stream per-source enrichment events as Server-Sent Events.

    Mirrors ``GET /api/ui/enrich`` but yields ``module`` events as each
    source resolves so the dashboard can render progressively instead of
    waiting for the slowest source. Final event carries the same UI-shaped
    payload the non-streaming endpoint returns.

    Events:

    * ``event: meta``  — ``{ioc, type, allowlisted, pending}``
    * ``event: module``— ``{name, entry: {score, data}}``
    * ``event: final`` — full ``_to_ui_shape`` payload (same as ``/api/ui/enrich``)
    * ``event: error`` — ``{detail}`` on unrecoverable error

    Headers include ``X-Accel-Buffering: no`` so nginx-style proxies don't
    coalesce events into a single chunk.
    """
    import json as _json

    refanged = defang_mod.refang(ioc)
    ioc_type = parser.detect_type(refanged)
    if ioc_type == "unknown":
        raise HTTPException(
            status_code=400,
            detail=f"Unable to detect IOC type for value: {ioc!r}.",
        )

    # Snapshot prev_score before the stream starts so the final event can
    # surface the delta the same way GET /api/ui/enrich does.
    database.init_db()
    prev_score: int | None = None
    ioc_id_prev = database.get_ioc_id(refanged)
    if ioc_id_prev is not None:
        conn = database.get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT last_score FROM iocs WHERE id = ?", (ioc_id_prev,))
        row = cur.fetchone()
        conn.close()
        if row and row[0] is not None:
            prev_score = int(row[0])

    async def _gen():
        try:
            agen = enrich.enrich_ioc_stream(refanged, ioc_type, no_cache=no_cache)
            async for ev in agen:
                kind = ev.get("event")
                if kind == "final":
                    result = ev["result"]
                    if defang:
                        result = _apply_output_defang(result, True)
                    shaped = _to_ui_shape(result, prev_score)
                    payload = _json.dumps(shaped, default=str)
                    yield f"event: final\ndata: {payload}\n\n"
                else:
                    payload = _json.dumps(ev, default=str)
                    yield f"event: {kind}\ndata: {payload}\n\n"
        except asyncio.CancelledError:
            # Client disconnected; let the generator clean up.
            raise
        except Exception as exc:  # pragma: no cover — defensive surface
            err = _json.dumps({"detail": str(exc)})
            yield f"event: error\ndata: {err}\n\n"

    return StreamingResponse(
        _gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


_UI_EXTRACT_MAX = 200
_UI_EXTRACT_TYPES = ("ip", "domain", "url", "hash", "cve", "asn")


@app.post("/api/ui/extract", dependencies=[Depends(require_token)])
async def ui_extract(payload: UiExtractRequest) -> dict[str, Any]:
    """Pull indicators out of pasted text **without enriching them**.

    The Batch tab calls this once, then enriches each indicator through
    ``/api/ui/enrich`` so it can show per-item progress and stop on demand.
    Extraction runs off the event loop; the body is capped at 256 KB and the
    result at 200 indicators. Each line is also tried as a single indicator,
    which is how CVE ids and ``AS12345`` (not covered by the free-text
    extractor) get in.
    """
    text = payload.text or ""
    found = await asyncio.to_thread(extractor.extract_iocs, text)
    seen: set[str] = set()
    iocs: list[dict[str, str]] = []
    skipped = 0

    def add(raw: str) -> None:
        nonlocal skipped
        ioc_type = parser.detect_type(raw)
        if ioc_type not in _UI_EXTRACT_TYPES:
            skipped += 1
            return
        value = parser.normalize_value(raw, ioc_type)
        key = value.lower()
        if key not in seen:
            seen.add(key)
            iocs.append({"value": value, "type": ioc_type})

    for line in text.splitlines():
        token = line.strip().strip(",;")
        if token and not token.startswith("#") and " " not in token:
            add(token)
    for bucket in found.values():
        for raw in bucket:
            add(raw)
    return {
        "iocs": iocs[:_UI_EXTRACT_MAX],
        "count": min(len(iocs), _UI_EXTRACT_MAX),
        "truncated": max(0, len(iocs) - _UI_EXTRACT_MAX),
        "skipped": skipped,
    }


@app.get("/api/ui/recent", dependencies=[Depends(require_token)])
def ui_recent(
    limit: int = Query(8, ge=1, le=500, description="Max rows to return"),
) -> list[dict[str, Any]]:
    """Return the newest cached IOCs reshaped for the brutalist dashboard.

    Reads ``iocs`` ordered by ``last_seen`` desc, rebuilds each module
    dict from cache (no API calls, no API spend), and runs the same UI
    reshape ``/api/ui/enrich`` produces. Empty list when the workspace
    has never been used — the dashboard renders an empty-state prompt
    instead of demo fixtures.

    ``enriched_at`` is the IOC's ``last_seen`` timestamp so the "enriched
    Xm ago" relative-time chip reflects real cache age, not page load.
    """
    from ..core import score as score_mod

    database.init_db()
    rows = database.get_recent_iocs(limit)
    out: list[dict[str, Any]] = []
    for row in rows:
        modules, scores = _build_modules_from_cache(row["id"])
        if not modules:
            # Defensive: iocs row exists but every enrichment was pruned.
            # Skip rather than emit a record with no signal — the strip
            # pill would render with empty modules and break panels.
            continue
        result = {
            "ioc": row["value"],
            "type": row["type"],
            "modules": modules,
            "final_score": score_mod.calculate_final_risk(scores),
        }
        last_score = row.get("last_score")
        prev_score = int(last_score) if last_score is not None else None
        shaped = _to_ui_shape(result, prev_score)
        last_seen = row.get("last_seen")
        if last_seen:
            # Persisted as "YYYY-MM-DD HH:MM:SS[.ffffff]" — normalise to
            # ISO-8601 with 'T' and a trailing 'Z' so the dashboard's
            # Relative component parses it the same way as live records.
            iso = str(last_seen).replace(" ", "T")
            if "." in iso:
                iso = iso.split(".", 1)[0]
            shaped["enriched_at"] = iso + "Z"
        out.append(shaped)
    return out


@app.get("/api/ui/pivot", dependencies=[Depends(require_token)])
def ui_pivot(
    kind: str = Query(..., description="Pivot kind: tag, malware, family, registrar, ioc, any"),
    value: str = Query(..., min_length=1, description="Value to search for"),
    limit: int = Query(16, ge=1, le=50, description="Max related IOCs to return"),
    exclude: str | None = Query(None, description="IOC value to exclude (typically the active one)"),
) -> list[dict[str, Any]]:
    """Return cached IOCs whose enrichments mention ``value``.

    Backs the PivotPanel's "RELATED" groups — same brutalist UI shape
    as ``/api/ui/recent``. Read-only, cache-only, no API spend.

    The search is intentionally cheap: a case-insensitive substring
    scan over the persisted JSON text. For ``kind`` values that we
    know are stored as quoted string literals (``tag``, ``malware``,
    ``family``, ``registrar``), the needle is wrapped in quotes to
    avoid substring false positives ("emotet" won't match "emotetable").
    Empty result list when nothing matches.
    """
    allowed = {"tag", "malware", "family", "registrar", "ioc", "any"}
    if kind not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid kind {kind!r}. Allowed: {sorted(allowed)}",
        )

    from ..core import score as score_mod

    database.init_db()
    rows = database.find_iocs_by_field(
        value, kind=kind, limit=limit, exclude_value=exclude
    )
    out: list[dict[str, Any]] = []
    for row in rows:
        modules, scores = _build_modules_from_cache(row["id"])
        if not modules:
            continue
        result = {
            "ioc": row["value"],
            "type": row["type"],
            "modules": modules,
            "final_score": score_mod.calculate_final_risk(scores),
        }
        last_score = row.get("last_score")
        prev_score = int(last_score) if last_score is not None else None
        shaped = _to_ui_shape(result, prev_score)
        last_seen = row.get("last_seen")
        if last_seen:
            iso = str(last_seen).replace(" ", "T")
            if "." in iso:
                iso = iso.split(".", 1)[0]
            shaped["enriched_at"] = iso + "Z"
        out.append(shaped)
    return out


# Heartbeat cadence for ``/api/ui/events``. Exposed as a module-level
# constant + env override so tests can shorten it without monkeypatching
# private state. EventSource clients and most reverse proxies idle a
# connection out around 30–60 s, so 25 s is comfortably inside that.
_SSE_HEARTBEAT_S: float = float(os.getenv("SHADOWSCOPE_SSE_HEARTBEAT_S", "25.0"))


async def _events_stream(heartbeat_s: float | None = None):
    """Async generator yielding SSE frames for ``/api/ui/events``.

    Extracted so unit tests can drive the loop directly without going
    through FastAPI's TestClient — httpx's ASGI transport buffers
    streaming bodies, which would make a heartbeat assertion impossible
    end-to-end.

    Yields the greeting frame, then either a real event (whenever one
    lands on the per-subscriber queue) or a ``: heartbeat`` SSE comment
    line whenever the bus stays silent for longer than ``heartbeat_s``
    (defaults to ``_SSE_HEARTBEAT_S``). Cancellation is propagated; the
    ``finally`` ensures the subscriber is released on every exit path.
    """
    import json as _json

    timeout = _SSE_HEARTBEAT_S if heartbeat_s is None else heartbeat_s
    # Register *before* yielding the greeting so any event published
    # immediately after a client connects can't slip in unobserved
    # while we're between frames. The greeting counts ourselves in
    # ``subs``.
    queue, release = eventbus.open_subscription()
    try:
        # Greeting frame so the client knows it's connected before the
        # first real event arrives.
        yield (
            f": shadowscope-events v1\n"
            f"event: hello\ndata: {_json.dumps({'subs': eventbus.subscriber_count()})}\n\n"
        )
        # Drive the subscription loop directly so we can emit a comment
        # keepalive whenever the bus is idle for longer than the heartbeat
        # interval. The previous implementation only checked the elapsed-
        # time gate *after* receiving an event, so a fully silent bus
        # produced zero heartbeats and proxies eventually closed the
        # connection.
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=timeout)
            except asyncio.TimeoutError:
                # SSE comment line — keepalive without a real event.
                yield ": heartbeat\n\n"
                continue
            yield f"event: {event['type']}\ndata: {_json.dumps(event)}\n\n"
    except asyncio.CancelledError:
        # Client disconnected — let the cancellation propagate after
        # cleanup so Starlette tears the response down cleanly.
        raise
    finally:
        release()


@app.get("/api/ui/events")
async def ui_events(token: str | None = Query(None)) -> StreamingResponse:
    """Server-Sent Events stream of enrichment-pipeline activity.

    Replaces the dashboard's 8 s ``/api/ui/recent`` poll for the Watch
    tab + AlertTicker. Each enrichment writes a ``score`` event with
    ``{"ioc": str, "score": int}`` payload. Heartbeats every 25 s
    (``SHADOWSCOPE_SSE_HEARTBEAT_S`` override) keep proxies from idling
    the connection out.

    Auth: EventSource can't set custom headers, so the bearer token is
    accepted via the ``?token=`` query param. When
    ``SHADOWSCOPE_API_TOKEN`` is set and the query token is missing or
    wrong → ``401``. When the env var is unset, the route is open
    (matches the "homelab localhost convenience" mode of
    :func:`require_token`). The events carry no secrets, but gating the
    stream prevents an anonymous consumer from observing enrichment
    activity timing / IOC values in real time.
    """
    expected = os.getenv("SHADOWSCOPE_API_TOKEN")
    if expected and token != expected:
        raise HTTPException(status_code=401, detail="Missing or invalid token")

    return StreamingResponse(
        _events_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",   # disable buffering behind nginx
            "Connection": "keep-alive",
        },
    )


@app.get("/api/ui/score_history/{value}", dependencies=[Depends(require_token)])
def ui_score_history(
    value: str,
    limit: int = Query(200, ge=1, le=2000, description="Max snapshots to return"),
) -> dict[str, Any]:
    """Return chronological score snapshots for an IOC.

    Snapshots are written by ``update_last_score`` every time the
    composite is recomputed (enrichment, watch re-enrich). Used by the
    Watch tab to render a real score-over-time line graph instead of
    the previous one-step delta against ``last_score``.

    404 when the IOC is not in the cache; ``[]`` history when it exists
    but predates the snapshot column (still rare — every enrich after
    the schema migration adds a row).
    """
    database.init_db()
    refanged = defang_mod.refang(value)
    ioc_id = database.get_ioc_id(refanged)
    if ioc_id is None:
        raise HTTPException(status_code=404, detail=f"IOC not found: {value}")
    history = database.get_score_history(ioc_id, limit=int(limit))
    points = []
    for row in history:
        ts = row.get("recorded_at")
        iso = str(ts).replace(" ", "T") if ts else None
        if iso and "." in iso:
            iso = iso.split(".", 1)[0]
        points.append({
            "score": int(row["score"]),
            "score_version": row.get("score_version"),  # None == pre-v2 (v1 mean)
            "recorded_at": (iso + "Z") if iso else None,
        })
    return {"ioc": refanged, "count": len(points), "points": points}


@app.get("/api/ui/cases", dependencies=[Depends(require_token)])
def ui_cases() -> list[dict[str, Any]]:
    """Return every case in the workspace with derived severity + opened.

    Severity = max ``last_score`` across the case's IOC members. Opened
    = earliest ``ioc_tags.created`` for the case_name. Derived at query
    time so the view stays in sync with the latest enrichments without
    a maintenance job. The ``iocs`` field carries the member values
    (just strings) so the dashboard can resolve them on demand via
    ``/show`` or ``/api/ui/enrich``.
    """
    database.init_db()
    cases = database.list_cases_with_summary()
    meta = database.get_case_meta()
    out: list[dict[str, Any]] = []
    for case in cases:
        name = case["case_name"]
        members = database.list_iocs_for_case(name)
        opened = case.get("opened_at")
        if opened:
            opened = str(opened).split(" ", 1)[0]  # date only
        info = meta.pop(name, None) or {}
        out.append({
            "id": name,
            "label": name,
            "iocs": [m["value"] for m in members],
            "ioc_count": int(case["ioc_count"]),
            "severity": int(case["severity"]),
            "opened": opened,
            "status": info.get("status", "open"),
            "description": info.get("description", ""),
        })
    # Cases created from the Cases tab that have no members yet.
    for name, info in meta.items():
        out.append({
            "id": name, "label": name, "iocs": [], "ioc_count": 0, "severity": 0,
            "opened": (info.get("created") or "").split(" ", 1)[0] or None,
            "status": info.get("status", "open"), "description": info.get("description", ""),
        })
    out.sort(key=lambda c: (c["status"] == "closed", -c["severity"], c["label"].lower()))
    return out


class CaseAssignRequest(BaseModel):
    """Body for `PATCH /api/ui/iocs/{value}/case`."""

    case: str | None = Field(
        None,
        description="Case label to assign. Empty / null detaches from any case.",
    )


@app.patch("/api/ui/iocs/{value}/case", dependencies=[Depends(require_token)])
def ui_set_ioc_case(value: str, req: CaseAssignRequest) -> dict[str, Any]:
    """Assign an IOC to a case (or detach it when ``case`` is empty).

    Defangs the path value first so the dashboard can pass either form.
    404 when the IOC isn't in the cache — we don't auto-create an empty
    iocs row, the caller should enrich first.
    """
    refanged = defang_mod.refang(value)
    database.init_db()
    ok = database.set_ioc_case(refanged, req.case)
    if not ok:
        raise HTTPException(
            status_code=404,
            detail=f"IOC {refanged!r} not found in cache — enrich first",
        )
    return {"ioc": refanged, "case": (req.case or None)}


@app.delete("/api/ui/cases/{case}", dependencies=[Depends(require_token)])
def ui_delete_case(case: str) -> dict[str, Any]:
    """Detach every IOC from ``case`` and remove its tag rows.

    The underlying IOCs and their enrichments are preserved — this only
    nukes the case relationship. Idempotent: returns ``removed: 0`` for
    an unknown case rather than 404 so the UI's delete-on-empty path
    stays simple.
    """
    database.init_db()
    removed = database.remove_case(case)
    database.delete_case_meta(case)
    return {"case": case, "removed": int(removed)}


# ---------------------------------------------------------------------------
# Analyst workflow: case management, manual verdict, notes, watchlist
# ---------------------------------------------------------------------------


def _require_ioc_id(raw: str) -> tuple[int, str]:
    value = defang_mod.refang((raw or "").strip())
    ioc_type = parser.detect_type(value)
    value = parser.normalize_value(value, ioc_type) if ioc_type != "unknown" else value
    database.init_db()
    ioc_id = database.get_ioc_id(value)
    if ioc_id is None:
        raise HTTPException(status_code=404, detail=f"IOC {value!r} not found in cache — enrich first")
    return ioc_id, value


@app.get("/api/ui/related", dependencies=[Depends(require_token)])
def ui_related(
    ioc: str = Query(..., min_length=1, description="Cached IOC to find relatives of"),
    limit: int = Query(12, ge=1, le=50, description="Max items per group"),
) -> dict[str, Any]:
    """Indicators related to one cached IOC, grouped by what they share.

    Cache-only — never calls a provider. Items carry ``cached``: true for
    indicators already enriched (with their last score), false for hosts
    that are only *named* in this IOC's data and could be enriched next.
    """
    from ..core import related as related_mod

    ioc_id, value = _require_ioc_id(ioc)
    ioc_type = parser.detect_type(value)
    return {
        "ioc": value,
        "type": ioc_type,
        "groups": related_mod.related_for(ioc_id, value, ioc_type, limit=limit),
    }


@app.get("/api/ui/timeline", dependencies=[Depends(require_token)])
def ui_timeline(
    ioc: str = Query(..., min_length=1, description="Cached IOC to build the timeline for"),
) -> dict[str, Any]:
    """Every dated fact about one cached IOC, newest first. Cache-only.

    Mixes what sources reported (registration, sightings, listings) with
    what happened here (score changes, verdicts, notes, cases, watchlist).
    """
    from ..core import timeline as timeline_mod

    ioc_id, value = _require_ioc_id(ioc)
    return {"ioc": value, "events": timeline_mod.timeline_for(ioc_id)}


_SEARCH_VERDICTS = {"any", "none", *database.VERDICTS}
# Keys a saved filter may carry — the Search tab's own state, nothing else.
_FILTER_KEYS = ("q", "type", "min_score", "max_score", "verdict", "case",
                "watched", "has_notes", "since_days", "deep", "sort")


@app.get("/api/ui/search", dependencies=[Depends(require_token)])
def ui_search(
    q: str | None = Query(None, max_length=500, description="Free text; every word must match somewhere"),
    type: str | None = Query(None, max_length=80, description="Comma-separated IOC types"),
    min_score: int | None = Query(None, ge=0, le=100),
    max_score: int | None = Query(None, ge=0, le=100),
    verdict: str | None = Query(None, description="A verdict, 'any' or 'none'"),
    case: str | None = Query(None, max_length=80, description="A case name, 'any' or 'none'"),
    watched: bool | None = Query(None),
    has_notes: bool | None = Query(None),
    since_days: int | None = Query(None, ge=1, le=3650, description="Seen within the last N days"),
    deep: bool = Query(True, description="Also scan the raw text of cached source answers"),
    sort: str = Query("score"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    """Search everything stored locally. Cache-only — never calls a provider."""
    from ..core import search as search_mod

    types = [t.strip().lower() for t in (type or "").split(",") if t.strip()]
    bad = [t for t in types if t not in search_mod.TYPES]
    if bad:
        raise HTTPException(status_code=422, detail=f"Unknown type(s): {', '.join(bad)}")
    if verdict is not None and verdict not in _SEARCH_VERDICTS:
        raise HTTPException(status_code=422, detail=f"verdict must be one of {sorted(_SEARCH_VERDICTS)}")
    if sort not in search_mod.SORTS:
        raise HTTPException(status_code=422, detail=f"sort must be one of {sorted(search_mod.SORTS)}")
    database.init_db()
    return search_mod.search(
        q, types=types, min_score=min_score, max_score=max_score, verdict=verdict, case=case,
        watched=watched, has_notes=has_notes, since_days=since_days, deep=deep,
        sort=sort, limit=limit, offset=offset,
    )


class FilterSaveRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=60)
    params: dict[str, Any] = Field(default_factory=dict)


@app.get("/api/ui/filters", dependencies=[Depends(require_token)])
def ui_filters() -> list[dict[str, Any]]:
    database.init_db()
    return database.filter_list()


@app.post("/api/ui/filters", dependencies=[Depends(require_token)])
def ui_filter_save(req: FilterSaveRequest) -> dict[str, Any]:
    name = req.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Filter name is empty")
    params: dict[str, Any] = {}
    for key in _FILTER_KEYS:
        value = req.params.get(key)
        if isinstance(value, bool | int) or (isinstance(value, str) and 0 < len(value) <= 500):
            params[key] = value
    database.init_db()
    database.filter_save(name, params)
    return {"name": name, "params": params}


@app.delete("/api/ui/filters/{name}", dependencies=[Depends(require_token)])
def ui_filter_delete(name: str) -> dict[str, int]:
    database.init_db()
    return {"removed": database.filter_delete(name)}


@app.get("/api/ui/report", dependencies=[Depends(require_token)])
def ui_report(
    ioc: str = Query(..., min_length=1, description="Cached IOC to report on"),
    format: str = Query("md", pattern="^(md|html)$", description="md, or html for a printable page"),
) -> dict[str, str]:
    """A shareable report on one cached IOC. Cache-only; indicators defanged.

    ``html`` is a self-contained page for the browser's Print -> Save as PDF.
    """
    from ..core import report as report_mod

    ioc_id, value = _require_ioc_id(ioc)
    title, blocks = report_mod.ioc_report(ioc_id, value, parser.detect_type(value))
    return {"format": format, "filename": report_mod.filename(value, format),
            "content": report_mod.render(title, blocks, format)}


@app.get("/api/ui/cases/{case}/report", dependencies=[Depends(require_token)])
def ui_case_report(
    case: str,
    format: str = Query("md", pattern="^(md|html)$"),
) -> dict[str, str]:
    """A shareable report on a case: summary table plus a section per member."""
    from ..core import report as report_mod

    database.init_db()
    built = report_mod.case_report(case)
    if built is None:
        raise HTTPException(status_code=404, detail=f"no case named {case!r}")
    title, blocks = built
    return {"format": format, "filename": report_mod.filename("case-" + case, format),
            "content": report_mod.render(title, blocks, format)}


_RESTORE_MAX_BYTES = 1024 * 1024 * 1024


def _scratch_path(tag: str) -> str:
    """A temp file next to the live database (same volume, cleaned by the caller)."""
    import uuid

    return f"{database.DB_PATH}.{tag}-{uuid.uuid4().hex[:12]}.tmp"


@app.get("/api/ui/backup", dependencies=[Depends(require_token)])
def ui_backup() -> Response:
    """Download a consistent copy of the local database.

    Holds cached answers, score history, verdicts, notes, cases, watchlist,
    saved filters and block/allow lists. API keys (``.env``) are not in it.
    """
    from ..core import backup as backup_mod

    tmp = _scratch_path("backup")
    try:
        backup_mod.snapshot(tmp)
        payload = Path(tmp).read_bytes()
    finally:
        Path(tmp).unlink(missing_ok=True)
    name = f"shadowscope-backup-{datetime.now().strftime('%Y%m%d-%H%M')}.db"
    return Response(content=payload, media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.post("/api/ui/restore", dependencies=[Depends(require_token)])
async def ui_restore(
    request: Request,
    dry_run: bool = Query(False, description="Only inspect the upload; change nothing"),
    x_confirm: str | None = Header(None),
) -> dict[str, Any]:
    """Replace the local database with an uploaded backup (raw request body).

    ``dry_run=true`` validates the file and reports what it holds next to
    what is here now. The real run needs the header ``X-Confirm: restore``;
    the current database is saved alongside as ``*.pre-restore-<time>.bak``
    before anything is replaced.
    """
    from ..core import backup as backup_mod

    if not dry_run and x_confirm != "restore":
        raise HTTPException(status_code=400, detail="send the header 'X-Confirm: restore' to replace the database")
    tmp = _scratch_path("restore")
    size = 0
    try:
        with open(tmp, "wb") as fh:
            async for chunk in request.stream():
                size += len(chunk)
                if size > _RESTORE_MAX_BYTES:
                    raise HTTPException(status_code=413, detail="backup file too large")
                fh.write(chunk)
        if size == 0:
            raise HTTPException(status_code=422, detail="empty upload")
        try:
            if dry_run:
                info = await asyncio.to_thread(backup_mod.inspect, tmp)
                return {"dry_run": True, "backup": info, "current": backup_mod.current_summary()}
            return await asyncio.to_thread(backup_mod.restore, tmp)
        except backup_mod.BackupError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    finally:
        Path(tmp).unlink(missing_ok=True)


class ListEntryRequest(BaseModel):
    list: str = Field(..., pattern="^(block|allow)$")
    pattern: str = Field(..., min_length=1, max_length=2100, description="IP, CIDR, domain, URL, hash, CVE or ASN")
    note: str | None = Field(None, max_length=300)


@app.get("/api/ui/lists", dependencies=[Depends(require_token)])
def ui_lists() -> list[dict[str, Any]]:
    """Every entry on the user's block and allow lists, newest first."""
    database.init_db()
    return userlists.entries()


@app.post("/api/ui/lists", dependencies=[Depends(require_token)])
def ui_list_add(req: ListEntryRequest) -> dict[str, Any]:
    """Add an entry. A domain also covers its subdomains; CIDRs cover ranges."""
    database.init_db()
    try:
        return userlists.add(req.list, req.pattern, req.note)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.delete("/api/ui/lists/{entry_id}", dependencies=[Depends(require_token)])
def ui_list_remove(entry_id: int) -> dict[str, int]:
    database.init_db()
    return {"removed": userlists.remove(entry_id)}


class ImportPreviewRequest(BaseModel):
    text: str = Field(..., max_length=2_000_000, description="STIX JSON, CSV or free text")


class ImportApplyRequest(BaseModel):
    rows: list[dict[str, Any]] = Field(..., max_length=2000)
    case: str | None = Field(None, max_length=80, description="Case for rows that carry none")


@app.post("/api/ui/import/preview", dependencies=[Depends(require_token)])
async def ui_import_preview(req: ImportPreviewRequest) -> dict[str, Any]:
    """Parse an import file and show what it holds. Writes nothing."""
    from ..core import importer

    return await asyncio.to_thread(importer.parse, req.text)


@app.post("/api/ui/import/apply", dependencies=[Depends(require_token)])
async def ui_import_apply(req: ImportApplyRequest) -> dict[str, int]:
    """Register previewed rows (with case / tags / note / verdict) in the cache.

    Never calls a provider — imported indicators are stored un-enriched.
    """
    from ..core import importer

    return await asyncio.to_thread(importer.apply, req.rows, case=req.case)


class CaseCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)
    description: str | None = Field(None, max_length=2000)


class CaseUpdateRequest(BaseModel):
    status: str | None = Field(None, pattern="^(open|closed)$")
    description: str | None = Field(None, max_length=2000)
    rename: str | None = Field(None, min_length=1, max_length=80)


@app.post("/api/ui/cases", dependencies=[Depends(require_token)])
def ui_create_case(req: CaseCreateRequest) -> dict[str, Any]:
    """Create an (empty) case so it can be filled from the Enrich tab."""
    database.init_db()
    name = req.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="case name is empty")
    database.upsert_case(name, req.description)
    return {"case": name, "status": "open"}


@app.patch("/api/ui/cases/{case}", dependencies=[Depends(require_token)])
def ui_update_case(case: str, req: CaseUpdateRequest) -> dict[str, Any]:
    """Close/reopen, describe or rename a case."""
    database.init_db()
    name = case
    database.upsert_case(name, req.description)
    if req.status:
        database.set_case_status(name, req.status)
    if req.rename and req.rename.strip() and req.rename.strip() != name:
        new = req.rename.strip()
        if not database.rename_case(name, new):
            raise HTTPException(status_code=409, detail=f"a case named {new!r} already exists")
        name = new
    info = database.get_case_meta().get(name, {})
    return {"case": name, **info}


@app.get("/api/ui/cases/{case}/export", dependencies=[Depends(require_token)])
def ui_export_case(case: str) -> dict[str, Any]:
    """Markdown write-up of a case: members, scores, analyst verdicts and notes."""
    database.init_db()
    info = database.get_case_meta().get(case, {})
    members = database.list_iocs_for_case(case)
    if not members and not info:
        raise HTTPException(status_code=404, detail=f"no case named {case!r}")
    lines = [
        f"# Case: {case}",
        "",
        f"- Status: **{info.get('status', 'open')}**",
        f"- Indicators: {len(members)}",
        f"- Exported: {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
    ]
    if info.get("description"):
        lines += ["", info["description"]]
    lines += ["", "| Indicator | Type | Score | Tier | Analyst verdict |", "|---|---|---|---|---|"]
    notes_block: list[str] = []
    for m in members:
        ioc_id = database.get_ioc_id(m["value"])
        score_val = m.get("last_score")
        verdict = database.get_verdict(ioc_id) if ioc_id else None
        tier = output._risk_tier(score_val) if score_val is not None else "—"
        shown = defang_mod.defang(m["value"])
        lines.append(
            f"| `{shown}` | {m.get('type', '')} | {score_val if score_val is not None else '—'} | {tier} | "
            f"{(verdict or {}).get('verdict', '—')} |"
        )
        notes = database.list_notes(ioc_id) if ioc_id else []
        if notes or (verdict and verdict.get("note")):
            notes_block.append(f"### `{shown}`")
            if verdict and verdict.get("note"):
                notes_block.append(f"- verdict note: {verdict['note']}")
            notes_block += [f"- {n['created'][:16]} — {n['body']}" for n in notes]
            notes_block.append("")
    if notes_block:
        lines += ["", "## Notes", ""] + notes_block
    return {"case": case, "filename": f"case-{case}.md", "markdown": "\n".join(lines) + "\n"}


class VerdictRequest(BaseModel):
    ioc: str = Field(..., min_length=1, max_length=2100)
    verdict: str | None = Field(None, pattern="^(malicious|suspicious|benign|false_positive)$")
    note: str | None = Field(None, max_length=1000)


@app.post("/api/ui/verdict", dependencies=[Depends(require_token)])
def ui_set_verdict(req: VerdictRequest) -> dict[str, Any]:
    """Set or clear (``verdict: null``) the analyst's own verdict on an IOC."""
    ioc_id, value = _require_ioc_id(req.ioc)
    database.set_verdict(ioc_id, req.verdict, req.note)
    return {"ioc": value, "verdict": database.get_verdict(ioc_id)}


class NoteRequest(BaseModel):
    ioc: str = Field(..., min_length=1, max_length=2100)
    body: str = Field(..., min_length=1, max_length=2000)


@app.post("/api/ui/notes", dependencies=[Depends(require_token)])
def ui_add_note(req: NoteRequest) -> dict[str, Any]:
    ioc_id, value = _require_ioc_id(req.ioc)
    body = req.body.strip()
    if not body:
        raise HTTPException(status_code=422, detail="note is empty")
    database.add_note(ioc_id, body)
    return {"ioc": value, "notes": database.list_notes(ioc_id)}


@app.delete("/api/ui/notes/{note_id}", dependencies=[Depends(require_token)])
def ui_delete_note(note_id: int) -> dict[str, Any]:
    database.init_db()
    return {"removed": int(database.delete_note(note_id))}


class WatchRequest(BaseModel):
    ioc: str = Field(..., min_length=1, max_length=2100)
    threshold: int = Field(20, ge=1, le=100)


@app.get("/api/ui/watchlist", dependencies=[Depends(require_token)])
def ui_watchlist() -> list[dict[str, Any]]:
    database.init_db()
    return [{**r, "added": str(r["added"]), "last_checked": str(r["last_checked"] or "")} for r in database.watch_list()]


@app.post("/api/ui/watchlist", dependencies=[Depends(require_token)])
def ui_watch_add(req: WatchRequest) -> dict[str, Any]:
    """Add an IOC to the watchlist (or change its alert threshold)."""
    ioc_id, value = _require_ioc_id(req.ioc)
    database.watch_add(ioc_id, req.threshold)
    return {"ioc": value, "watch": database.watch_get(ioc_id)}


@app.delete("/api/ui/watchlist", dependencies=[Depends(require_token)])
def ui_watch_remove(ioc: str = Query(..., description="IOC to stop watching")) -> dict[str, Any]:
    ioc_id, value = _require_ioc_id(ioc)
    return {"ioc": value, "removed": int(database.watch_remove(ioc_id))}


_WATCH_CHECK_MAX = 50


@app.post("/api/ui/watchlist/check", dependencies=[Depends(require_token)])
async def ui_watch_check() -> dict[str, Any]:
    """Re-enrich every watched IOC (fresh, no cache) and report score changes.

    One at a time, so the per-source rate limits are respected. A run that
    came back degraded is reported but never compared: a missing source
    would look like a score drop. ``alerts`` lists IOCs whose score moved
    by at least their own threshold since the last complete check.
    """
    database.init_db()
    rows = database.watch_list()[:_WATCH_CHECK_MAX]
    alerts: list[dict[str, Any]] = []
    degraded: list[dict[str, Any]] = []
    checked = 0
    for row in rows:
        previous = row["checked_score"] if row["checked_score"] is not None else row["score"]
        try:
            result = await enrich.enrich_ioc_async(row["value"], row["type"], no_cache=True)
        except Exception:  # never let one indicator abort the run
            degraded.append({"ioc": row["value"], "unavailable": {"enrich": "exception"}})
            continue
        if result.get("degraded"):
            degraded.append({"ioc": row["value"], "unavailable": result.get("unavailable") or {}})
            continue
        new = int(result.get("final_score") or 0)
        delta = None if previous is None else new - int(previous)
        database.watch_record(row["ioc_id"], new, delta)
        checked += 1
        if delta is not None and abs(delta) >= int(row["threshold"]):
            alerts.append({
                "ioc": row["value"], "type": row["type"], "previous": int(previous), "score": new,
                "delta": delta, "threshold": int(row["threshold"]), "tier": output._risk_tier(new),
            })
    return {"watched": len(rows), "checked": checked, "alerts": alerts, "degraded": degraded}


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
    ioc_type = parser.detect_type(refanged)
    modules, scores = _build_modules_from_cache(ioc_id)

    from ..core import score as score_mod
    final_score = score_mod.calculate_final_risk(scores)

    result: dict[str, Any] = {
        "ioc": refanged,
        "type": ioc_type,
        "modules": modules,
        "final_score": final_score,
    }
    return _apply_output_defang(result, defang)


@app.get(
    "/api/cache/stats",
    response_model=CacheStatsResponse,
    dependencies=[Depends(require_token)],
)
def cache_stats_endpoint() -> CacheStatsResponse:
    """Return row counts, on-disk size, and per-source breakdown.

    Mirrors `shadowscope cache stats`. Read-only — safe to expose to any
    authenticated UI consumer; never returns enrichment payloads or
    secrets, only aggregate counts.
    """
    return CacheStatsResponse(**database.cache_stats())


@app.post(
    "/api/cache/prune",
    response_model=CachePruneResponse,
    dependencies=[Depends(require_token)],
)
def cache_prune_endpoint(req: CachePruneRequest) -> CachePruneResponse:
    """Delete enrichment rows older than `older_than_days` then optionally
    cap per (ioc, source) to the newest `keep_last`.

    No request body fields → uses the same defaults as the CLI:
    `RETENTION_DAYS` env or 90 days, with no per-key cap. Returns the
    exact retention window used so UI clients can display it.
    """
    if req.older_than_days is not None:
        days = float(req.older_than_days)
    else:
        try:
            days = float(os.getenv("RETENTION_DAYS", "90"))
        except ValueError:
            days = 90.0
    keep_last = int(req.keep_last or 0)

    removed_age = database.prune_enrichments_older_than(days)
    removed_cap = database.prune_enrichments_keep_last_n(keep_last) if keep_last else 0
    # Match the CLI's last-prune bookkeeping so the auto-prune janitor
    # backs off until tomorrow.
    database.set_meta("last_prune", datetime.now(timezone.utc).isoformat())
    return CachePruneResponse(
        used_older_than_days=days,
        used_keep_last=keep_last,
        removed_by_age=removed_age,
        removed_by_keep_last=removed_cap,
    )


@app.post(
    "/api/cache/clear",
    response_model=CacheClearResponse,
    dependencies=[Depends(require_token)],
)
def cache_clear_endpoint(req: CacheClearRequest) -> CacheClearResponse:
    """Wipe rows by source, by IOC value, or wholesale.

    Exactly one of ``source`` / ``ioc`` / ``all`` must be set. The check
    is enforced at the API layer so we can return a clean HTTP 400 rather
    than the ValueError the DB function would raise.
    """
    filters = [bool(req.source), bool(req.ioc), bool(req.all)]
    if sum(filters) != 1:
        raise HTTPException(
            status_code=400,
            detail="Pass exactly one of: source, ioc, all=true",
        )
    if req.all:
        scope = "all"
        removed = database.clear_enrichments(all=True)
    elif req.source:
        scope = f"source={req.source}"
        removed = database.clear_enrichments(source=req.source)
    else:
        # req.ioc is set per the sum-of-filters check above.
        assert req.ioc is not None
        scope = f"ioc={req.ioc}"
        removed = database.clear_enrichments(ioc_value=req.ioc)
    return CacheClearResponse(scope=scope, removed=removed)


@app.get("/sources", dependencies=[Depends(require_token)])
def list_sources() -> dict[str, bool]:
    """List every configured source and whether its key is present.

    Returns a flat ``{source_name: key_is_set}`` dict. Never returns the
    key itself — that would leak secrets into HTTP responses.

    Tor and WHOIS need no key and report ``True`` unconditionally; the
    abuse.ch trio reports whether ``ABUSECH_AUTH_KEY`` is set.
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
        # abuse.ch query APIs need one shared Auth-Key (free): https://auth.abuse.ch/
        "urlhaus": bool(os.getenv("ABUSECH_AUTH_KEY")),
        "threatfox": bool(os.getenv("ABUSECH_AUTH_KEY")),
        "malwarebazaar": bool(os.getenv("ABUSECH_AUTH_KEY")),
        "tor": True,
        "whois": True,
    }

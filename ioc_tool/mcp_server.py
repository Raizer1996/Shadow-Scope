"""ShadowScope MCP server — expose the enrichment pipeline to MCP clients.

Runs the orchestrator **in-process** (no REST server needed) over stdio so
an agent such as Claude Code can call ``enrich_ioc`` / ``extract_and_enrich``
directly. Same ``.env`` + SQLite cache as the CLI.

Install + run::

    pip install "shadowscope[mcp]"
    shadowscope-mcp                      # stdio transport

Register with Claude Code::

    claude mcp add --scope user shadowscope -- shadowscope-mcp

stdout is the JSON-RPC channel: nothing in this module (or the pipeline it
calls) may ``print()`` to stdout. Diagnostics go to stderr.
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

from dotenv import load_dotenv

from ioc_tool.core import database, defang, enrich, extractor, llm, parser, score

try:
    from mcp.server.mcpserver import MCPServer
except ImportError as exc:  # pragma: no cover - import guard
    raise SystemExit(
        "shadowscope-mcp needs the 'mcp' package (>=2.3): pip install 'shadowscope[mcp]'"
    ) from exc

_SUPPORTED_TYPES = ("ip", "domain", "url", "hash", "cve", "asn")
_MAX_BULK = 50
_MAX_TEXT = 256_000

server = MCPServer(
    name="shadowscope",
    version="1.0.0",
    instructions=(
        "IOC enrichment + composite risk scoring (0-100: Safe/Low/Medium/High/"
        "Critical) from VirusTotal, AbuseIPDB, OTX, GreyNoise, abuse.ch feeds, "
        "NVD/EPSS/KEV and more. Pass IPs, domains, URLs, hashes, CVE IDs or ASNs; "
        "defanged forms (1[.]2[.]3[.]4, hxxp://) are accepted. Results are cached "
        "for 24h; set no_cache=true to force a refetch."
    ),
)


def _classify(ioc: str) -> tuple[str, str] | dict[str, Any]:
    """Return ``(value, type)`` or an error dict for unsupported input."""
    raw = (ioc or "").strip()
    if not raw:
        return {"error": "empty ioc"}
    ioc_type = parser.detect_type(raw)
    if ioc_type not in _SUPPORTED_TYPES:
        return {
            "error": f"unsupported or unrecognised IOC: {raw!r}",
            "supported_types": list(_SUPPORTED_TYPES),
        }
    return parser.normalize_value(raw, ioc_type), ioc_type


def _compact_modules(modules: dict[str, Any]) -> dict[str, Any]:
    """Per-source ``{score, detail}`` one-liners instead of raw provider payloads.

    A single IP can carry >100 KB of raw Shodan / Censys / OTX JSON; that is
    far more than an agent needs to judge an IOC and blows past most clients'
    tool-result limits. ``verbose=true`` returns the raw ``data`` instead.
    """
    from ioc_tool.web.api import _ui_detail  # lazy: pulls in FastAPI

    out: dict[str, Any] = {}
    for name, entry in (modules or {}).items():
        if not isinstance(entry, dict):
            continue
        sc = entry.get("score")
        raw = entry.get("data")
        data: dict[str, Any] = raw if isinstance(raw, dict) else {}
        try:
            detail = _ui_detail(name, int(sc or 0), data)
        except Exception:  # detail is best-effort; never fail the tool over it
            detail = ""
        item: dict[str, Any] = {"score": sc, "detail": detail}
        for flag in ("rate_limited", "fallback_used"):
            if data.get(flag):
                item[flag] = data[flag]
        out[name] = item
    return out


def _shape(result: dict[str, Any], *, defang_output: bool, verbose: bool = False) -> dict[str, Any]:
    """Add the tier label, compact the modules unless ``verbose``, optionally defang ``ioc``."""
    out = dict(result)
    out["risk_tier"] = score.risk_tier(out.get("final_score"))
    if not verbose:
        out["modules"] = _compact_modules(out.get("modules") or {})
    if defang_output and isinstance(out.get("ioc"), str):
        out["ioc"] = defang.defang(out["ioc"])
    return out


@server.tool()
async def enrich_ioc(
    ioc: str,
    no_cache: bool = False,
    summary: bool = False,
    defang_output: bool = False,
    verbose: bool = False,
) -> dict[str, Any]:
    """Enrich one IOC (IP / domain / URL / hash / CVE / ASN) across every applicable source.

    Returns ``{ioc, type, modules: {Source: {score, detail}}, final_score, risk_tier}``.
    When the result says ``degraded: true``, call this again **without** ``no_cache``:
    sources that answered are served from the 24 h cache and only the ones listed in
    ``unavailable`` are fetched again.
    ``verbose=true`` swaps each source's one-line ``detail`` for its raw provider ``data``
    (can be >100 KB for an IP). ``summary=true`` appends an ``llm_summary`` verdict from
    local Ollama when reachable. ``defang_output=true`` defangs the returned ``ioc``.
    """
    classified = _classify(ioc)
    if isinstance(classified, dict):
        return classified
    value, ioc_type = classified
    result = await enrich.enrich_ioc_async(value, ioc_type, no_cache=no_cache)
    if summary:
        verdict = await asyncio.to_thread(llm.summarize, result)
        if verdict:
            result["llm_summary"] = verdict
    return _shape(result, defang_output=defang_output, verbose=verbose)


@server.tool()
async def enrich_many(
    iocs: list[str],
    no_cache: bool = False,
    defang_output: bool = False,
    verbose: bool = False,
) -> dict[str, Any]:
    """Enrich up to 50 IOCs concurrently. Returns ``{results: [...], skipped: [{ioc, reason}]}``.

    Results are compact (per-source ``{score, detail}``) unless ``verbose=true``.
    """
    if len(iocs) > _MAX_BULK:
        return {"error": f"too many IOCs ({len(iocs)}); max {_MAX_BULK} per call"}
    typed: list[tuple[str, str]] = []
    skipped: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for raw in iocs:
        classified = _classify(raw)
        if isinstance(classified, dict):
            skipped.append({"ioc": raw, "reason": classified["error"]})
            continue
        if classified in seen:
            continue
        seen.add(classified)
        typed.append(classified)
    results = await enrich.enrich_many_async(typed, no_cache=no_cache) if typed else []
    return {
        "results": [_shape(r, defang_output=defang_output, verbose=verbose) for r in results],
        "skipped": skipped,
    }


@server.tool()
async def extract_and_enrich(
    text: str,
    enrich_found: bool = True,
    no_cache: bool = False,
    defang_output: bool = False,
    verbose: bool = False,
) -> dict[str, Any]:
    """Pull IOCs out of free text (log lines, a report, an email) and optionally enrich them.

    Returns ``{extracted: {type: [values]}, results: [...], skipped: [...]}``.
    """
    if len(text) > _MAX_TEXT:
        return {"error": f"text too long ({len(text)} chars); max {_MAX_TEXT}"}
    found = await asyncio.to_thread(extractor.extract_iocs, text)
    out: dict[str, Any] = {"extracted": found}
    if not enrich_found:
        return out
    flat = [v for t, vals in found.items() if t in _SUPPORTED_TYPES for v in vals]
    bulk = await enrich_many(
        flat[:_MAX_BULK], no_cache=no_cache, defang_output=defang_output, verbose=verbose
    )
    out.update(bulk)
    if len(flat) > _MAX_BULK:
        out["truncated"] = len(flat) - _MAX_BULK
    return out


@server.tool()
def show_cached(ioc: str) -> dict[str, Any]:
    """Return what the local cache already holds for an IOC — no network, no API spend.

    ``{"cached": false}`` when the IOC has never been enriched here.
    """
    classified = _classify(ioc)
    if isinstance(classified, dict):
        return classified
    value, ioc_type = classified
    ioc_id = database.get_ioc_id(value)
    if not ioc_id:
        return {"ioc": value, "type": ioc_type, "cached": False}
    conn = database.get_db_connection()
    try:
        row = conn.execute(
            "SELECT last_score, first_seen, last_seen FROM iocs WHERE id = ?", (ioc_id,)
        ).fetchone()
        sources = conn.execute(
            "SELECT source, MAX(timestamp) AS ts, score FROM enrichments "
            "WHERE ioc_id = ? GROUP BY source",
            (ioc_id,),
        ).fetchall()
    finally:
        conn.close()
    last_score = row["last_score"] if row else None
    return {
        "ioc": value,
        "type": ioc_type,
        "cached": True,
        "final_score": last_score,
        "risk_tier": score.risk_tier(last_score),
        "first_seen": row["first_seen"] if row else None,
        "last_seen": row["last_seen"] if row else None,
        "sources": {r["source"]: {"score": r["score"], "fetched_at": r["ts"]} for r in sources},
    }


@server.tool()
def list_sources() -> dict[str, Any]:
    """Which enrichment sources are usable right now (API key present or no key needed)."""
    from ioc_tool.web.api import _SOURCE_REGISTRY

    out: dict[str, Any] = {}
    for src in _SOURCE_REGISTRY:
        env = src.get("env")
        configured = True if env is None else bool(os.getenv(env))
        out[src["id"]] = {
            "configured": configured or bool(src.get("anonymous_ok")),
            "env": env,
            "types": src["types"],
        }
    return out


@server.tool()
def cache_stats() -> dict[str, Any]:
    """Row counts, on-disk size and per-source breakdown of the local SQLite cache."""
    stats = database.cache_stats()
    stats.pop("db_path", None)
    return stats


def _bootstrap() -> None:
    """Load ``ioc_tool/.env`` (same file the CLI uses) and make sure the DB schema exists."""
    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
    workspace = os.getenv("SHADOWSCOPE_WORKSPACE")
    if workspace:
        database.set_workspace(workspace)
    database.init_db()


def main() -> None:
    _bootstrap()
    try:
        server.run(transport="stdio")
    except KeyboardInterrupt:  # pragma: no cover
        print("shadowscope-mcp: stopped", file=sys.stderr)


if __name__ == "__main__":
    main()

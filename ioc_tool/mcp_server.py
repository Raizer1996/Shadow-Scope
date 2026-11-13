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

from ioc_tool.core import (
    database,
    defang,
    enrich,
    envfile,
    extractor,
    llm,
    parser,
    paths,
    related,
    score,
    search,
    timeline,
    userlists,
)
from ioc_tool.core import report as report_mod

try:
    from mcp.server.mcpserver import MCPServer
except ImportError as exc:  # pragma: no cover - import guard
    raise SystemExit(
        "shadowscope-mcp needs the 'mcp' package (>=2.3): pip install 'shadowscope[mcp]'"
    ) from exc

_SUPPORTED_TYPES = ("ip", "domain", "url", "hash", "cve", "asn", "email")
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
        "for 24h; set no_cache=true to force a refetch. The analyst tools "
        "(search_cache, related_indicators, ioc_timeline, report, set_verdict, "
        "add_note, list_cases, assign_case, watchlist, user_list) read and write "
        "only the local database and never call a provider; most need the IOC to "
        "have been enriched first."
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
    problems = envfile.warnings()
    if problems:
        out["_env_warnings"] = problems  # key names and line numbers only, never values
    return out


@server.tool()
def cache_stats() -> dict[str, Any]:
    """Row counts, on-disk size and per-source breakdown of the local SQLite cache."""
    stats = database.cache_stats()
    stats.pop("db_path", None)
    return stats


# ---------------------------------------------------------------------------
# Analyst tools — local database only, no provider calls
# ---------------------------------------------------------------------------

def _cached(ioc: str) -> tuple[int, str, str] | dict[str, Any]:
    """``(ioc_id, value, type)`` for an IOC already in the cache, else an error dict."""
    classified = _classify(ioc)
    if isinstance(classified, dict):
        return classified
    value, ioc_type = classified
    ioc_id = database.get_ioc_id(value)
    if not ioc_id:
        return {"error": f"{value!r} is not in the local cache — run enrich_ioc first", "ioc": value, "cached": False}
    return int(ioc_id), value, ioc_type


@server.tool()
def search_cache(
    query: str = "",
    types: str = "",
    min_score: int | None = None,
    verdict: str = "",
    case: str = "",
    watched: bool | None = None,
    deep: bool = True,
    limit: int = 25,
) -> dict[str, Any]:
    """Search everything stored locally — no network, no API spend.

    ``query`` words must all match somewhere: indicator, verdict, notes, case,
    tags, malware family, or (``deep``) the raw text sources returned. Use
    ``"quoted phrases"`` for exact text. ``types`` is comma-separated
    (ip,domain,url,hash,cve,asn). ``verdict`` / ``case`` take a value, ``any``
    or ``none``. Each row says where it matched.
    """
    wanted = [t.strip().lower() for t in types.split(",") if t.strip()]
    bad = [t for t in wanted if t not in search.TYPES]
    if bad:
        return {"error": f"unknown type(s): {', '.join(bad)}", "supported_types": list(search.TYPES)}
    if verdict and verdict not in ("any", "none", *database.VERDICTS):
        return {"error": f"verdict must be one of: any, none, {', '.join(database.VERDICTS)}"}
    return search.search(
        query, types=wanted, min_score=min_score, verdict=verdict or None, case=case or None,
        watched=watched, deep=deep, limit=max(1, min(int(limit), 100)),
    )


@server.tool()
def related_indicators(ioc: str, limit: int = 8) -> dict[str, Any]:
    """What else to look at for a cached IOC — from local data only.

    Groups: same case, same malware, same network, same domain, hosts seen
    with it (DNS / rDNS / passive DNS), certificate subdomains, shared tags,
    same registrar. Items with ``cached: false`` are only named in the data
    and have not been enriched yet.
    """
    found = _cached(ioc)
    if isinstance(found, dict):
        return found
    ioc_id, value, ioc_type = found
    return {"ioc": value, "type": ioc_type,
            "groups": related.related_for(ioc_id, value, ioc_type, limit=max(1, min(int(limit), 30)))}


@server.tool()
def ioc_timeline(ioc: str, limit: int = 40) -> dict[str, Any]:
    """Every dated fact about a cached IOC, newest first (UTC).

    Mixes what sources reported (registered, first/last seen, listed) with
    local history (score changes, verdicts, notes, case, watchlist).
    """
    found = _cached(ioc)
    if isinstance(found, dict):
        return found
    ioc_id, value, _ = found
    events = timeline.timeline_for(ioc_id)
    cap = max(1, min(int(limit), 200))
    return {"ioc": value, "total": len(events), "events": events[:cap]}


@server.tool()
def report(ioc: str = "", case: str = "") -> dict[str, Any]:
    """A shareable Markdown report on one cached IOC, or on a whole case.

    Pass exactly one of ``ioc`` / ``case``. Indicators are defanged.
    """
    if bool(ioc.strip()) == bool(case.strip()):
        return {"error": "pass exactly one of ioc or case"}
    if case.strip():
        built = report_mod.case_report(case.strip())
        if built is None:
            return {"error": f"no case named {case.strip()!r}"}
        return {"case": case.strip(), "markdown": report_mod.to_markdown(built[1])}
    found = _cached(ioc)
    if isinstance(found, dict):
        return found
    ioc_id, value, ioc_type = found
    return {"ioc": value, "markdown": report_mod.to_markdown(report_mod.ioc_report(ioc_id, value, ioc_type)[1])}


@server.tool()
def set_verdict(ioc: str, verdict: str, note: str = "") -> dict[str, Any]:
    """Record the analyst's own verdict on a cached IOC (stored locally).

    ``verdict``: malicious, suspicious, benign, false_positive — or ``clear``
    to remove it. The verdict sits beside the computed score; it never
    changes the score.
    """
    found = _cached(ioc)
    if isinstance(found, dict):
        return found
    ioc_id, value, _ = found
    wanted = verdict.strip().lower().replace(" ", "_")
    if wanted == "clear":
        database.set_verdict(ioc_id, None)
    elif wanted in database.VERDICTS:
        database.set_verdict(ioc_id, wanted, note.strip()[:1000] or None)
    else:
        return {"error": f"verdict must be one of: {', '.join(database.VERDICTS)}, clear"}
    return {"ioc": value, "verdict": database.get_verdict(ioc_id)}


@server.tool()
def add_note(ioc: str, note: str) -> dict[str, Any]:
    """Attach a free-text note to a cached IOC (stored locally)."""
    found = _cached(ioc)
    if isinstance(found, dict):
        return found
    ioc_id, value, _ = found
    body = note.strip()[:2000]
    if not body:
        return {"error": "empty note"}
    database.add_note(ioc_id, body)
    return {"ioc": value, "notes": database.list_notes(ioc_id)}


@server.tool()
def list_cases() -> dict[str, Any]:
    """Every case with its status, description and member indicators."""
    meta = database.get_case_meta()
    names = {row["case_name"] for row in database.list_cases_with_summary()} | set(meta)
    cases = []
    for name in sorted(names):
        members = database.list_iocs_for_case(name)
        scores = [m["last_score"] for m in members if m.get("last_score") is not None]
        info = meta.get(name, {})
        cases.append({
            "case": name, "status": info.get("status", "open"), "description": info.get("description") or None,
            "max_score": max(scores) if scores else None,
            "indicators": [{"ioc": m["value"], "type": m["type"], "score": m.get("last_score")} for m in members],
        })
    return {"cases": cases}


@server.tool()
def assign_case(ioc: str, case: str) -> dict[str, Any]:
    """Put a cached IOC into a case (created if new). Empty ``case`` removes it from its case."""
    found = _cached(ioc)
    if isinstance(found, dict):
        return found
    _, value, _ = found
    name = " ".join(case.split())[:80]
    if name:
        database.upsert_case(name)
    database.set_ioc_case(value, name or None)
    return {"ioc": value, "case": name or None}


@server.tool()
def watchlist(action: str = "list", ioc: str = "", threshold: int = 20) -> dict[str, Any]:
    """The watchlist: indicators re-checked for score changes from the dashboard.

    ``action``: ``list`` (default), ``add`` or ``remove`` (both need ``ioc``).
    ``threshold`` is the score move that raises an alert. Re-checking itself
    is done from the dashboard's Watch tab — it spends API quota.
    """
    act = action.strip().lower()
    if act == "list":
        return {"watched": [
            {"ioc": r["value"], "type": r["type"], "score": r["score"], "threshold": r["threshold"],
             "last_checked": str(r["last_checked"])[:16] if r["last_checked"] else None, "last_delta": r["last_delta"]}
            for r in database.watch_list()
        ]}
    if act not in ("add", "remove"):
        return {"error": "action must be list, add or remove"}
    found = _cached(ioc)
    if isinstance(found, dict):
        return found
    ioc_id, value, _ = found
    if act == "add":
        if not 1 <= int(threshold) <= 100:
            return {"error": "threshold must be 1-100"}
        database.watch_add(ioc_id, int(threshold))
        return {"ioc": value, "watch": database.watch_get(ioc_id)}
    return {"ioc": value, "removed": database.watch_remove(ioc_id)}


@server.tool()
def user_list(
    action: str = "list",
    list_name: str = "",
    pattern: str = "",
    note: str = "",
    entry_id: int | None = None,
) -> dict[str, Any]:
    """The user's own blocklist / allowlist (stored locally, applied at once).

    ``action``: ``list`` (default); ``add`` needs ``list_name`` (block|allow)
    and ``pattern`` (IP, CIDR, domain — covers subdomains —, URL, hash, CVE,
    ASN); ``remove`` needs ``entry_id``; ``check`` tells which entry, if any,
    covers ``pattern``. Blocked scores 100; allowed skips all lookups.
    """
    act = action.strip().lower()
    if act == "list":
        return {"entries": userlists.entries()}
    if act == "add":
        try:
            return {"added": userlists.add(list_name.strip().lower(), pattern, note)}
        except ValueError as exc:
            return {"error": str(exc)}
    if act == "remove":
        if entry_id is None:
            return {"error": "remove needs entry_id (see action=list)"}
        return {"removed": userlists.remove(int(entry_id))}
    if act == "check":
        classified = _classify(pattern)
        if isinstance(classified, dict):
            return classified
        return {"ioc": classified[0], "match": userlists.match(classified[0], classified[1])}
    return {"error": "action must be list, add, remove or check"}


def _bootstrap() -> None:
    """Load the same ``.env`` the CLI uses and make sure the DB schema exists.

    ``paths.env_file()`` is the package folder in a source checkout and the
    per-user home (``%LOCALAPPDATA%\\ShadowScope`` / ``SHADOWSCOPE_HOME``) when
    installed. Looking only beside the package left an installed MCP server
    with no API keys.
    """
    for problem in envfile.load():
        print(f"shadowscope-mcp: {problem}", file=sys.stderr)
    paths.ensure_data_dir()
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

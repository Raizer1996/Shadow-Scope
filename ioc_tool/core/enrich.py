"""Per-IOC enrichment orchestrator.

This module fans out a single IOC across every applicable threat-intel
source, applies the cache-aware refresh policy, scores each response,
persists fresh data to SQLite, and returns a unified result dict for the
UI / output layers.

# Concurrency model
The 16 external sources (VT, AbuseIPDB, Shodan, IPQS, IPinfo, Tor list,
WHOIS, URLhaus, GreyNoise, ThreatFox, MalwareBazaar, OTX, URLscan, ...)
are all I/O-bound `requests` calls with no inter-dependencies. Each
per-source task is dispatched via :func:`asyncio.to_thread` and the full
batch is awaited with :func:`asyncio.gather`, so wall-clock time becomes
roughly ``max(per-source latency)`` instead of the sum.

We deliberately keep the underlying modules sync (`requests`-based) and
delegate them onto the default thread pool rather than rewriting against
``aiohttp``. That keeps the existing ``responses`` test suite green and
avoids touching every ``ioc_tool/modules/*.py`` file.

Public surface:

- :func:`enrich_ioc` — sync wrapper, the historical entry point used by
  ``cli.handle_enrich`` and ``cli.handle_show``. Internally drives the
  async pipeline with :func:`asyncio.run`.
- :func:`enrich_ioc_async` — coroutine form, suitable for a future
  bulk-parallel mode that fans out across multiple IOCs at once.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Callable
from contextvars import ContextVar
from datetime import datetime, timedelta
from typing import Any

from ..modules import (
    abuseipdb,
    crtsh,
    epss,
    feodo,
    greynoise,
    ip_quality_score,
    ipinfo_mod,
    kev,
    malwarebazaar,
    nvd,
    otx,
    pulsedive,
    shodan_mod,
    sslbl,
    threatfox,
    tor,
    urlhaus,
    urlscan,
    vt,
    whois_mod,
)
from . import allowlist, database, heuristics, parser, score

# Per-call ``--no-cache`` toggle — propagates from enrich_ioc{,_async}
# into _run_source via a ContextVar so we don't have to thread the flag
# through every per-source asyncio.to_thread call site. ``asyncio.to_thread``
# preserves the active context for the worker thread, so a value set in
# the orchestrator is visible to the source worker without any glue.
no_cache_ctx: ContextVar[bool] = ContextVar("no_cache_ctx", default=False)


# Cache TTL — how long a cached row is considered fresh before we refetch.
# Defaults to 24 h to match the historical behaviour; can be tuned via the
# ``CACHE_TTL_HOURS`` env var (float supported for sub-hour increments).
# Unparseable or non-positive values fall back to 24 h.
_DEFAULT_CACHE_TTL_HOURS = 24.0


def _cache_ttl_hours() -> float:
    """Resolve the cache TTL in hours from the env, with a 24 h fallback."""
    raw = os.getenv("CACHE_TTL_HOURS", "").strip()
    if not raw:
        return _DEFAULT_CACHE_TTL_HOURS
    try:
        value = float(raw)
    except ValueError:
        return _DEFAULT_CACHE_TTL_HOURS
    return value if value > 0 else _DEFAULT_CACHE_TTL_HOURS

# ---------------------------------------------------------------------------
# Cache freshness
# ---------------------------------------------------------------------------


def should_refresh(timestamp_str: str | None) -> bool:
    """Return True when the cached row is older than ``CACHE_TTL_HOURS`` or unparseable."""
    if not timestamp_str:
        return True
    try:
        # SQLite default timestamp is often 'YYYY-MM-DD HH:MM:SS.ssssss'
        last_check = (
            datetime.fromisoformat(timestamp_str)
            if 'T' in timestamp_str
            else datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
        )
    except ValueError:
        try:
            last_check = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        except Exception:
            return True

    return datetime.now() - last_check > timedelta(hours=_cache_ttl_hours())


# ---------------------------------------------------------------------------
# Per-source worker
# ---------------------------------------------------------------------------
#
# Each source contributes one entry to the gather. The worker is
# intentionally simple: check cache, fetch if stale, score, persist.
# Returning a tuple lets the caller assemble the results dict outside
# the thread (so we never share dict state across tasks).
#
# Sentinel for sources that fetch info-only data (Shodan, IPinfo) — they
# still appear in the results dict but their score does NOT feed into
# the composite. The historical behavior already appended 0 for IPQS /
# AbuseIPDB / etc., so info-only sources are flagged via a separate
# boolean rather than score-value introspection.


_SourceResult = tuple[str, dict, int, bool]
# (display_name, data, score, contributes_to_composite)


def _run_source(
    ioc_id: int,
    source_key: str,
    display_name: str,
    fetcher: Callable[[], dict | None],
    scorer: Callable[[dict], int] | None,
    *,
    info_only: bool = False,
    cache_filter: Callable[[dict], dict | None] | None = None,
    post_process: Callable[[dict], tuple[dict, int]] | None = None,
    no_cache: bool = False,
) -> _SourceResult | None:
    """Run a single enrichment source: cache → fetch → score → persist.

    Parameters mirror the historical per-source blocks in :func:`enrich_ioc`:

    * ``cache_filter`` runs on the raw fetcher payload BEFORE persistence
      (used by Shodan, which returns ``{"error": ...}`` on auth failures —
      we treat those as no-data and skip the DB write).
    * ``post_process`` is a hook used exclusively by WHOIS, whose payload
      contains :class:`datetime` objects that must be normalised to ISO
      strings before JSON-encoding into SQLite. Returns the
      ``(serialisable_data, score)`` pair to persist + return.
    * ``no_cache`` (or :data:`no_cache_ctx` set to ``True``) bypasses the
      cache-hit branch and always refetches. Fresh data is still written
      to the cache so subsequent calls without the flag benefit from the
      new row.
    """
    if not (no_cache or no_cache_ctx.get()):
        cached = database.get_latest_enrichment(ioc_id, source_key)
        if cached and not should_refresh(cached['timestamp']):
            data = json.loads(cached['data'])
            return (display_name, data, cached['score'], not info_only)

    data = fetcher()
    if cache_filter is not None and data is not None:
        data = cache_filter(data)
    if data is None:
        return None

    if post_process is not None:
        # WHOIS: convert datetimes → ISO before storage, compute score
        # from the original (pre-serialisation) record.
        data, source_score = post_process(data)
    else:
        source_score = scorer(data) if scorer is not None else 0

    database.add_enrichment(ioc_id, source_key, data, source_score)
    return (display_name, data, source_score, not info_only)


# ---------------------------------------------------------------------------
# Per-source fetcher factories (each closes over `value` / `ioc_type`)
# ---------------------------------------------------------------------------


def _vt_fetcher(value: str, ioc_type: str) -> Callable[[], dict | None]:
    def _do() -> dict | None:
        if ioc_type == 'ip':
            return vt.enrich_ip(value)
        if ioc_type == 'domain':
            return vt.enrich_domain(value)
        if ioc_type == 'url':
            return vt.enrich_url(value)
        if ioc_type == 'hash':
            return vt.enrich_hash(value)
        return None
    return _do


def _vt_scorer(data: dict) -> int:
    return score.calculate_vt_score(data.get('last_analysis_stats', {}))


def _shodan_filter(data: dict) -> dict | None:
    """Shodan returns ``{'error': ...}`` on auth/missing-key — treat as no-data."""
    if isinstance(data, dict) and 'error' in data:
        return None
    return data


def _ipqs_scorer(data: dict) -> int:
    return data.get('fraud_score', 0) if isinstance(data, dict) else 0


def _urlhaus_fetcher(value: str, ioc_type: str) -> Callable[[], dict | None]:
    def _do() -> dict | None:
        if ioc_type == 'url':
            return urlhaus.enrich_url(value)
        return urlhaus.enrich_host(value)
    return _do


def _whois_post_process(data: dict) -> tuple[dict, int]:
    """Serialise datetime fields → ISO strings; compute score from creation_date."""
    serializable_whois: dict[str, Any] = {}
    for key, val in data.items():
        if isinstance(val, datetime):
            serializable_whois[key] = val.isoformat()
        elif isinstance(val, list):
            serializable_whois[key] = [
                x.isoformat() if isinstance(x, datetime) else x for x in val
            ]
        else:
            serializable_whois[key] = val
    whois_score = score.calculate_whois_score(data.get('creation_date'))
    return serializable_whois, whois_score


# ---------------------------------------------------------------------------
# Tor — special: list lookup, no HTTP, no per-source DB cache row.
# ---------------------------------------------------------------------------


def _tor_check(value: str) -> _SourceResult | None:
    """Tor exit-node check. Local file lookup, kept on the thread pool for
    parity with the other sources (cheap, but predictable scheduling).
    """
    try:
        is_tor = tor.is_tor_node(value)
    except Exception:
        return None
    if not is_tor:
        return None
    return ('TOR', {'is_tor': True}, 100, True)


# ---------------------------------------------------------------------------
# Async orchestrator
# ---------------------------------------------------------------------------


async def enrich_ioc_async(
    value: str,
    ioc_type: str,
    *,
    no_cache: bool = False,
) -> dict:
    """Run every applicable enrichment source for ``value`` in parallel.

    Each source is delegated to :func:`asyncio.to_thread` so its blocking
    ``requests`` call runs on the default thread pool. The full batch is
    awaited with :func:`asyncio.gather(return_exceptions=True)` — any
    single-source crash is swallowed and that source is skipped, matching
    the historical "API failures return None — never crash the CLI" rule.

    Set ``no_cache=True`` to force a fresh fetch from every source,
    bypassing the SQLite cache.
    """
    token = no_cache_ctx.set(no_cache) if no_cache else None
    try:
        return await _enrich_ioc_inner(value, ioc_type)
    finally:
        if token is not None:
            no_cache_ctx.reset(token)


async def _enrich_ioc_inner(value: str, ioc_type: str) -> dict:
    # Canonicalise the value for types that require it (currently just
    # CVE → uppercased) so the DB cache key, the per-source lookups,
    # and the returned ``ioc`` field all agree on one shape.
    value = parser.normalize_value(value, ioc_type)

    # Allowlist short-circuit — skip every external source for known-internal
    # / trusted IOCs. Saves API quota on bulk enrichment of corp ranges.
    # The result still flows through the same shape (modules dict) so output
    # adapters (CSV/STIX/MD) treat it uniformly.
    allow_hit = allowlist.is_allowlisted(value, ioc_type)
    if allow_hit is not None:
        return {
            'ioc': value,
            'type': ioc_type,
            'modules': {'Allowlist': {'score': 0, 'data': allow_hit}},
            'final_score': 0,
            'allowlisted': True,
        }

    ioc_id = database.add_or_update_ioc(value, ioc_type)
    tasks: list = []

    # --- VirusTotal — all IOC types ---
    tasks.append(asyncio.to_thread(
        _run_source, ioc_id, 'virustotal', 'VirusTotal',
        _vt_fetcher(value, ioc_type), _vt_scorer,
    ))

    # --- AbuseIPDB — IP only ---
    if ioc_type == 'ip':
        tasks.append(asyncio.to_thread(
            _run_source, ioc_id, 'abuseipdb', 'AbuseIPDB',
            lambda: abuseipdb.enrich_ip(value),
            score.calculate_abuseipdb_score,
        ))

    # --- Tor exit-node — IP only (no DB cache; matches historical behaviour) ---
    if ioc_type == 'ip':
        tasks.append(asyncio.to_thread(_tor_check, value))

    # --- Shodan — IP only (info-only score; error-dict → None) ---
    if ioc_type == 'ip':
        tasks.append(asyncio.to_thread(
            _run_source, ioc_id, 'shodan', 'Shodan',
            lambda: shodan_mod.host_search(value),
            None,
            info_only=True,
            cache_filter=_shodan_filter,
        ))

    # --- IPQualityScore — IP only ---
    if ioc_type == 'ip':
        tasks.append(asyncio.to_thread(
            _run_source, ioc_id, 'ipqs', 'IPQS',
            lambda: ip_quality_score.enrich_ip(value),
            _ipqs_scorer,
        ))

    # --- IPinfo — IP only (info-only) ---
    if ioc_type == 'ip':
        tasks.append(asyncio.to_thread(
            _run_source, ioc_id, 'ipinfo', 'IPinfo',
            lambda: ipinfo_mod.enrich_ip(value),
            None,
            info_only=True,
        ))

    # --- GreyNoise — IP only ---
    if ioc_type == 'ip':
        tasks.append(asyncio.to_thread(
            _run_source, ioc_id, 'greynoise', 'GreyNoise',
            lambda: greynoise.enrich_ip(value),
            score.calculate_greynoise_score,
        ))

    # --- URLhaus — URL / domain / IP ---
    if ioc_type in ('url', 'domain', 'ip'):
        tasks.append(asyncio.to_thread(
            _run_source, ioc_id, 'urlhaus', 'URLhaus',
            _urlhaus_fetcher(value, ioc_type),
            score.calculate_urlhaus_score,
        ))

    # --- ThreatFox — IP / domain / URL / hash ---
    if ioc_type in ('ip', 'domain', 'url', 'hash'):
        tasks.append(asyncio.to_thread(
            _run_source, ioc_id, 'threatfox', 'ThreatFox',
            lambda: threatfox.enrich(value),
            score.calculate_threatfox_score,
        ))

    # --- AlienVault OTX — IP / domain / URL / hash ---
    if ioc_type in ('ip', 'domain', 'url', 'hash'):
        tasks.append(asyncio.to_thread(
            _run_source, ioc_id, 'otx', 'OTX',
            lambda: otx.enrich(value, ioc_type),
            score.calculate_otx_score,
        ))

    # --- URLscan.io — IP / domain / URL ---
    if ioc_type in ('ip', 'domain', 'url'):
        tasks.append(asyncio.to_thread(
            _run_source, ioc_id, 'urlscan', 'URLscan',
            lambda: urlscan.enrich(value, ioc_type),
            score.calculate_urlscan_score,
        ))

    # --- Pulsedive — IP / domain / URL (free, no key required) ---
    if ioc_type in ('ip', 'domain', 'url'):
        tasks.append(asyncio.to_thread(
            _run_source, ioc_id, 'pulsedive', 'Pulsedive',
            lambda: pulsedive.enrich(value, ioc_type),
            score.calculate_pulsedive_score,
        ))

    # --- MalwareBazaar — hash only ---
    if ioc_type == 'hash':
        tasks.append(asyncio.to_thread(
            _run_source, ioc_id, 'malwarebazaar', 'MalwareBazaar',
            lambda: malwarebazaar.enrich_hash(value),
            score.calculate_malwarebazaar_score,
        ))

    # --- abuse.ch Feodo Tracker — IP only (botnet C2 blocklist) ---
    if ioc_type == 'ip':
        tasks.append(asyncio.to_thread(
            _run_source, ioc_id, 'feodo', 'Feodo',
            lambda: feodo.enrich_ip(value),
            score.calculate_feodo_score,
        ))

    # --- abuse.ch SSL Blacklist — hash only (SHA-1 cert fingerprints) ---
    if ioc_type == 'hash':
        tasks.append(asyncio.to_thread(
            _run_source, ioc_id, 'sslbl', 'SSLBL',
            lambda: sslbl.enrich_hash(value),
            score.calculate_sslbl_score,
        ))

    # --- crt.sh certificate transparency — domain only ---
    if ioc_type == 'domain':
        tasks.append(asyncio.to_thread(
            _run_source, ioc_id, 'crtsh', 'crt.sh',
            lambda: crtsh.enrich_domain(value),
            score.calculate_crtsh_score,
        ))

    # --- WHOIS — domain only (datetime serialisation hook) ---
    if ioc_type == 'domain':
        tasks.append(asyncio.to_thread(
            _run_source, ioc_id, 'whois', 'WHOIS',
            lambda: whois_mod.get_whois_data(value),
            None,
            post_process=_whois_post_process,
        ))

    # --- CVE enrichment fan-out: NVD + EPSS + CISA KEV ---
    # All three share the per-source DB cache (24 h TTL via should_refresh)
    # so a repeated query within the day doesn't refetch. KEV additionally
    # caches the full catalog on disk at ioc_tool/data/cisa_kev.json
    # (see ioc_tool.modules.kev) — that's a second layer below the DB row.
    if ioc_type == 'cve':
        tasks.append(asyncio.to_thread(
            _run_source, ioc_id, 'nvd', 'NVD',
            lambda: nvd.enrich_cve(value),
            score.calculate_nvd_score,
        ))
        tasks.append(asyncio.to_thread(
            _run_source, ioc_id, 'epss', 'EPSS',
            lambda: epss.enrich_cve(value),
            score.calculate_epss_score,
        ))
        tasks.append(asyncio.to_thread(
            _run_source, ioc_id, 'kev', 'KEV',
            lambda: kev.get_kev_entry(value),
            score.calculate_kev_score,
        ))

    raw_results = await asyncio.gather(*tasks, return_exceptions=True)

    results: dict[str, Any] = {}
    scores: list[int] = []
    for item in raw_results:
        if isinstance(item, BaseException):
            # Source crashed in the thread — swallow per the never-crash contract.
            continue
        if item is None:
            continue
        display_name, data, src_score, contributes = item
        results[display_name] = {'score': src_score, 'data': data}
        if contributes:
            scores.append(src_score)

    # ---------------------------------------------------------------------
    # Local heuristics — pure functions on data we already have.
    # Bundled under a single 'Heuristics' module entry so they surface in
    # the output without changing the per-source schema.
    # ---------------------------------------------------------------------
    heuristics_data: dict[str, Any] = {}
    heuristics_scores: list[int] = []

    if ioc_type == 'domain':
        whois_entry = results.get('WHOIS', {}).get('data') or {}
        nrd = heuristics.nrd_check(whois_entry.get('creation_date'))
        if nrd is not None:
            heuristics_data['nrd'] = nrd
            heuristics_scores.append(nrd['score'])

        dga = heuristics.dga_check(value)
        if dga is not None:
            heuristics_data['dga'] = dga
            heuristics_scores.append(dga['score'])

        typo = heuristics.typosquat_check(value)
        if typo is not None:
            heuristics_data['typosquat'] = typo
            heuristics_scores.append(typo['score'])

        idn = heuristics.idn_check(value)
        if idn is not None:
            heuristics_data['idn'] = idn
            heuristics_scores.append(idn['score'])

    if heuristics_data:
        composite = (
            int(sum(heuristics_scores) / len(heuristics_scores))
            if heuristics_scores else 0
        )
        results['Heuristics'] = {'score': composite, 'data': heuristics_data}
        if composite > 0:
            scores.append(composite)

    final_score = score.calculate_final_risk(scores)
    return {
        'ioc': value,
        'type': ioc_type,
        'modules': results,
        'final_score': final_score,
    }


def enrich_ioc(value: str, ioc_type: str, *, no_cache: bool = False) -> dict:
    """Sync wrapper: drives :func:`enrich_ioc_async` via :func:`asyncio.run`.

    Existing call sites (``cli.handle_enrich``, ``cli.handle_show``) stay
    unchanged — only the internals are now parallel. The optional
    ``no_cache`` flag forces every source to refetch rather than reading
    from the SQLite cache, matching the ``--no-cache`` CLI flag.
    """
    return asyncio.run(enrich_ioc_async(value, ioc_type, no_cache=no_cache))


async def enrich_many_async(
    iocs: list[tuple[str, str]],
    *,
    no_cache: bool = False,
) -> list[dict]:
    """Enrich a batch of (value, ioc_type) pairs in parallel.

    Fans out one ``enrich_ioc_async`` coroutine per IOC, awaited with
    :func:`asyncio.gather(return_exceptions=True)` so a single crashing
    IOC can't take down the batch — failed entries are dropped silently
    (matching the per-source never-crash contract one level up). Order
    of the returned list matches input order, minus any crashes.

    The wall-clock win is meaningful for SOC bulk-enrichment workflows:
    20 IOCs sequentially is 20 × max(per-IOC latency); with this fan-out
    it's still ~max(per-IOC latency) — the source fan-out within each
    IOC dominates over the per-IOC dimension.
    """
    tasks = [enrich_ioc_async(value, ioc_type, no_cache=no_cache) for value, ioc_type in iocs]
    raw = await asyncio.gather(*tasks, return_exceptions=True)
    return [item for item in raw if not isinstance(item, BaseException)]


def enrich_many(
    iocs: list[tuple[str, str]],
    *,
    no_cache: bool = False,
) -> list[dict]:
    """Sync wrapper for :func:`enrich_many_async` — used by the bulk CLI path."""
    return asyncio.run(enrich_many_async(iocs, no_cache=no_cache))

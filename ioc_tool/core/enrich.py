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
from datetime import datetime, timedelta
from typing import Any, Callable, Optional, Tuple

from . import database, score
from ..modules import (
    abuseipdb,
    greynoise,
    ipinfo_mod,
    ip_quality_score,
    malwarebazaar,
    otx,
    shodan_mod,
    threatfox,
    tor,
    urlhaus,
    urlscan,
    vt,
    whois_mod,
)


# ---------------------------------------------------------------------------
# Cache freshness
# ---------------------------------------------------------------------------


def should_refresh(timestamp_str: Optional[str]) -> bool:
    """Return True if the cached row is stale (older than 24 h) or unparseable."""
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

    return datetime.now() - last_check > timedelta(hours=24)


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


_SourceResult = Tuple[str, dict, int, bool]
# (display_name, data, score, contributes_to_composite)


def _run_source(
    ioc_id: int,
    source_key: str,
    display_name: str,
    fetcher: Callable[[], Optional[dict]],
    scorer: Optional[Callable[[dict], int]],
    *,
    info_only: bool = False,
    cache_filter: Optional[Callable[[dict], Optional[dict]]] = None,
    post_process: Optional[Callable[[dict], Tuple[dict, int]]] = None,
) -> Optional[_SourceResult]:
    """Run a single enrichment source: cache → fetch → score → persist.

    Parameters mirror the historical per-source blocks in :func:`enrich_ioc`:

    * ``cache_filter`` runs on the raw fetcher payload BEFORE persistence
      (used by Shodan, which returns ``{"error": ...}`` on auth failures —
      we treat those as no-data and skip the DB write).
    * ``post_process`` is a hook used exclusively by WHOIS, whose payload
      contains :class:`datetime` objects that must be normalised to ISO
      strings before JSON-encoding into SQLite. Returns the
      ``(serialisable_data, score)`` pair to persist + return.
    """
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


def _vt_fetcher(value: str, ioc_type: str) -> Callable[[], Optional[dict]]:
    def _do() -> Optional[dict]:
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


def _shodan_filter(data: dict) -> Optional[dict]:
    """Shodan returns ``{'error': ...}`` on auth/missing-key — treat as no-data."""
    if isinstance(data, dict) and 'error' in data:
        return None
    return data


def _ipqs_scorer(data: dict) -> int:
    return data.get('fraud_score', 0) if isinstance(data, dict) else 0


def _urlhaus_fetcher(value: str, ioc_type: str) -> Callable[[], Optional[dict]]:
    def _do() -> Optional[dict]:
        if ioc_type == 'url':
            return urlhaus.enrich_url(value)
        return urlhaus.enrich_host(value)
    return _do


def _whois_post_process(data: dict) -> Tuple[dict, int]:
    """Serialise datetime fields → ISO strings; compute score from creation_date."""
    serializable_whois = {}
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


def _tor_check(value: str) -> Optional[_SourceResult]:
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


async def enrich_ioc_async(value: str, ioc_type: str) -> dict:
    """Run every applicable enrichment source for ``value`` in parallel.

    Each source is delegated to :func:`asyncio.to_thread` so its blocking
    ``requests`` call runs on the default thread pool. The full batch is
    awaited with :func:`asyncio.gather(return_exceptions=True)` — any
    single-source crash is swallowed and that source is skipped, matching
    the historical "API failures return None — never crash the CLI" rule.
    """
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

    # --- MalwareBazaar — hash only ---
    if ioc_type == 'hash':
        tasks.append(asyncio.to_thread(
            _run_source, ioc_id, 'malwarebazaar', 'MalwareBazaar',
            lambda: malwarebazaar.enrich_hash(value),
            score.calculate_malwarebazaar_score,
        ))

    # --- WHOIS — domain only (datetime serialisation hook) ---
    if ioc_type == 'domain':
        tasks.append(asyncio.to_thread(
            _run_source, ioc_id, 'whois', 'WHOIS',
            lambda: whois_mod.get_whois_data(value),
            None,
            post_process=_whois_post_process,
        ))

    raw_results = await asyncio.gather(*tasks, return_exceptions=True)

    results: dict[str, Any] = {}
    scores: list[int] = []
    for item in raw_results:
        if isinstance(item, Exception):
            # Source crashed in the thread — swallow per the never-crash contract.
            continue
        if item is None:
            continue
        display_name, data, src_score, contributes = item
        results[display_name] = {'score': src_score, 'data': data}
        if contributes:
            scores.append(src_score)

    final_score = score.calculate_final_risk(scores)
    return {
        'ioc': value,
        'type': ioc_type,
        'modules': results,
        'final_score': final_score,
    }


def enrich_ioc(value: str, ioc_type: str) -> dict:
    """Sync wrapper: drives :func:`enrich_ioc_async` via :func:`asyncio.run`.

    Existing call sites (``cli.handle_enrich``, ``cli.handle_show``) stay
    unchanged — only the internals are now parallel.
    """
    return asyncio.run(enrich_ioc_async(value, ioc_type))

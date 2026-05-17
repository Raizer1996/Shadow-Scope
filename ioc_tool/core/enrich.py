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
import contextlib
import json
import os
from collections.abc import Callable
from contextvars import ContextVar
from datetime import datetime, timedelta
from typing import Any

from ..modules import (
    abstract_api,
    abuseipdb,
    censys,
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
    pdns,
    pulsedive,
    rdns,
    shodan_mod,
    sslbl,
    threatfox,
    tor,
    urlhaus,
    urlscan,
    vt,
    whois_mod,
)
from ..modules import (
    asn as asn_mod,
)
from . import allowlist, database, heuristics, http, parser, score

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
# Cache retention (auto-prune)
# ---------------------------------------------------------------------------
#
# ``CACHE_TTL_HOURS`` only governs *freshness* (when to refetch); without a
# janitor the SQLite table would grow forever because ``add_enrichment``
# always INSERTs. The hook below runs at most once per process *and* once
# per 24 h per workspace, deleting rows older than ``RETENTION_DAYS``
# (default 90 d). Set ``AUTO_PRUNE=0`` to disable entirely — analysts who
# manage retention via cron / `shadowscope cache prune` can opt out.

_DEFAULT_RETENTION_DAYS = 90.0
_AUTO_PRUNE_INTERVAL_HOURS = 24.0
_auto_prune_done: set[str] = set()  # workspaces already checked this process


# ---------------------------------------------------------------------------
# Provider failover (VT → OTX on 429)
# ---------------------------------------------------------------------------
#
# VirusTotal's free tier (4 req/min) is the tightest in the fan-out; OTX
# (10 req/min default) covers the same IP/domain/hash territory with
# overlapping coverage. When the rate-limit ledger flags VT as throttled
# during this fan-out, we add OTX synchronously (if it wasn't already in
# the planned task list) and stamp a ``fallback_used`` annotation on the
# VT entry so the analyst can see we substituted.
#
# The decision is purely additive — it never modifies the composite score
# formula. Opt out via ``SHADOWSCOPE_FAILOVER_DISABLE=1``.

# Subset of IOC types that overlap between VT and OTX. URL is excluded
# deliberately: the task spec scopes failover to IP/domain/hash.
_OTX_FAILOVER_TYPES = frozenset({"ip", "domain", "hash"})


def _failover_enabled() -> bool:
    """Default-on. ``SHADOWSCOPE_FAILOVER_DISABLE=1`` skips the fallback path."""
    raw = os.getenv("SHADOWSCOPE_FAILOVER_DISABLE", "").strip().lower()
    return raw not in {"1", "true", "yes", "on"}


def _retention_days() -> float:
    raw = os.getenv("RETENTION_DAYS", "").strip()
    if not raw:
        return _DEFAULT_RETENTION_DAYS
    try:
        value = float(raw)
    except ValueError:
        return _DEFAULT_RETENTION_DAYS
    return value if value > 0 else _DEFAULT_RETENTION_DAYS


def _auto_prune_enabled() -> bool:
    """Honour ``AUTO_PRUNE`` env. Default on; ``0``/``false``/``no`` disable."""
    raw = os.getenv("AUTO_PRUNE", "1").strip().lower()
    return raw not in {"0", "false", "no", "off", ""}


def maybe_auto_prune() -> None:
    """Run an age-based prune at most once per process per workspace per day.

    Silent: errors are swallowed so a broken DB never blocks enrichment. The
    last-prune timestamp is stored in the workspace's ``meta`` table so a
    long-running daemon and a one-shot CLI invocation see the same schedule.
    """
    if not _auto_prune_enabled():
        return
    try:
        db_path = database.DB_PATH
        if db_path in _auto_prune_done:
            return
        _auto_prune_done.add(db_path)

        last_raw = database.get_meta("last_prune")
        if last_raw:
            try:
                last = datetime.fromisoformat(last_raw)
                if datetime.now() - last < timedelta(hours=_AUTO_PRUNE_INTERVAL_HOURS):
                    return
            except ValueError:
                pass  # corrupt timestamp → fall through and run prune

        database.prune_enrichments_older_than(_retention_days())
        database.set_meta("last_prune", datetime.now().isoformat())
    except Exception:
        # Maintenance must never break the user-facing enrichment path.
        pass

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
    """Treat ``{}`` / ``{'error': ...}`` as no-data so we don't persist empty rows.

    Both Shodan (`host_search`) and Censys (`host_lookup`) return an empty
    dict when no API key is configured or the IP simply isn't in the index.
    Persisting those would inflate the cache with `{}` rows that re-trigger
    a fetch on every call (because there's no useful payload to compare
    against) and clutter the per-source history view.
    """
    if not isinstance(data, dict) or not data or 'error' in data:
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
# VT → OTX failover helper
# ---------------------------------------------------------------------------


def _apply_vt_otx_failover(
    value: str,
    ioc_type: str,
    ioc_id: int,
    results: dict[str, Any],
    scores: list[tuple[str, int]],
    planned_sources: set[str],
) -> None:
    """Patch the per-IOC result dict with the VT→OTX failover annotation.

    Called only when ``core.http`` has flagged ``virustotal`` as rate-
    limited during the just-completed fan-out, failover is enabled, and
    the IOC type overlaps with OTX coverage.

    Behaviour:

    * If OTX wasn't in the planned task list, run it synchronously now
      and stuff the result into ``results`` / ``scores`` as if it had
      been there all along (so the rest of the composite formula sees a
      uniform shape).
    * Stamp a ``fallback_used`` field on the ``VirusTotal`` entry — even
      when VT had no entry (its fetcher returned ``None``), so the
      analyst can see that we *tried* and substituted. In that case we
      synthesise a minimal placeholder entry under the ``VirusTotal``
      key whose ``data`` is just the annotation.

    The function is deliberately silent on failure: any exception from
    the synchronous OTX call collapses to a no-op so the orchestrator's
    never-crash contract holds.
    """
    # 1) Make sure OTX ran. If not, run it inline now.
    if 'otx' not in planned_sources:
        try:
            otx_result = _run_source(
                ioc_id, 'otx', 'OTX',
                lambda: otx.enrich(value, ioc_type),
                score.calculate_otx_score,
            )
        except Exception:
            otx_result = None
        if otx_result is not None:
            display_name, data, src_score, contributes = otx_result
            results[display_name] = {'score': src_score, 'data': data}
            if contributes:
                scores.append((display_name, src_score))
        planned_sources.add('otx')

    # 2) Annotate the VT entry. If VT silently dropped (no row in
    #    results), create a placeholder so the annotation is visible.
    vt_entry = results.get('VirusTotal')
    if vt_entry is None:
        results['VirusTotal'] = {
            'score': 0,
            'data': {'rate_limited': True, 'fallback_used': 'otx'},
        }
    else:
        existing_data = vt_entry.get('data')
        if isinstance(existing_data, dict):
            existing_data['fallback_used'] = 'otx'
        else:
            # Defensive: shouldn't happen for VT, but if `data` is non-dict
            # we attach the annotation alongside it without clobbering.
            vt_entry['data'] = {
                'value': existing_data,
                'fallback_used': 'otx',
            }


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
    # Opportunistic cache janitor — bounded to one age-prune per process per
    # workspace per day. Silent on failure so this can't break enrichment.
    maybe_auto_prune()

    no_cache_token = no_cache_ctx.set(no_cache) if no_cache else None
    # Fresh rate-limit ledger for this fan-out. Any module hitting a 429
    # via core.http will record its source key here; the failover hook
    # in _enrich_ioc_inner reads the ledger after gather.
    ledger_token = http.rate_limited_ctx.set(set())
    try:
        return await _enrich_ioc_inner(value, ioc_type)
    finally:
        http.rate_limited_ctx.reset(ledger_token)
        if no_cache_token is not None:
            no_cache_ctx.reset(no_cache_token)


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
    # Track which source keys are already in the planned fan-out so the
    # post-gather failover hook can tell "OTX already ran normally" from
    # "OTX needs to be added because VT 429'd and OTX wasn't planned".
    planned_sources: set[str] = set()

    # --- VirusTotal — all IOC types ---
    tasks.append(asyncio.to_thread(
        _run_source, ioc_id, 'virustotal', 'VirusTotal',
        _vt_fetcher(value, ioc_type), _vt_scorer,
    ))
    planned_sources.add('virustotal')

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

    # --- Reverse DNS (PTR) — IP only (info-only, stdlib lookup) ---
    if ioc_type == 'ip':
        tasks.append(asyncio.to_thread(
            _run_source, ioc_id, 'rdns', 'rDNS',
            lambda: rdns.enrich_ip(value),
            None,
            info_only=True,
        ))

    # --- Passive DNS first-seen / IP age — IP only (info-only, Mnemonic free) ---
    # ``pdns.enrich_ip`` returns ``{}`` on soft-fail; treat that as no-data
    # so we don't persist a blank row that re-triggers a fetch each call.
    if ioc_type == 'ip':
        tasks.append(asyncio.to_thread(
            _run_source, ioc_id, 'pdns', 'PDNS',
            lambda: pdns.enrich_ip(value),
            score.calculate_pdns_score,
            info_only=True,
            cache_filter=_shodan_filter,
        ))

    # --- Censys Hosts v2 — IP only (info-only; deeper banners, JARM, cert chain, OS) ---
    if ioc_type == 'ip':
        tasks.append(asyncio.to_thread(
            _run_source, ioc_id, 'censys', 'Censys',
            lambda: censys.host_lookup(value),
            None,
            info_only=True,
            cache_filter=_shodan_filter,
        ))

    # --- AbstractAPI — IP only (anonymisation flags) ---
    if ioc_type == 'ip':
        tasks.append(asyncio.to_thread(
            _run_source, ioc_id, 'abstract', 'AbstractAPI',
            lambda: abstract_api.enrich_ip(value),
            score.calculate_abstract_score,
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
        planned_sources.add('otx')

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

    # --- ASN enrichment via bgpview.io (info-only score) ---
    if ioc_type == 'asn':
        tasks.append(asyncio.to_thread(
            _run_source, ioc_id, 'asn_bgpview', 'ASN',
            lambda: asn_mod.enrich(value),
            score.calculate_asn_score,
            info_only=True,
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
    scores: list[tuple[str, int]] = []
    for item in raw_results:
        if isinstance(item, BaseException):
            # Source crashed in the thread — swallow per the never-crash contract.
            continue
        if item is None:
            continue
        display_name, data, src_score, contributes = item
        results[display_name] = {'score': src_score, 'data': data}
        if contributes:
            scores.append((display_name, src_score))

    # ---------------------------------------------------------------------
    # Provider failover hook — VT 429 → OTX
    # ---------------------------------------------------------------------
    # If VT got throttled (recorded in the rate-limit ledger by core.http)
    # AND failover is enabled AND the IOC type is one OTX covers, run OTX
    # synchronously now (if it wasn't already planned) and annotate the VT
    # result dict with the fallback source.  Purely additive: does NOT
    # touch the score that feeds calculate_final_risk.
    if (
        _failover_enabled()
        and ioc_type in _OTX_FAILOVER_TYPES
        and http.was_rate_limited('virustotal')
    ):
        _apply_vt_otx_failover(value, ioc_type, ioc_id, results, scores, planned_sources)

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

        tld = heuristics.tld_check(value)
        if tld is not None:
            heuristics_data['tld'] = tld
            heuristics_scores.append(tld['score'])

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
            scores.append(('Heuristics', composite))

    final_score = score.calculate_final_risk(scores)
    # Stamp the latest composite onto the iocs row — drives watch-mode
    # delta detection. Cheap UPDATE, fire-and-forget; failures are ignored
    # by the database layer so this never blocks a return.
    with contextlib.suppress(Exception):
        database.update_last_score(ioc_id, final_score)
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

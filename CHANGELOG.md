# Changelog

All notable changes to ShadowScope. Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Your own blocklist and allowlist.** New LISTS tab (`g l`) and
  `+ BLOCK` / `+ ALLOW` on the Enrich analyst bar. Entries are exact
  indicators, CIDR ranges, or domains (which cover their subdomains), stored
  locally and applied without a restart. A blocklist match adds a
  `Blocklist` source scoring 100 at full weight; an allowlist match skips
  every lookup and scores 0, like the env allowlist (which is unchanged).
  The most specific entry wins; on a tie the blocklist does. Cached
  indicators reflect list changes immediately.
  `GET/POST /api/ui/lists`, `DELETE /api/ui/lists/{id}`.
- **Reports.** One indicator (Enrich view → REPORT) or a whole case (Cases
  tab) as Markdown, or as a clean printable page whose button leads to the
  browser's Save as PDF — no PDF library involved. An indicator report
  holds score, verdict, case, tags, notes, per-source scores, timeline and
  related indicators; a case report a summary table plus a section per
  member. Indicators are always defanged and all source text is escaped.
  `GET /api/ui/report`, `GET /api/ui/cases/{case}/report` (`format=md|html`).
- **Import with details.** The Batch tab's add box gains PREVIEW IMPORT for
  STIX 2.x JSON (indicator patterns, observables, vulnerabilities; names and
  descriptions become notes, labels and whatever an indicator `indicates`
  become tags), CSV with a header (`ioc` / `indicator` / `ip` / `domain` /
  `url` / `hash` …, optional `case`, `tags`, `note`, `verdict`) and plain
  text, up to 2 MB / 2000 indicators. The preview shows what was found;
  then IMPORT ONLY stores everything locally with no lookups, or IMPORT +
  ENRICH also looks up the first 200. Re-importing a file duplicates
  nothing and never overwrites an existing verdict.
  `POST /api/ui/import/preview`, `POST /api/ui/import/apply`.
- **Timeline per indicator.** The Enrich view gains a TIMELINE block: one
  newest-first list mixing what sources reported (registered, first/last
  seen, listed, certificate issued, CVE published, KEV added, upcoming
  expiry) with what happened locally (first enriched, each score change,
  verdicts, notes, case/tag assignments, watchlist). Kinds can be toggled;
  two sources reporting the same fact on the same day are one row.
  `GET /api/ui/timeline` — cache-only.
- **Search tab** (`g f`). One box over everything stored locally:
  indicator values, verdicts, notes, cases, tags, malware families and the
  full text of cached source answers (`deep`, on by default). Words are
  ANDed, `"quoted phrases"` stay together, defanged input is understood, and
  every row says where it matched. Filters: type, minimum score, verdict,
  case, watched, has notes, last seen; sort; CSV export. Searches can be
  saved by name. `GET /api/ui/search`, `GET/POST/DELETE /api/ui/filters` —
  cache-only, no provider calls.
- **Related panel.** The Enrich view's RELATED box now answers "what else
  should I look at?" from the local cache alone (`GET /api/ui/related`, no
  provider calls): same case, same malware family, same network (announced
  prefix, else /24), same registered domain or URLs hosted on the IP, hosts
  seen with it (DNS records, reverse DNS, passive DNS), subdomains from
  certificates, shared tags, same registrar. Indicators already enriched
  show their score and open for free; hosts only named in the data are
  marked NEW and enrich on click.
- **Analyst workflow.** Per indicator: a manual verdict (malicious /
  suspicious / benign / false positive) stored beside the score and never
  altering it, free notes, and a watch switch. **Cases tab**: create, close
  / reopen, rename, describe, export as defanged Markdown; empty cases are
  listed. **Watch tab**: a real watchlist with a per-indicator alert
  threshold and `CHECK NOW` (fresh re-check one at a time; degraded runs are
  shown but never compared); the old list is kept below as HISTORY.
- **Batch tab: paste or drop a list.** `+ ADD INDICATORS` opens a box that
  takes one indicator per line or any text (log, email, report) and a
  dropped/selected file. New `POST /api/ui/extract` pulls the indicators out
  (off the event loop, 256 KB / 200-indicator caps, CVE ids and AS numbers
  included) and the tab enriches them three at a time with a progress bar,
  a STOP button and failed/degraded counts. Degraded rows get a marker.
  `EXPORT .csv` now works (it had no handler) and neutralises formula cells.
- **Wide-screen Enrich layout (>= 1600 px).** The source attribution table
  moves into the hero's right column: spider and map sit side by side with
  the table directly beneath (beside the spider for non-IP types), so the
  verdict evidence is visible without scrolling. Below 1600 px nothing
  changes. Static asset version bumped to `?v=121`.
- **Retry failed sources** button on the degraded banner. A plain re-enrich
  serves sources that answered from the 24 h cache and refetches only the
  unavailable ones, so no quota is spent twice; the MCP `enrich_ioc` docstring
  tells agents the same.

### Fixed

- **Rate limits starved small batches.** URLhaus and ThreatFox were
  configured as daily list downloads (4 / hour) although they are per-IOC
  query APIs, and URLscan, IPQS, OTX, Pulsedive, PDNS and MalwareBazaar were
  set well under their free tiers — a 10-IP run marked them unavailable.
- **Dashboard showed things the API did not say.** Degraded results now carry
  a visible banner naming each unavailable source and its reason, the spider
  marks those axes `n/a` instead of "no hit", and the attribution header
  counts answered vs unavailable. The "fetched" column uses the real cache
  timestamp per source (new `modules[*].fetched_at`) instead of a string
  hash. The score-delta chip only appears on an actual change and no longer
  draws an invented 7-day sparkline; the empty history state explains why
  degraded runs are not recorded.
- **Consensus contradicted the score.** Context-only sources (Censys, rDNS,
  PDNS, ASN joined Shodan/IPinfo/crt.sh) left the denominator and a source
  now "flags" at 40+ rather than at any non-zero score.
- **GreyNoise `suspicious`** scored 0; now 50.
- **Diff tab** never rendered (defaulted to two ids that do not exist).
- **Batch tab** listed only the 8-row recent strip; it now lists the cache.
- **Watch tab** timestamps had no date. NVD showed "anonymous" with a key set.

## [1.1.0] — 2026-11-10

### Added

- **Windows installer** — `scripts/install-windows.ps1` / `install-windows.cmd`:
  per-user, no admin. venv + `shadowscope.exe` launcher on the user PATH,
  `.env` created from the template (placeholders blanked, ACL restricted to
  the current user), `-DryRun`, `-Uninstall [-Purge]`. Windows CI job.
- **`SHADOWSCOPE_HOME`** + per-user config/data dir for installed copies
  (`core/paths.py`). Source checkouts and Docker keep `ioc_tool/.env` +
  `ioc_tool/data/`. Migration: a copy previously pip-installed into
  `site-packages` kept its cache in `site-packages/ioc_tool/data/`; move
  `ioc.db` to the new per-user `data/` dir to keep history.

- **MCP server** — `shadowscope-mcp` (`pip install "shadowscope[mcp]"`,
  `ioc_tool/mcp_server.py`) exposes `enrich_ioc`, `enrich_many`,
  `extract_and_enrich`, `show_cached`, `list_sources`, `cache_stats` over
  stdio for Claude Code and other MCP clients. Runs the orchestrator
  in-process against the same `.env` + SQLite cache as the CLI; no REST
  server needed. Register with
  `claude mcp add --scope user shadowscope -- shadowscope-mcp`.

### Changed

- **Scoring calibration.** VirusTotal scores the detection **count**
  (`>=3 → 65`, `>=6 → 85`, `>=20 → 95`, `suspicious` at half weight)
  instead of `malicious / total_engines`, which rendered a 5/94 verdict
  as a 5. EPSS takes `max(probability, percentile_bucket)` — raw EPSS
  probabilities are tiny by construction, so the 90th percentile used to
  score 3. The `Heuristics` composite keeps its strongest sub-signal
  rather than averaging them.
  **These change existing scores**; `final_score` values stored before
  this release are not comparable with new ones.

- **One version string.** `ioc_tool.__version__` (1.1.0) is the single
  source: `pyproject` reads it dynamically, `/` and `/health` return it, and
  `/ui` injects it as `window.SHADOWSCOPE_VERSION` so the dashboard badge no
  longer hard-codes `v0.9.2`.
- **Dependency pins**: `requests` 2.32.5 → 2.33.0 (PYSEC-2026-2275),
  `python-dotenv` 1.2.1 → 1.2.2 (PYSEC-2026-2270) — both surfaced by the new
  `pip-audit` job; `pytest` 9.0.2 → 9.0.3.
- **CI hardening.** `permissions: contents: read`; actions pinned to commit
  SHAs; matrix adds Python 3.13 and 3.14; new `install-smoke` job
  (`pip install ".[mcp]"`, console scripts, version parity) and an advisory
  `pip-audit` job. `.github/dependabot.yml` for pip + GitHub Actions.
- **Tri-state source results.** Timeout, connection error, 429, 5xx, 401/403
  and local rate-limit refusals used to collapse into "no data" — the IOC
  was scored from whatever answered and that score was persisted, so a
  throttled VT free tier produced fake "score dropped" alerts in `watch`.
  `core/http.py` now records a per-task failure ledger, `_run_source`
  returns an `Unavailable` marker instead of `None` for sources that never
  answered (incl. fetcher exceptions), and every result carries
  `degraded: bool` + `unavailable: {source: reason}`. When an opinion
  source is unavailable the composite is returned but **not** written to
  `last_score` / `score_history`; `watch` skips the delta; the CLI prints a
  warning; `/api/ui/*` and the SSE `skipped` frame expose the reason.
  WHOIS "no match" stays a no-hit; other WHOIS exceptions count as failures.
- **Composite score v2 — strongest weighted signal + corroboration** replaces
  the weighted mean (`core/score.py::calculate_final_risk`). v1 let "no data"
  zeros and weak sources drag confirmed hits down: a Tor exit with AbuseIPDB
  100 + Pulsedive 95 scored 57 "Medium", a Feodo-listed C2 14 "Safe". Now
  `final = max(score × weight) (+10 when ≥ 2 sources are ≥ 50 weighted)`,
  clamped 0–100. Results carry `score_version: 2`; `score_history` rows store
  the version so pre-v2 points are not compared with new ones. Tor weight
  0.7 → 0.5 (a lone exit node reads Medium, not High). The cache-derived
  composite used by `/show` and the dashboard recent strip now passes named
  scores, so it applies real weights instead of the 0.5 default.
- **Certificate transparency now goes to api.ctlogs.dev first** (new
  `modules/ctlogs.py`, optional `CTLOGS_API_KEY`), with crt.sh as the
  automatic fallback. ctlogs answers in ~50 ms and does not 502 on large
  zones; its free tier only covers certificates valid now or expired
  within 90 days, so `total` is a 90-day count. Same cache key / display
  name (`crt.sh`); a `provider` field and the dashboard detail string say
  which backend answered. `docker-compose.yml` now also forwards
  `PULSEDIVE_API_KEY`, `CENSYS_API_KEY`, `CTLOGS_API_KEY`.
- `requirements.txt` pins `fastapi==0.162.2` (was 0.118.0). The `mcp` extra
  on Python 3.14 needs `starlette>=0.49`, which FastAPI 0.118 rejects; the
  full suite passes unchanged on 0.162.2.

- **Brutalist React dashboard** at `/ui` — terminal-grade aesthetic
  (orange accent, dense monospace, score-coded ticker, score banner,
  tab nav: Enrich / Batch / Watch / Cases / Diff). React 18 +
  Babel-standalone in-browser. Legacy vanilla UI preserved at
  `/ui-classic`.
- **Live backend wiring** for the brutalist dashboard. New
  `GET /api/ui/enrich` endpoint synthesises the UI-shape fields
  (stable `id`, pre-computed `agreement`, per-module `detail`
  summaries, `prev_score` from `iocs.last_score`) around the raw
  orchestrator output. Frontend `window.shadowscopeFetch()` helper +
  rewired `onEnrich` flow; mock data stays as a fallback when the
  request fails.
- **Pulsedive** enrichment source (free tier; `PULSEDIVE_API_KEY` for
  higher quota). Risk-tier → 0-100 score mapping.
- **Tags + cases** — `shadowscope tag <ioc> --tag X --case Y --note Z`,
  `shadowscope cases`. New `ioc_tags` table with idempotent UNIQUE
  constraint + note upsert on conflict.
- **Watch mode** — `shadowscope watch [--case=X] [--threshold=N]
  [--webhook=URL] [--json]` re-enriches IOCs, diffs vs stored
  `last_score`, emits deltas. Cron-friendly.
- **Source agreement matrix** — `output.consensus_summary()` reports
  flagged-vs-missed across opinion sources. Markdown reports surface
  a one-line consensus tag.
- **PyPI packaging** — `pyproject.toml` ships a buildable wheel via
  `setuptools.build_meta`. Dependencies pinned, `web/static/*` and
  `data/*.json` shipped as package-data, console_scripts entry.

### Fixed

- **Offset-aware WHOIS dates silently dropped two domain signals.**
  `calculate_whois_score` and `heuristics.nrd_check` subtracted an
  offset-aware `creation_date` from a naive `datetime.now()`, raising
  `TypeError`. Raised inside a thread-pooled source, it was swallowed by
  the orchestrator's `gather(return_exceptions=True)`, so the WHOIS row
  vanished — and with it the NRD heuristic, which reads WHOIS's payload.
  Registrars returning offset-aware dates therefore had newly-registered-
  domain detection silently disabled. Naive dates are now assumed UTC.
- Wheel shipped `web/static/index.html` only — `/ui` loaded blank on any
  pip/pipx install. Package-data now globs `web/static/**/*` and includes
  `.env.example`.
- `enrich -f` crashed with `UnicodeDecodeError` on UTF-16 files (Windows
  PowerShell 5.1 `>` default) and kept a stray BOM on UTF-8-with-BOM files.
- Redirected output on Windows (`--csv > out.csv`) could raise
  `UnicodeEncodeError` under cp1252; stdio is forced to UTF-8 there.
- `.env` with a UTF-8 BOM silently dropped its first key.
- **ThreatFox scored substring matches as hits.** `search_ioc` is a substring
  search; the module took `data[0]`, so `google.com` inherited a confidence-75
  `sites.google.com/...` malware URL and scored 80. Only an entry whose IOC
  equals the query (ip:port → host, URL modulo trailing slash) counts now;
  the highest-confidence exact match is returned with a `related_hits`
  count for pivoting.
- **URLhaus, ThreatFox and MalwareBazaar were silently dead.** abuse.ch's
  query APIs have required an `Auth-Key` header since 2024 and answered
  every ShadowScope request with `401`, which the soft-fail contract
  turned into "no data". New `ABUSECH_AUTH_KEY` (one free key from
  auth.abuse.ch covers all three) is sent on every call; without it the
  three sources are skipped and `/sources` reports them as not configured
  instead of always-on.
- **CLI enriched the defanged string.** `enrich 1[.]2[.]3[.]4` classified
  the input correctly but queried every source (and keyed the cache) with
  the literal `1[.]2[.]3[.]4`, so defanged IOCs always came back "Safe".
  `parser.normalize_value` now refangs ip/domain/url/hash/email; `enrich`
  and `show` pass the normalised value. The REST API already did this.
- **IPQS never ran.** The module read `IP_QUALITY_SCORE` while every
  template/doc/compose file and `/sources` said `IPQS_API_KEY`. Documented
  name now wins; the legacy name is still honoured.
- **WHOIS errors corrupted `--json`/`--csv` output** — the module printed
  `WHOIS error: …` to stdout from a worker thread. Now stderr.
- **Four different risk-tier scales.** `show` (≥70 Critical / ≥40 Medium /
  else Low), the `enrich` table (0 Safe / <40 Low / <75 Medium / <100 High /
  100 Critical, Tor forced Critical), `core/output` and `core/llm`
  (80/60/40/20) disagreed, so a score of 65 read as Medium, Low and High
  depending on the surface. One `core.score.risk_tier()` table
  (80/60/40/20, matching `docs/ARCHITECTURE.md` and the dashboard) now
  drives all of them; Tor is shown as a flag instead of re-tiering.

- Suppress Python 3.12+ `DeprecationWarning` from the default SQLite
  `datetime` adapter by registering an explicit ISO 8601 adapter at module
  load time.

## [0.7.0] — 2026-05-15

### Added

- **Allowlist** (`ALLOWLIST_CIDRS`, `ALLOWLIST_DOMAINS`) — short-circuits
  the enrichment pipeline when an IOC matches a corp range or internal
  domain. Saves API quota on bulk enrichment of mixed logs. Domain
  matches are subdomain-aware; CIDR supports IPv4 + IPv6.

## [0.6.0] — 2026-05-15

### Added

- **Heuristics module** (`ioc_tool/core/heuristics.py`) — dependency-free,
  deterministic score amplifiers that run post-gather on already-enriched
  data. Surfaces under a single `Heuristics` pseudo-module entry.
  - **NRD flag** — newly registered domain via WHOIS `creation_date`.
    Four buckets: fresh (<7d, 95) / nrd (<30d, 75) / recent (<90d, 40) /
    mature (0).
  - **DGA detection** — Shannon entropy + uncommon-bigram fraction +
    longest-consonant-run, weighted composite. English domains 5–25, DGA
    samples 80+.
  - **Typosquat / homograph** — confusable-aware Damerau-Levenshtein vs
    `WATCHLIST_DOMAINS` env. Visual substitutions (1↔l, 0↔o, rn↔m) cost
    0 instead of 1. Confusable-only lookalikes score 95; real
    distance-1 typos score 85.
  - **IDN homograph** — decodes `xn--` punycode, flags mixed-script
    labels (Cyrillic 'а' in Latin context) at 90. Pure-script IDNs
    (испытание.com, мир.рф) score 50 (legit but worth flagging).

## [0.4.0-batch-A] — 2026-05-15

### Added

- **abuse.ch Feodo Tracker** (IP, no key) — botnet C2 blocklist
  mirrored to disk via `FEODO_LIST_TTL_HOURS` env.
- **abuse.ch SSL Blacklist** (hash, no key) — SHA-1 malicious cert
  fingerprints; short-circuits non-SHA1 inputs.
- **crt.sh** (domain, no key) — certificate-transparency search with
  subdomain enumeration + most-recent-issuance metadata.

## [0.3.0] — 2026-05-15

### Added

- **STIX 2.1 export** (`--stix`) — hand-rolled bundle with `indicator`
  SDOs. Stable `uuid5(name)` IDs (idempotent re-enrichment). Patterns
  match the OASIS 2.1 spec for IP / domain / URL / hash.
- **Markdown report** (`--md`) — case-doc with score banner, per-source
  table, heuristics bullets, optional LLM verdict block.
- **Bulk parallel** — `enrich_many{,_async}` fans out across IOCs via
  `asyncio.gather`. Wall-clock becomes `max(per-IOC)` instead of sum.
- **Pipe support** — `echo 1.2.3.4 | shadowscope enrich -` routes through
  the text-extractor pipeline.
- **`CACHE_TTL_HOURS` env** — tunable freshness window (float, fallback
  24 h). Replaces hardcoded 24 h staleness in `should_refresh`.
- **`--no-cache` flag** — bypasses the SQLite cache, forces a fresh
  fetch from every source. Propagated via `ContextVar` so per-source
  `asyncio.to_thread` workers see the flag without explicit threading.
- **Tor list staleness** — `TOR_LIST_TTL_HOURS` env (default 24 h);
  refresh on first miss or expiry; stale-on-failure fallback.
- **Punycode decode** — IDN/homograph detection in the heuristics module
  (see 0.6.0).

### Fixed

- Pre-existing bug where the human-mode CLI branch dropped `--no-cache`
  before reaching the orchestrator.

## [0.2.0] — 2026-05-15

### Added

- **`pyproject.toml`** — package metadata + ruff (E/W/F/I/B/UP/SIM) +
  mypy + pytest configuration.
- **Mypy CI step** alongside ruff + pytest on Python 3.10 / 3.11 / 3.12.
- **CI + mypy + ruff badges** in README.
- **`requirements-dev.txt`** — pinned `mypy==2.1.0` + `types-requests`.

### Changed

- Type hints sufficient for mypy clean across 37 source files
  (non-strict baseline, `ignore_missing_imports`, `whois` override).
- Ruff clean across 30 files: bare-except, unused imports/vars, trailing
  whitespace, `zip(..., strict=True)`, ternaries replacing trivial
  if/else, SIM/UP fixes.

## [0.1.0] — 2026-05-14 — Initial v1.0 ship

### Added

- Core enrichment pipeline (`enrich_ioc`, `enrich_ioc_async`) with
  parallel fan-out across 19 sources via `asyncio.to_thread` +
  `asyncio.gather`.
- Sources: VirusTotal, AbuseIPDB, Shodan, IPQualityScore, IPinfo,
  GreyNoise, URLhaus, ThreatFox, MalwareBazaar, OTX, URLscan,
  Hybrid Analysis, Joe Sandbox, FileScan.io, Tor exit list, WHOIS,
  NVD, EPSS, CISA KEV.
- IOC types: IP, domain, URL, hash (MD5/SHA1/SHA256), email, CVE.
- Defang / refang of input + output formats.
- IOC extraction from free-form text (`--text` flag).
- LLM natural-language verdict via local Ollama (`--summary` flag).
- FastAPI REST API + iframe-embeddable dashboard at `/ui`.
- Docker (multi-stage `python:3.12-slim`, non-root) + docker-compose.
- 183 offline tests using `responses` mocking.

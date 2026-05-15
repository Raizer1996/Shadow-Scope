# Changelog

All notable changes to ShadowScope. Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

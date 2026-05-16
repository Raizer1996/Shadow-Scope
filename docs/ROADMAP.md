# ShadowScope — Roadmap

Public backlog. Items marked **[issue]** will be promoted to GitHub Issues with milestone labels once the repo is pushed.

Organized by **release milestone** (foundational → expansion → polish) and by **category** within each.

---

## v0.2 — Quality + Speed (foundations) ✅

### Engineering
- [x] **Type hints + mypy clean** on public functions — mypy passes on 36 source files (non-strict baseline, ignore_missing_imports)
- [x] **GitHub Actions CI matrix** — ruff lint + mypy + pytest on py3.10/3.11/3.12; `pyproject.toml` with ruff (E/W/F/I/B/UP/SIM) + mypy config; CI/mypy/ruff badges in README

---

## v0.3 — Output + Bulk (analyst usability)

### Output formats
- [x] **STIX 2.1 export** (`--stix`) — hand-rolled bundle with indicator SDOs (stable uuid5 IDs, score-mapped indicator_types, ShadowScope labels)
- [x] **Markdown report** (`--md`) — case-doc with score banner, per-source table, heuristics block, optional LLM verdict
- [ ] ~~**PDF report** (`--pdf`)~~ — dropped as not relevant for current users (use `--md` and render to PDF externally if needed).

### Bulk + I/O
- [x] **Bulk mode** (`-f iocs.txt`) — parallel fan-out across IOCs via `enrich_many` / `enrich_many_async` (asyncio.gather over per-IOC tasks)
- [x] **Pipe support** (`echo 1.2.3.4 | shadowscope enrich -`) — stdin sentinel routes through the text-extractor pipeline
- [x] **Punycode decode** — `idn_check` in heuristics module: decodes `xn--` labels, flags mixed-script homograph (Cyrillic 'а' in Latin context = 90, pure-script IDN = 50)

### Cache / freshness
- [x] **Configurable cache TTL** — env `CACHE_TTL_HOURS` (float supported, fallback 24 h)
- [x] **Tor list auto-refresh** — staleness check via file mtime + `TOR_LIST_TTL_HOURS` env (default 24 h); refresh on first miss or expiry
- [x] **Force refresh flag** — `--no-cache` CLI flag + `enrich_ioc(no_cache=)` kwarg, propagated via `ContextVar`
- [x] **Cache retention & cleanup** — `enrichments` rows no longer grow forever. New `RETENTION_DAYS` env (default 90 d) drives an opportunistic auto-prune janitor (one age-prune per process per workspace per 24 h; opt-out via `AUTO_PRUNE=0`). New `shadowscope cache {stats,prune,clear}` CLI for manual inspection and explicit wipes — `prune --older-than 30d|12h|...` with optional `--keep-last N` per (ioc, source); `clear --source X | --ioc Y | --all` (exactly one filter, `--yes` skips the confirm). New `meta` key/value table holds the last-prune timestamp (2026-05-16)

---

## v0.4 — New Sources (intel breadth)

### Free / freemium IOC sources
- [x] **abuse.ch Feodo Tracker** — botnet C2 IP blocklist, mirrored to disk with `FEODO_LIST_TTL_HOURS` env (default 24 h); scored 95 online / 70 offline
- [x] **abuse.ch SSL Blacklist** — SHA-1 cert fingerprints, mirrored to disk; short-circuits non-SHA1 inputs; hit → 95
- [x] **crt.sh certificate transparency** — subdomain enumeration + recent-issuance metadata; info-only score (15 ≥100 certs, 30 ≥1000)
- [ ] **SecurityTrails** — passive DNS, historical WHOIS, subdomain enum. **[issue]**
- [x] **Pulsedive** — free aggregator, anonymous tier works; optional `PULSEDIVE_API_KEY` unlocks higher quota; risk-tier mapped to 0-100 (critical=95, high=80, medium=55, low=25)
- [ ] **IBM X-Force Exchange** — free tier reputation. **[issue]**
- [ ] **Cisco Talos** — IP/domain reputation. **[issue]**
- [ ] **Censys** — alternative to Shodan, free academic tier. **[issue]**
- [ ] **DNSDB / Farsight passive DNS** *(paid — optional)*. **[issue]**

### New IOC types
- [ ] **Email** — EmailRep, HaveIBeenPwned breach check. **[issue]**
- [x] **ASN** — `AS12345` / `ASN12345` / `as12345` recognised as new IOC type. Enriched via bgpview.io free API: name, country, RIR, allocation date, traffic estimation, email/abuse contacts. Info-only score (doesn't push composite tier — analysts read fields directly).
- [ ] **Bitcoin / crypto wallet** — OFAC sanctions list, basic chain analytics. **[issue]**
- [ ] **TLS fingerprint** — JA3 / JA3S matching against known-bad lists. **[issue]**
- [ ] **YARA hash match** — auto-detect malware family from sample/hash. **[issue]**

---

## v0.5 — Sandboxing & Detection Rule Generation

### Sandbox expansion
- [ ] **ANY.RUN** integration. **[issue]**
- [ ] **Hatching Triage** — fast, free academic tier. **[issue]**
- [ ] **Cuckoo Sandbox** (local instance). **[issue]**
- [ ] **VMRay** *(commercial — optional)*. **[issue]**

### Auto-generated detection content
- [ ] **Sigma rule** from enriched IOC. **[issue]**
- [ ] **YARA rule** from sample hash + sandbox strings. **[issue]**
- [ ] **Snort / Suricata rule** from network IOC. **[issue]**
- [ ] **Splunk SPL search** template. **[issue]**
- [ ] **KQL search** for Microsoft Sentinel. **[issue]**
- [ ] **Elastic detection query**. **[issue]**

---

## v0.6 — Smart Features (analyst intelligence)

- [x] **DGA detection** — entropy + bigram improbability + consonant-run scoring (domain IOCs)
- [x] **NRD flag** — newly registered domain via WHOIS creation_date → 4 buckets (fresh/nrd/recent/mature)
- [x] **Typosquatting / homograph detection** — confusable-aware Damerau-Levenshtein vs `WATCHLIST_DOMAINS` env (rn→m, 1→l, 0→o, etc.)
- [ ] **Pivot suggestions** — given IP, surface related domains via PDNS / cert overlap. **[issue]**
- [ ] **Reverse DNS** lookup on every IP. **[issue]**
- [ ] **Suspicious TLD scoring** — `.tk / .top / .xyz / .surf` bump. **[issue]**
- [ ] **First-seen / IP age** from PDNS data. **[issue]**
<!-- Moved to Done 2026-05-14 — LLM summary (local Ollama, --summary flag) -->

- [ ] **Auto-tag with MITRE ATT&CK** technique mapping based on observed behavior. **[issue]**

---

## v0.7 — Case Management & Workflow

- [x] **Tags + cases** — `shadowscope tag <ioc> --tag=phishing --case=campaign-x --note="ATO landing"`, `shadowscope cases [--case=name]`. New `ioc_tags` table; idempotent under UNIQUE constraint; remove via `--remove`.
- [x] **Notes per IOC** — `--note` flag on `tag` subcommand upserts on conflict.
- [x] **History view** — `shadowscope history <ioc> [--source X]` shows every cached enrichment per source with a Unicode-block sparkline of score progression.
- [x] **Allowlist** — `ALLOWLIST_CIDRS` + `ALLOWLIST_DOMAINS` env vars short-circuit the enrichment pipeline for org-internal IPs / domains / URLs (subdomain-aware, IPv4+IPv6 CIDR support)
- [x] **Watch mode** — `shadowscope watch [--case=name] [--threshold=N] [--webhook=URL] [--json]` re-enriches every IOC (or just one case), diffs vs stored `last_score`, emits deltas above the threshold to stdout / webhook. Cron-friendly with `--json` (one event per line).
- [x] **Multiple workspaces** — `--workspace=name` flag (or `SHADOWSCOPE_WORKSPACE` env) routes the SQLite cache + tags + history at `ioc_tool/data/ioc-<name>.db`. Default workspace stays at `ioc.db` for backwards compat. `shadowscope workspaces` lists every DB on disk with row counts.
- [x] **Compare two IOCs** — `shadowscope diff <ioc1> <ioc2>` side-by-side module-score table with per-source delta column.
- [x] **Risk score history graph** — Unicode-block sparkline column inside the `history` subcommand (9-level bucketing, 0-100 → ` ▁▂▃▄▅▆▇█`).
- [x] **Source agreement matrix** — `consensus_summary()` in output module: counts flagged vs missed across opinion sources (excludes Shodan / IPinfo / crt.sh / Heuristics / Allowlist); 4-tier consensus (high ≥70%, medium ≥40%, low >0, none); surfaces in Markdown reports

---

## v0.8 — Integrations (push to your stack)

### Case management
- [ ] **TheHive + Cortex** — push enriched IOC as observable + run as Cortex analyzer. **[issue]**
- [ ] **MISP** — push attribute to event. **[issue]**
- [ ] **ServiceNow** — open incident ticket from Critical score. **[issue]**

### SIEM / log pipelines
- [ ] **Splunk HEC** forwarder. **[issue]**
- [ ] **Elastic / Logstash** output. **[issue]**
- [ ] **Generic webhook** — JSON POST to any URL. **[issue]**

### Chat / notification
- [ ] **Telegram bot** — alert on Critical (hooks into existing homelab Telegram). **[issue]**
- [ ] **Slack bot** — slash command `/scope 1.2.3.4`. **[issue]**
- [ ] **Discord bot**. **[issue]**
- [ ] **Email report** (SMTP). **[issue]**

---

## v0.9 — UI Surfaces

- [ ] **GraphQL API** *(optional)*. **[issue]**
- [ ] **TUI** — full-screen terminal UI with `textual`. **[issue]**
- [ ] **Browser extension** — right-click any IP/domain → enrich popup. **[issue]**
- [ ] **VS Code extension** — hover any IP in code/logs → tooltip with score. **[issue]**
- [ ] **Burp Suite extension** — enrich findings inline. **[issue]**

---

## v1.0 — Packaging & Distribution

- [x] **PyPI package** — `pyproject.toml` ships a buildable wheel via `setuptools.build_meta`: dependencies pinned (`requests`, `rich`, `python-dotenv`, `python-whois`, `fastapi`, `uvicorn[standard]`), optional `dev` extras, package-data carries `web/static/*` and `data/*.json`, console_scripts entry `shadowscope = ioc_tool.main:main`. Verified locally: 100 KB wheel, 24 modules, entry point + static files included. Upload to PyPI is a separate `twine upload` step.
- [ ] **pipx install** docs — straightforward once on PyPI: `pipx install shadowscope`.
<!-- Moved to Done 2026-05-14 — Docker image (multi-stage python:3.12-slim, non-root, healthcheck) -->
<!-- Moved to Done 2026-05-14 — Docker Compose stack (Redis backend deferred — single-container SQLite is sufficient for current scale) -->
- [ ] **Kubernetes Helm chart**. **[issue]**
- [ ] **Demo GIF / asciinema** in README. **[issue]**
- [x] **SemVer + CHANGELOG.md** — Keep-a-Changelog format documenting v0.1 → v0.7

---

## v1.1+ — Architecture / scaling

- [ ] **Redis cache backend** (replaces SQLite for multi-process / API server mode). **[issue]**
- [ ] **PostgreSQL backend** (long-term history, multi-user). **[issue]**
- [ ] **Celery / RQ task queue** for distributed enrichment. **[issue]**
- [ ] **Plugin loader** — auto-discover `ioc_tool/modules/*.py` via `importlib`; no edits to `enrich.py` needed. **[issue]**
- [ ] **Per-source rate-limit handler** — token bucket; back off on 429. **[issue]**
- [ ] **Provider failover / fallback** — if VT 429s, fall back to AlienVault OTX. **[issue]**

---

## v1.2+ — Security hardening

- [ ] **Encrypt cache DB** — sqlcipher / PostgreSQL TDE. **[issue]**
- [ ] **TOR / proxy outbound** — anonymize source IP when querying suspicious actors' infra. **[issue]**
- [ ] **HashiCorp Vault** integration for key storage. **[issue]**
- [ ] **Audit log** — who queried what, when, from where (for shared instances). **[issue]**
- [ ] **API key rotation reminder** — flag keys older than N days. **[issue]**
- [ ] **TLP marking** on output (TLP:WHITE / GREEN / AMBER / RED). **[issue]**
- [ ] **SAML / SSO** for web dashboard mode. **[issue]**

---

## 🎯 High-priority subset (recommended first beyond v0.2)

If pursuing one milestone at a time, these give the biggest SOC bang-per-buck:

1. **abuse.ch suite** (URLhaus + ThreatFox + MalwareBazaar) — no API key, fresh feeds
2. **GreyNoise** — instant FP killer for IP triage
3. **URLscan.io** — phishing-case gold
4. **IOC defang/refang + paste-text extraction** — daily-driver UX win
5. **JSON output + Telegram alert** — wires ShadowScope into existing homelab stack
6. **CVE + EPSS + KEV** — covers vuln triage, not just IOC enrichment

---

## Done

- [x] Repo hygiene — gitignore binaries / cache / debug scripts (2026-05-14)
- [x] `.env.example` ↔ README sync (2026-05-14)
- [x] GitHub-ready docs scaffold — CLAUDE.md, docs/, LICENSE, CONTRIBUTING, CI workflow, smoke tests (2026-05-14)
- [x] Full feature backlog brainstormed and structured (2026-05-14)
- [x] Argparse subcommands — `enrich`, `analyze`, `shodan`, `show` replace `-1/-2/-3` (2026-05-14)
- [x] Pinned `requirements.txt` versions + added `requirements-dev.txt` (pytest, ruff, responses) (2026-05-14)
- [x] IOC defang / refang — auto-refang input in parser, optional `--defang` flag for output (2026-05-14)
- [x] Pytest mocking — `responses` lib intercepts every module HTTP call; tests run offline in <1 s (2026-05-14)
- [x] JSON output (`--json`) for SIEM ingest (2026-05-14)
- [x] CSV output (`--csv`) for spreadsheet handoff (2026-05-14)
- [x] IOC extraction from text — `enrich --text "blob"` / `enrich -` pipe-mode pulls IPs/domains/URLs/hashes/emails from prose and enriches each (2026-05-14)
- [x] abuse.ch URLhaus — malicious URL / host enrichment, no API key required (2026-05-14)
- [x] GreyNoise — Community API IP classification (noise vs targeted, huge SOC FP killer) (2026-05-14)
- [x] abuse.ch ThreatFox — fresh IOC feed across IP/domain/URL/hash, no API key required (2026-05-14)
- [x] abuse.ch MalwareBazaar — hash → sample + malware family classification, no API key required (2026-05-14)
- [x] AlienVault OTX — community pulse / threat-actor reports across IP/domain/URL/hash (free API key) (2026-05-14)
- [x] URLscan.io — historical scan search (screenshots + verdicts) across IP/domain/URL, optional free API key (2026-05-14)
- [x] Async enrichment — `core.enrich` now runs every applicable source in parallel. Implemented via `asyncio.to_thread()` — modules stay sync, parallelism via thread-pool gather (zero module rewrites, all 119 existing tests stay green). ~9× wall-clock speedup on multi-source IP queries (2026-05-14)
- [x] REST API server — `shadowscope serve` exposes enrichment as HTTP via FastAPI + uvicorn. Endpoints: `/`, `/health`, `/enrich`, `/enrich/bulk` (concurrent), `/extract`, `/show`, `/sources`. Bearer-token auth via `SHADOWSCOPE_API_TOKEN` (off when unset), configurable CORS via `SHADOWSCOPE_CORS_ORIGINS`. Thin layer over `enrich_ioc_async` — zero core changes (2026-05-14)
- [x] Web dashboard — minimal terminal-themed HTML/CSS/JS at `/ui`, served from `ioc_tool/web/static/`. Single-page, no SPA framework, no build step, no CDN deps. Auto-classifies input (single IOC / bulk list / prose blob → `/enrich`, `/enrich/bulk`, `/extract`). Drill-down per-source details, color-coded risk tiers, live `/sources` panel. Token via `?token=<v>` query string for iframe embeds — in-memory only, never persisted. Iframe-embeddable into homelab secops dashboard (2026-05-14)
- [x] CVE IOC type — NVD CVSS v3.1 + EPSS exploit probability + CISA KEV (Known Exploited Vulnerabilities) catalog. New `cve` type in `parser.detect_type` (uppercase-canonicalised), three new modules (`nvd.py`, `epss.py`, `kev.py`), KEV catalog cached daily at `ioc_tool/data/cisa_kev.json`, six new CSV columns (`nvd_cvss`, `nvd_severity`, `epss_score`, `epss_percentile`, `kev_in_catalog`, `kev_ransomware`). No new API keys required (2026-05-14)
- [x] **LLM summary** — natural-language 2-3 sentence verdict via local Ollama. New `ioc_tool/core/llm.py` (model-agnostic `_build_prompt` + `summarize`), top-level `--summary` CLI flag (works on `enrich` and `show`, plus JSON/CSV output), `?summary=true` query param on `/enrich`, `/enrich/bulk`, `/extract`. Bulk summarisation parallelised via `asyncio.to_thread`. Configurable via env `OLLAMA_BASE_URL` (default `http://localhost:11434`) + `OLLAMA_MODEL` (default `llama3.2`). Optional feature — Ollama unreachable → `summarize()` returns `None`, ShadowScope keeps working. Dashboard exposes a global "Include LLM verdict" checkbox; verdicts render below each row (2026-05-14)
- [x] **Docker image** — multi-stage `python:3.12-slim` Dockerfile at repo root, runs as non-root `shadowscope` user, stdlib `/health` healthcheck, EXPOSE 8765. `.dockerignore` ships only `ioc_tool/` + `requirements.txt`. Default `CMD` launches the FastAPI server (2026-05-14)
- [x] **Docker Compose stack** — `docker-compose.yml` at repo root with a single `shadowscope` service, `shadowscope-data` named volume persisting `/app/ioc_tool/data` (SQLite cache + CISA KEV snapshot), env passthrough for every API key + auth/CORS, `host.docker.internal:host-gateway` extra_host so the container reaches the host's Ollama on Linux. Redis backend deferred — single-container SQLite is sufficient for current scale (2026-05-14)

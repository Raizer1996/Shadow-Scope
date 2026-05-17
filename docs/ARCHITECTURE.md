# ShadowScope — Architecture

> Single source of truth. Update with every change. Commit with the work.

## Overview

ShadowScope is a terminal-based IOC enrichment and risk-scoring tool. It accepts an Indicator of Compromise (IP, domain, URL, or file hash), fans out queries to multiple threat-intelligence sources **in parallel**, caches results in SQLite, and produces a composite risk score plus a rich terminal report.

## High-level data flow

```
            ┌──────────────┐
   user ───▶│ ioc_tool.ui  │  (CLI / interactive menu)
            │   cli.py     │
            └──────┬───────┘
                   │ value, ioc_type
                   ▼
            ┌──────────────┐
            │ core.parser  │  detect type (ip / domain / url / hash)
            └──────┬───────┘
                   ▼
            ┌──────────────┐         cache hit?
            │ core.enrich  │◀───────▶ core.database (SQLite, 24h TTL)
            └──────┬───────┘
                   │  asyncio.gather(*[asyncio.to_thread(source) ...])
                   │  ┌───────────┬───────────┬───────────┬──────────┐
                   ▼  ▼           ▼           ▼           ▼          ▼
              modules.vt  abuseipdb   shodan_mod   ipqs    ipinfo_mod  whois_mod
              greynoise   urlhaus     threatfox    otx     urlscan     malwarebazaar
              tor                                                      filescan_io / hybrid_analysis / joe_sandbox
                   │
                   ▼
            ┌──────────────┐
            │  core.score  │  composite risk 0-100
            └──────┬───────┘
                   │
                   │   (optional, --summary / ?summary=true)
                   │   ┌──────────────┐
                   ├──▶│  core.llm    │──▶ POST localhost:11434/api/generate (Ollama)
                   │   └──────┬───────┘    → 2-3 sentence verdict (None on failure)
                   ▼          ▼
            ┌──────────────┐
            │  ui.cli      │  render table + score banner [+ LLM verdict panel]
            └──────────────┘
```

## Concurrency model

Every enrichment source is an independent, blocking `requests` call (~500–2000 ms each). `core.enrich.enrich_ioc_async` dispatches each applicable source as an `asyncio.to_thread(...)` task, then awaits the full batch with `asyncio.gather(return_exceptions=True)`. Wall-clock time becomes roughly `max(per-source latency)` instead of the sum — measured ~9× speedup on a 10-source IP query in a synthetic 200 ms-per-source benchmark.

The modules stay sync (`requests`-based) on purpose. Switching to `aiohttp` would force rewriting every `ioc_tool/modules/*.py`, break the `responses`-mocking test suite, and add `aioresponses` as a dev dep — all for the same wall-clock outcome on this many calls. The thread-pool approach gives the same parallelism with zero module changes.

`enrich_ioc(value, ioc_type)` is preserved as a sync wrapper (it calls `asyncio.run(enrich_ioc_async(...))` internally) so every existing call site stays unchanged. The 24 h per-source cache pattern via `core.database.get_latest_enrichment` / `add_enrichment` is preserved — each thread checks its own cache row before issuing the network call, and `sqlite3.connect()` is opened per-call so each thread gets its own connection.

Per-source exceptions are caught at the gather layer (`return_exceptions=True`) and silently dropped, matching the existing "API failures return `None` — never crash the CLI" contract.

**Provider failover (VT → OTX).** `core/http.py` keeps a per-task `rate_limited_ctx` ContextVar; when an upstream returns a 429 we can't escape via retry (or our own token bucket refuses), the helper records the source key in that ledger. After the fan-out completes, `core/enrich._apply_vt_otx_failover` checks the ledger — if `virustotal` is flagged and the IOC type is IP/domain/hash, the VT result entry is stamped with `fallback_used: 'otx'` (synthesising a placeholder if VT returned `None`), and OTX is invoked synchronously when it wasn't already in the planned task list. The annotation is transparency-only and does not feed into `calculate_final_risk`. Set `SHADOWSCOPE_FAILOVER_DISABLE=1` to disable.

## Module map

| Path | Purpose |
|------|---------|
| `ioc_tool/main.py` | Entry point: loads `.env`, hands off to `ui.cli.main()` |
| `ioc_tool/ui/cli.py` | Interactive menu + arg-flag shortcuts (`-1/-2/-3`) |
| `ioc_tool/ui/banner.py` | "Sniper Scope" ASCII art + colors |
| `ioc_tool/core/parser.py` | Detect IOC type from string |
| `ioc_tool/core/defang.py` | Defang/refang IOC strings |
| `ioc_tool/core/extractor.py` | Extract IOCs from arbitrary text blobs |
| `ioc_tool/core/enrich.py` | Orchestrate per-source enrichment + cache lookups |
| `ioc_tool/core/database.py` | SQLite wrapper (IOCs + enrichments tables) |
| `ioc_tool/core/score.py` | Per-source scoring + composite risk avg |
| `ioc_tool/core/output.py` | JSON/CSV serializers for results |
| `ioc_tool/core/llm.py` | LLM-generated natural-language verdict via local Ollama (optional, `--summary` / `?summary=true`) |
| `ioc_tool/modules/vt.py` | VirusTotal v3 API client |
| `ioc_tool/modules/abuseipdb.py` | AbuseIPDB IP confidence lookup |
| `ioc_tool/modules/shodan_mod.py` | Shodan host info |
| `ioc_tool/modules/ip_quality_score.py` | IPQS fraud score |
| `ioc_tool/modules/ipinfo_mod.py` | IPinfo ASN/org/geo |
| `ioc_tool/modules/tor.py` | Match against Tor exit-node list |
| `ioc_tool/modules/whois_mod.py` | Domain WHOIS lookup |
| `ioc_tool/modules/urlhaus.py` | abuse.ch URLhaus malicious URL / host lookup (no API key) |
| `ioc_tool/modules/threatfox.py` | abuse.ch ThreatFox IOC lookup (ip/domain/url/hash, no API key) |
| `ioc_tool/modules/malwarebazaar.py` | abuse.ch MalwareBazaar hash lookup (sample + family, no API key) |
| `ioc_tool/modules/greynoise.py` | GreyNoise community classification — noise vs targeted |
| `ioc_tool/modules/otx.py` | AlienVault OTX pulse lookup — community / threat-actor reports |
| `ioc_tool/modules/urlscan.py` | URLscan.io historical scan search (IP / domain / URL — screenshots + verdicts) |
| `ioc_tool/modules/filescan_io.py` | FileScan.IO file/URL submission |
| `ioc_tool/modules/hybrid_analysis.py` | Hybrid Analysis sandbox (optional) |
| `ioc_tool/modules/joe_sandbox.py` | Joe Sandbox Cloud (optional) |
| `ioc_tool/modules/nvd.py` | NIST NVD CVE metadata (CVSS v3.1 base score + severity) |
| `ioc_tool/modules/epss.py` | FIRST.org EPSS exploit-prediction probability + percentile |
| `ioc_tool/modules/kev.py` | CISA KEV (Known Exploited Vulnerabilities) catalog membership |
| `ioc_tool/modules/pdns.py` | Passive DNS (Mnemonic free tier) — first-seen / last-seen / IP age (info-only, IP IOCs only) |
| `ioc_tool/data/ioc.db` | SQLite cache (gitignored) |
| `ioc_tool/data/tor_nodes.txt` | Tor exit-node IP list (gitignored cache) |
| `ioc_tool/data/cisa_kev.json` | CISA KEV catalog snapshot (gitignored cache, refreshed daily) |
| `ioc_tool/web/__init__.py` | REST API package marker |
| `ioc_tool/web/api.py` | FastAPI app + routes — thin HTTP layer over `enrich_ioc_async` |
| `ioc_tool/web/static/index.html` | Dashboard shell (terminal-dark theme, no framework) |
| `ioc_tool/web/static/styles.css` | Dashboard CSS (vanilla, dark palette + monospace) |
| `ioc_tool/web/static/app.js` | Dashboard logic — vanilla JS, fetches the JSON API |

The CLI subcommand `shadowscope serve` (handled in `ui/cli.py::handle_serve`) launches the FastAPI app under uvicorn — see the **REST API** section below.

## Source coverage matrix

| IOC type | VT | AbuseIPDB | Shodan | IPQS | IPinfo | Tor | WHOIS | URLhaus | ThreatFox | MalwareBazaar | GreyNoise | OTX | URLscan | Sandbox | NVD | EPSS | KEV |
|----------|----|-----------|--------|------|--------|-----|-------|---------|-----------|---------------|-----------|-----|---------|---------|-----|------|-----|
| IP       | ✅ | ✅        | ✅     | ✅   | ✅     | ✅  | —     | ✅      | ✅        | —             | ✅        | ✅  | ✅      | —       | —   | —    | —   |
| Domain   | ✅ | —         | —      | —    | —      | —   | ✅    | ✅      | ✅        | —             | —         | ✅  | ✅      | —       | —   | —    | —   |
| URL      | ✅ | —         | —      | —    | —      | —   | —     | ✅      | ✅        | —             | —         | ✅  | ✅      | ✅      | —   | —    | —   |
| Hash     | ✅ | —         | —      | —    | —      | —   | —     | —       | ✅        | ✅            | —         | ✅  | —       | ✅      | —   | —    | —   |
| File     | —  | —         | —      | —    | —      | —   | —     | —       | —         | —             | —         | —   | —       | ✅      | —   | —    | —   |
| CVE      | —  | —         | —      | —    | —      | —   | —     | —       | —         | —             | —         | —   | —       | —       | ✅  | ✅   | ✅  |

## Risk-scoring algorithm

Per-source raw scores → averaged → composite final score (0–100).

| Source | Formula |
|--------|---------|
| VirusTotal | `malicious_count / total_engines * 100` |
| AbuseIPDB  | `abuseConfidenceScore` (already 0–100) |
| IPQS       | `fraud_score` (already 0–100) |
| Tor        | `100` if on exit-node list else `0` |
| WHOIS age  | `<30d → 90`, `30–180d → 60`, `>180d → 10`, unknown → `50` |
| URLhaus    | `95` if online hit, `70` if offline hit, `80` otherwise hit, `0` if no data |
| ThreatFox  | hit & `confidence_level >= 75 → 95`, `>= 50 → 80`, other hit → `60`, no data → `0` |
| MalwareBazaar | `95` on any hit (sample known to abuse.ch), `0` if no data |
| GreyNoise  | `malicious=90`, `benign/riot=0`, `unknown=0`, none=`0` |
| OTX        | pulses 1–2 → `50`, 3–9 → `75`, ≥10 → `90`; `reputation < 0` adds `+10` (cap `100`); no pulses + `reputation >= 0` → `0` |
| URLscan    | any result with malicious verdict → `90`; history exists, no malicious verdict → `30`; `total == 0` or no data → `0` |
| Shodan     | `0` (informational only — tags/ports/vulns shown but not scored) |
| IPinfo     | `0` (informational only — ASN/org/geo shown) |
| NVD        | `int(round(CVSS v3.1 baseScore * 10))` — 0 if no v3.1 metric |
| EPSS       | `int(round(epss * 100))`; floor at `70` when `percentile >= 0.99` |
| KEV        | `100` if listed in CISA KEV catalog, else `0` |

Final = `int(sum(scores) / len(scores))`.

Tiers:

| Range | Label    |
|-------|----------|
| 0–19  | Safe     |
| 20–39 | Low      |
| 40–59 | Medium   |
| 60–79 | High     |
| 80–100| Critical |

## Caching

- **Backend**: SQLite at `ioc_tool/data/ioc.db`
- **Tables**: `iocs`, `enrichments`, `ioc_tags`, `meta` (key/value, used by auto-prune scheduling)
- **Freshness TTL**: 24 h (`core.enrich.should_refresh`), tunable via `CACHE_TTL_HOURS` env. Controls *refetch*, not deletion.
- **Retention**: 90 d (default) — `enrichments` rows older than `RETENTION_DAYS` env are removed by the auto-prune janitor. Set `AUTO_PRUNE=0` to disable the in-process janitor (e.g. when you run `shadowscope cache prune` from cron instead).
- **Auto-prune**: at most once per process per workspace per day; silent on failure so it can never break the enrichment path.
- **Manual maintenance**: `shadowscope cache stats|prune|clear` — `stats` shows row counts + on-disk size + per-source breakdown; `prune` accepts `--older-than 30d|12h|...` plus `--keep-last N` to cap per-(ioc, source) history; `clear` wipes by `--source`, `--ioc`, or `--all` (exactly one filter required, `--yes` for non-interactive use).
- **Effect**: repeat queries within freshness TTL hit cache → no API spend; long-term disk growth is bounded by retention.

## LLM verdict

Optional natural-language layer on top of the structured enrichment. After `core.score` produces the composite risk, callers can opt in (`--summary` on the CLI, `?summary=true` on the API) to have `core.llm.summarize()` call a local Ollama HTTP server and return a 2-3 sentence analyst-grade verdict that names the dominant signals and recommends a next action.

* **Endpoint** — `POST {OLLAMA_BASE_URL}/api/generate` (default `http://localhost:11434`)
* **Model**    — `OLLAMA_MODEL` (default `llama3.2`)
* **Timeout**  — 30 s by default; tweakable via the `timeout` argument
* **Prompt**   — built by `_build_prompt(result)` from the enrichment dict: IOC value, type, composite score + tier, then one line per source with score and 1–3 key facts (VirusTotal `5/93 malicious`, AbuseIPDB `confidence 95`, URLhaus `threat=malware_download`, etc.). Total stays under ~600 chars so small local models handle it without truncation.
* **Fallback** — connection error, timeout, non-200, malformed JSON, or missing `response` field all return `None`. The CLI surfaces a dim "LLM summary unavailable" note; the REST API simply omits the `llm_summary` key. **ShadowScope never crashes because Ollama is offline.**
* **Bulk**     — `/enrich/bulk` and `/extract` parallelise summarisation across results via `asyncio.gather(asyncio.to_thread(llm.summarize, r), ...)` since each call is independent network I/O.

The feature is purely additive — disable it by omitting the flag/query param, and ShadowScope behaves exactly as before.

## Configuration

All secrets in `ioc_tool/.env` (gitignored). Template: `ioc_tool/.env.example`. See [`API_KEYS.md`](API_KEYS.md) for provider details.

## Conventions

- **Language**: Python 3.10+ (developed on 3.13)
- **Style**: PEP 8, 4-space indent, type hints on new code
- **Errors**: API failures return `None`; never crash the CLI
- **Cache-aware**: every module wraps API call in `should_refresh()` check
- **Secrets**: never log, print, or commit `.env`

## Adding a new enrichment source

1. Create `ioc_tool/modules/<source>.py` exposing `enrich_ip()` / `enrich_domain()` / etc.
2. Add scoring helper to `ioc_tool/core/score.py` if it produces a score.
3. Wire into `ioc_tool/core/enrich.py` next to existing source blocks (preserve cache pattern).
4. Add env-var name to `ioc_tool/.env.example` and to `docs/API_KEYS.md`.
5. Add a smoke test in `tests/`.

## REST API

`shadowscope serve` exposes the enrichment pipeline as a JSON REST API for external consumers (notably the homelab secops dashboard). The HTTP layer (`ioc_tool/web/api.py`) is intentionally thin — it parses params, refangs input, delegates to `enrich_ioc_async`, and serialises the result. No new enrichment logic lives in the API.

### Bind defaults

| Setting | Default | CLI flag |
|---------|---------|----------|
| Host    | `127.0.0.1` | `--host` |
| Port    | `8765`      | `--port` |
| Reload  | off         | `--reload` (dev only — uvicorn requires import-string target) |

### Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET    | `/` | Service info — version + endpoint list |
| GET    | `/health` | Liveness probe — always public, returns `{"status": "ok"}` |
| GET    | `/enrich?ioc=<value>[&defang=true]` | Enrich a single IOC (auto-detected, refanged) |
| POST   | `/enrich/bulk` | Body `{"iocs": [...]}` — enrich every IOC concurrently via `asyncio.gather` |
| POST   | `/extract` | Body `{"text": "..."}` — pull IOCs from a text blob, then enrich each |
| GET    | `/show?ioc=<value>[&defang=true]` | Return cached enrichment without refetching — 404 if not in cache |
| GET    | `/sources` | Map of `source_name → bool` indicating whether the API key is set. **Never returns key values.** |
| GET    | `/api/ui/recent?limit=N` | Newest cached IOCs (default 8, max 50) reshaped for the dashboard's recent strip. Reads `iocs` desc by `last_seen`, rebuilds modules from cache — no API spend. Empty list when the workspace has never been enriched. |
| GET    | `/api/ui/pivot?kind=<kind>&value=<v>[&limit=N&exclude=<ioc>]` | Cache-wide related-IOC lookup. `kind`: `tag` / `malware` / `family` / `registrar` / `ioc` / `any`. Substring scan over persisted JSON; quoted-literal match for known string-field kinds avoids false positives (`"emotet"` won't match `emotetable`). Powers the dashboard's PivotPanel "RELATED" groups. |
| GET    | `/api/ui/cases` | List every case in the workspace with member IOC values, count, derived severity (max member `last_score`), and earliest tag creation as `opened`. Backs the Cases tab. |
| PATCH  | `/api/ui/iocs/{value}/case` | Body `{"case": "<name>" \| null}` — assign or detach. Refangs the path value. 404 when the IOC isn't in the cache (enrich first). An IOC can belong to at most one case at a time; reassigning replaces the prior tag row. |
| DELETE | `/api/ui/cases/{case}` | Detach every IOC from a case. The underlying IOCs + their enrichments are preserved; only the case relationship is removed. Idempotent: unknown case returns `removed: 0`. |
| GET    | `/ui` | Dashboard SPA shell (HTML). No auth — the data behind it is what's gated. |
| GET    | `/static/*` | Dashboard CSS / JS assets. No auth. |

Every enrichment endpoint accepts an optional `?defang=true` query param that defangs the returned `ioc` field (uses `core.defang.defang()`).

### Auth model

Bearer token via the `SHADOWSCOPE_API_TOKEN` env var.

* **Unset** — auth disabled. Suitable for localhost-only homelab use.
* **Set** — every endpoint except `/health` requires `Authorization: Bearer <token>`. Missing/malformed header → `401`. Wrong token → `403`. Error messages are deliberately generic and never reveal whether the token is configured.

`/api/ui/events` (the SSE stream consumed by the dashboard) accepts the token via the `?token=<v>` query param instead of `Authorization:` — `EventSource` can't set request headers. Same env var, same comparison. The dashboard's `shadowscopeSubscribeEvents` helper appends it from `sessionStorage.ss_api_token` automatically.

`SHADOWSCOPE_SSE_HEARTBEAT_S` (default `25.0`) controls how often `/api/ui/events` emits a `: heartbeat` comment line when the bus is idle. Lower it in tests; raise it if a proxy in front of ShadowScope tolerates longer idles.

### CORS

Configured via `SHADOWSCOPE_CORS_ORIGINS` (comma-separated origins). Defaults: `*` (open) when `SHADOWSCOPE_API_TOKEN` is unset; `http://localhost:8765,http://127.0.0.1:8765` (loopback only) when the token is set so a stolen token can't be replayed cross-origin. Override explicitly to lock to a non-loopback dashboard origin in production-style deployments, e.g. `SHADOWSCOPE_CORS_ORIGINS=https://secops.lan`.

### Integration with homelab consumers

The homelab "secops web service" treats ShadowScope as a callable HTTP API. Recommended deployment:

* Bind `127.0.0.1:8765` (or a Docker-internal network) — never expose directly to the public internet.
* Generate a token: `export SHADOWSCOPE_API_TOKEN=$(openssl rand -hex 32)` and pass it as a Bearer header from the dashboard.
* Set `SHADOWSCOPE_CORS_ORIGINS` to the dashboard's exact origin when leaving permissive defaults.

### Dashboard

The dashboard (`GET /ui`) is a single-page UI served from `ioc_tool/web/static/` — vanilla HTML/CSS/JS, no SPA framework, no build step, no CDN dependencies. CSS/JS load from stable `/static/<file>` paths via FastAPI's `StaticFiles` mount. The dashboard route itself is **not** auth-gated; the HTML shell is harmless and the per-fetch JSON calls inside the JS carry the bearer token.

**Standalone use** — open `http://<host>:8765/ui` in a browser. If `SHADOWSCOPE_API_TOKEN` is set, the page surfaces an inline auth banner where the user can paste the token; it's kept in memory for the page lifetime only (never `localStorage` — that's an XSS risk).

**Iframe embed pattern** (homelab secops web service):

```html
<iframe
  src="http://shadowscope.lan:8765/ui?token=<bearer-token>"
  referrerpolicy="no-referrer"
  sandbox="allow-scripts allow-same-origin"
  style="width:100%;height:100vh;border:0"></iframe>
```

The dashboard reads `?token=<v>` from `window.location.search` on load and injects it into every fetch as `Authorization: Bearer <v>`. The HTML sets `<meta name="referrer" content="no-referrer">` and ShadowScope does not emit `X-Frame-Options` / `Content-Security-Policy: frame-ancestors`, so embedding works out of the box. Lock down CORS (`SHADOWSCOPE_CORS_ORIGINS`) to the embedding dashboard's origin in production.

**Recent strip** — the row of score pills at the top of the Enrich tab seeds from `/api/ui/recent` on mount (newest 8 cached IOCs), then prepends each new enrichment in front. A fresh workspace shows an empty-state prompt instead of demo data, so the strip always reflects real cache state. The "clear strip" button next to the count is **view-only**: it resets the React `results` array but leaves SQLite untouched. To delete cached enrichments use the Cache tab → `/api/cache/clear` (gated, requires a filter — by source / IOC / `all=true`).

## Container deployment

ShadowScope is packaged for drop-in use inside a docker-compose homelab stack.

* **Dockerfile** — multi-stage build on `python:3.12-slim`. Stage 1 installs `requirements.txt` into `/opt/venv`; stage 2 copies the venv + `ioc_tool/` package, drops to a non-root `shadowscope` user, exposes `8765`, and HEALTHCHECKs the FastAPI `/health` route with a stdlib `urllib.request` probe. Default CMD is `python -m ioc_tool.main serve --host 0.0.0.0 --port 8765`.
* **docker-compose.yml** — single `shadowscope` service. Mounts a named `shadowscope-data` volume at `/app/ioc_tool/data` so the SQLite cache (`ioc.db`) and CISA KEV snapshot (`cisa_kev.json`) survive container restarts. Pulls all secrets + tuneables from a sibling `.env` file (`VT_API_KEY`, `ABUSEIPDB_API_KEY`, …, `SHADOWSCOPE_API_TOKEN`, `SHADOWSCOPE_CORS_ORIGINS`, `OLLAMA_BASE_URL`, `OLLAMA_MODEL`). Adds `extra_hosts: ["host.docker.internal:host-gateway"]` so the container can reach the host's Ollama on Linux Docker.

**Run it**

```bash
cp .env.example .env
# fill in keys
docker compose up -d
curl http://localhost:8765/health
```

Consumers (e.g. the homelab secops web service) point at `http://shadowscope:8765/...` when sharing a compose network, or `http://localhost:8765/...` when binding to the host.

## Open work

See [`ROADMAP.md`](ROADMAP.md) for the active backlog.

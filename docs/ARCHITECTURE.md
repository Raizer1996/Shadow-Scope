# ShadowScope — Architecture

> Single source of truth. Update with every change. Commit with the work.

## Overview

ShadowScope is a terminal-based IOC enrichment and risk-scoring tool. It accepts an Indicator of Compromise (IP, domain, URL, or file hash), queries multiple threat-intelligence sources in series, caches results in SQLite, and produces a composite risk score plus a rich terminal report.

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
                   │
       ┌───────────┼───────────┬───────────┬───────────┬──────────┐
       ▼           ▼           ▼           ▼           ▼          ▼
    modules.vt  abuseipdb   shodan_mod  ipqs       ipinfo_mod  whois_mod
                            tor                                 filescan_io
                                                                hybrid_analysis
                                                                joe_sandbox
                   │
                   ▼
            ┌──────────────┐
            │  core.score  │  composite risk 0-100
            └──────┬───────┘
                   ▼
            ┌──────────────┐
            │  ui.cli      │  render table + score banner
            └──────────────┘
```

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
| `ioc_tool/modules/vt.py` | VirusTotal v3 API client |
| `ioc_tool/modules/abuseipdb.py` | AbuseIPDB IP confidence lookup |
| `ioc_tool/modules/shodan_mod.py` | Shodan host info |
| `ioc_tool/modules/ip_quality_score.py` | IPQS fraud score |
| `ioc_tool/modules/ipinfo_mod.py` | IPinfo ASN/org/geo |
| `ioc_tool/modules/tor.py` | Match against Tor exit-node list |
| `ioc_tool/modules/whois_mod.py` | Domain WHOIS lookup |
| `ioc_tool/modules/urlhaus.py` | abuse.ch URLhaus malicious URL / host lookup (no API key) |
| `ioc_tool/modules/filescan_io.py` | FileScan.IO file/URL submission |
| `ioc_tool/modules/hybrid_analysis.py` | Hybrid Analysis sandbox (optional) |
| `ioc_tool/modules/joe_sandbox.py` | Joe Sandbox Cloud (optional) |
| `ioc_tool/data/ioc.db` | SQLite cache (gitignored) |
| `ioc_tool/data/tor_nodes.txt` | Tor exit-node IP list (gitignored cache) |

## Source coverage matrix

| IOC type | VT | AbuseIPDB | Shodan | IPQS | IPinfo | Tor | WHOIS | URLhaus | Sandbox |
|----------|----|-----------|--------|------|--------|-----|-------|---------|---------|
| IP       | ✅ | ✅        | ✅     | ✅   | ✅     | ✅  | —     | ✅      | —       |
| Domain   | ✅ | —         | —      | —    | —      | —   | ✅    | ✅      | —       |
| URL      | ✅ | —         | —      | —    | —      | —   | —     | ✅      | ✅      |
| Hash     | ✅ | —         | —      | —    | —      | —   | —     | —       | ✅      |
| File     | —  | —         | —      | —    | —      | —   | —     | —       | ✅      |

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
| Shodan     | `0` (informational only — tags/ports/vulns shown but not scored) |
| IPinfo     | `0` (informational only — ASN/org/geo shown) |

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
- **Tables**: `iocs` (id, value, type), `enrichments` (ioc_id, source, data_json, score, timestamp)
- **TTL**: 24 h (`core.enrich.should_refresh`)
- **Effect**: repeat queries within 24 h hit cache → no API spend

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

## Open work

See [`ROADMAP.md`](ROADMAP.md) for the active backlog.

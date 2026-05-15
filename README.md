# ShadowScope 🛰️

[![CI](https://github.com/Raizer1996/Shadow-Scope/actions/workflows/ci.yml/badge.svg)](https://github.com/Raizer1996/Shadow-Scope/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![mypy: checked](https://img.shields.io/badge/mypy-checked-blue.svg)](https://mypy-lang.org/)
[![ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![IOC Types](https://img.shields.io/badge/IOC-IP%20%7C%20Domain%20%7C%20URL%20%7C%20Hash%20%7C%20File-orange.svg)](docs/ARCHITECTURE.md)

**ShadowScope** is a terminal-based IOC (Indicator of Compromise) enrichment and analysis tool. It aggregates data from multiple threat intelligence sources to produce a comprehensive risk assessment for IPs, domains, URLs, file hashes, and files.

<img width="562" height="110" alt="banner" src="https://github.com/user-attachments/assets/d356a536-f94d-4a9a-8c64-eabfbd54381b" />

## 🚀 Features

- **Multi-Source Enrichment**
  - **VirusTotal** — Malicious detection counts and analysis stats
  - **AbuseIPDB** — Confidence scores and usage types (ISP, Data Center)
  - **Shodan** — Host tags (VPN, Proxy), open ports, and vulnerabilities
  - **IPQualityScore** — Fraud and risk scoring
  - **IPinfo** — Organization and ASN details
  - **Tor Detection** — Identifies active Tor exit nodes
  - **WHOIS** — Domain creation dates and registrar info
  - **URLhaus** — abuse.ch malicious URL database (no API key)
  - **ThreatFox (abuse.ch)** — fresh community-shared IOCs (no API key)
  - **MalwareBazaar (abuse.ch)** — hash → malware family + sample metadata (no API key)
  - **GreyNoise** — classifies internet background noise vs targeted activity (kills SOC false positives)
  - **AlienVault OTX** — community pulse / threat-actor reports (free key)
  - **URLscan.io** — historical scan search, screenshots + verdicts (free key, optional)
  - **CVE triage** — NVD CVSS + EPSS exploit probability + CISA KEV (Known Exploited Vulnerabilities) catalog

  <img width="1341" height="529" alt="enrich result" src="https://github.com/user-attachments/assets/033a128a-68db-4fdd-8698-7d0f09439246" />
  <img width="363" height="422" alt="risk score" src="https://github.com/user-attachments/assets/6d584762-5951-4ebb-98b4-25b9395feb10" />

- **Multi-Sandbox Analysis**
  - **FileScan.IO** — Full file/URL analysis with report links
  - **Hybrid Analysis** *(optional)* — Automated malware analysis
  - **Joe Sandbox** *(optional)* — Deep malware analysis

  <img width="1206" height="88" alt="sandbox result" src="https://github.com/user-attachments/assets/22f1c531-4fb1-4b20-af9b-bf52b6010282" />

- **Smart Risk Scoring**
  - Composite risk score (0–100)
  - Color-coded tiers: **Safe**, **Low**, **Medium**, **High**, **Critical**
  - Automatic flagging of VPNs, proxies, and Tor exit nodes
  - 24 h SQLite cache — no wasted API quota on repeat queries

- **Parallel multi-source enrichment** — every applicable source fires concurrently via `asyncio.to_thread`; ~9× faster than serial for multi-source IP queries (wall-clock becomes `max(per-source latency)` instead of the sum)

- **LLM verdict (optional)** — 2-3 sentence natural-language reasoning via local Ollama. Pass `--summary` on the CLI or `?summary=true` on the API; configurable via `OLLAMA_BASE_URL` / `OLLAMA_MODEL`. Gracefully degrades to no-op when Ollama is unreachable

- **Sleek CLI**
  - Interactive menu system
  - Rich text formatting with tables and colors
  - "Sniper Scope" banner and visual effects

## ⚡ Quick start

```bash
git clone https://github.com/Raizer1996/Shadow-Scope.git
cd Shadow-Scope
pip install -r requirements.txt
cp ioc_tool/.env.example ioc_tool/.env
nano ioc_tool/.env          # paste your API keys
python3 -m ioc_tool.main    # interactive mode
```

## 🛠️ Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/Raizer1996/Shadow-Scope.git
   cd Shadow-Scope
   ```

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Configure API keys**

   ```bash
   cp ioc_tool/.env.example ioc_tool/.env
   nano ioc_tool/.env
   ```

   See [`docs/API_KEYS.md`](docs/API_KEYS.md) for provider signup links and free-tier limits.

   Minimum recommended: `VT_API_KEY` + `ABUSEIPDB_API_KEY`. Missing keys are skipped gracefully.

## 💻 Usage

ShadowScope uses discoverable argparse subcommands. Run with no arguments for the
interactive menu, or pass a subcommand for a one-shot operation.

> Paste defanged IOCs (`1[.]2[.]3[.]4`, `hxxp://evil[.]com`, `user[at]example[.]com`) — they're auto-refanged on input. Use `--defang` to defang results on output so reports are safe to share.

**Interactive mode**

```bash
python3 -m ioc_tool.main
```

**Enrich a single IOC** (IP / domain / URL / hash / CVE)

```bash
python3 -m ioc_tool.main enrich 8.8.8.8
python3 -m ioc_tool.main enrich CVE-2024-1234
```

**LLM verdict** (optional — requires a local [Ollama](https://ollama.com) install)

```bash
python3 -m ioc_tool.main enrich 8.8.8.8 --summary
```

Appends a 2-3 sentence natural-language verdict below the table. Override the model or endpoint via `OLLAMA_MODEL` / `OLLAMA_BASE_URL`. If Ollama is unreachable the call returns silently and the rest of the report still prints.

**Bulk enrich from a file** (one IOC per line)

```bash
python3 -m ioc_tool.main enrich -f iocs.txt
```

**Extract IOCs from text**

Paste a ticket, email body, or threat report and ShadowScope will pull every
IP, domain, URL, hash, and email out (refanging on the way in) and enrich
each one.

```bash
python3 -m ioc_tool.main enrich --text "Saw 1.2.3.4 hit our firewall and email from attacker@evil.com"
echo "blob with hxxp://evil[.]com/bad" | python3 -m ioc_tool.main enrich -
cat ticket.txt | python3 -m ioc_tool.main enrich -
```

**Machine-readable output** for SIEM / spreadsheet pipelines

```bash
python3 -m ioc_tool.main enrich 8.8.8.8 --json
python3 -m ioc_tool.main enrich -f iocs.txt --csv > report.csv
```

`--json` emits the full result payload; `--csv` flattens to the key columns (IOC, type, final score, risk tier, per-source highlights). Both keep stdout parse-clean — banners and warnings are routed to stderr.

**Sandbox analyze a file or URL** (file vs URL auto-detected)

```bash
python3 -m ioc_tool.main analyze sample.exe
python3 -m ioc_tool.main analyze https://example.com/bad
```

**Shodan-only host lookup**

```bash
python3 -m ioc_tool.main shodan 1.1.1.1
```

**Show cached enrichment** for a previously-enriched IOC

```bash
python3 -m ioc_tool.main show 8.8.8.8
```

**Help at any level**

```bash
python3 -m ioc_tool.main --help
python3 -m ioc_tool.main enrich --help
```

## 🌐 REST API

`shadowscope serve` launches a FastAPI server that exposes the enrichment pipeline over HTTP — built for integration with the homelab secops dashboard or any other consumer that wants JSON instead of CLI.

```bash
pip install -r requirements.txt
export SHADOWSCOPE_API_TOKEN=$(openssl rand -hex 32)  # optional — omit for unauthed localhost-only use
shadowscope serve --host 0.0.0.0 --port 8765
curl -H "Authorization: Bearer $SHADOWSCOPE_API_TOKEN" "http://localhost:8765/enrich?ioc=8.8.8.8"
```

The CLI entry name is `shadowscope` when installed; from a checkout use `python3 -m ioc_tool.main serve ...`. Both forms work identically.

**Endpoints**

| Method | Path | Purpose |
|--------|------|---------|
| GET    | `/` | Service info |
| GET    | `/health` | Liveness — always public |
| GET    | `/enrich?ioc=<value>` | Enrich one IOC (auto-detected, refanged) |
| POST   | `/enrich/bulk` | `{"iocs": [...]}` — concurrent enrichment |
| POST   | `/extract` | `{"text": "..."}` — extract IOCs from a blob and enrich each |
| GET    | `/show?ioc=<value>` | Cached enrichment, no refetch — 404 if not cached |
| GET    | `/sources` | `{source_name: key_present}` — never returns key values |

Add `?defang=true` to any enrichment endpoint to defang the returned `ioc` field. Add `?summary=true` to `/enrich`, `/enrich/bulk`, or `/extract` to attach an LLM-generated `llm_summary` field via local Ollama (omitted when Ollama is unreachable). Auth (`SHADOWSCOPE_API_TOKEN`) and CORS (`SHADOWSCOPE_CORS_ORIGINS`, comma-separated, default `*`) are env-configurable. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#rest-api) for the full breakdown.

**Web dashboard** — once the server is up, open `http://localhost:8765/ui` for a minimal terminal-themed UI: paste one IOC, a comma/newline list, or a full text blob and the page picks the right call (`/enrich`, `/enrich/bulk`, or `/extract`) automatically. It is iframe-embeddable into the homelab secops dashboard via `?token=<bearer>` in the URL. See the **Dashboard** section in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#dashboard) for the embed pattern.

<!-- TODO: dashboard screenshot -->

## 🐳 Docker

ShadowScope ships with a multi-stage `Dockerfile` and a single-service `docker-compose.yml` so it can be dropped straight into a homelab compose stack as another containerised service.

```bash
cp .env.example .env       # fill in your API keys + (optional) bearer token
docker compose up -d
curl http://localhost:8765/health
```

Then open the dashboard at `http://localhost:8765/ui`.

The image runs as a non-root `shadowscope` user, exposes `8765`, and uses the FastAPI `/health` route for its container healthcheck. The compose stack mounts a named `shadowscope-data` volume at `/app/ioc_tool/data` to persist the SQLite cache and CISA KEV snapshot across restarts. On Linux Docker the container reaches the host's Ollama at `host.docker.internal:11434` via the `host-gateway` extra_host. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#container-deployment) for the full breakdown.

## 📚 Documentation

| Doc | Purpose |
|-----|---------|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Module map, data flow, scoring algorithm |
| [`docs/API_KEYS.md`](docs/API_KEYS.md) | Provider signup, free-tier limits, env vars |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Open backlog and planned features |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to contribute, PR rules, conventions |
| [`CLAUDE.md`](CLAUDE.md) | AI / contributor orientation guide |

## 🗺️ Roadmap

Highlights (full list in [`docs/ROADMAP.md`](docs/ROADMAP.md)):

- Argparse subcommands (`shadowscope enrich <ioc>`)
- JSON / CSV output for SIEM ingest
- Bulk mode (`-f iocs.txt`)
- Plugin loader — drop-in modules with no `enrich.py` edits
- PyPI package + Docker image

## 🤝 Contributing

PRs welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## 🛡️ License

[MIT](LICENSE). For educational and defensive use. Use responsibly.

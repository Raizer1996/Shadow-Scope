# ShadowScope 🛰️

[![CI](https://github.com/Raizer1996/Shadow-Scope/actions/workflows/ci.yml/badge.svg)](https://github.com/Raizer1996/Shadow-Scope/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
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

**Interactive mode**

```bash
python3 -m ioc_tool.main
```

**Enrich a single IOC** (IP / domain / URL / hash)

```bash
python3 -m ioc_tool.main enrich 8.8.8.8
```

**Bulk enrich from a file** (one IOC per line)

```bash
python3 -m ioc_tool.main enrich -f iocs.txt
```

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

- Async enrichment (`aiohttp` + `asyncio.gather`)
- Argparse subcommands (`shadowscope enrich <ioc>`)
- JSON / CSV output for SIEM ingest
- Bulk mode (`-f iocs.txt`)
- Plugin loader — drop-in modules with no `enrich.py` edits
- PyPI package + Docker image

## 🤝 Contributing

PRs welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## 🛡️ License

[MIT](LICENSE). For educational and defensive use. Use responsibly.

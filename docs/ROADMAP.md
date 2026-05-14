# ShadowScope — Roadmap

Public backlog. Items marked **[issue]** will be promoted to GitHub Issues with milestone labels once the repo is pushed.

Organized by **release milestone** (foundational → expansion → polish) and by **category** within each.

---

## v0.2 — Quality + Speed (foundations)

### Engineering
- [ ] **Async enrichment** — `aiohttp` + `asyncio.gather()` in `core.enrich`; ~5–10× speedup on multi-source IP queries. **[issue]**
- [ ] **Pytest mocking** — `responses` lib; tests must not hit live APIs. **[issue]**
- [ ] **Type hints + mypy clean** on public functions. **[issue]**
- [ ] **GitHub Actions CI matrix** — ruff lint + pytest on py3.10/3.11/3.12 *(already scaffolded — needs ruff config + green run)*. **[issue]**

---

## v0.3 — Output + Bulk (analyst usability)

### Output formats
- [ ] **JSON output** (`--json`) for SIEM ingest. **[issue]**
- [ ] **CSV output** (`--csv`) for spreadsheet handoff. **[issue]**
- [ ] **STIX 2.1 export** (`--stix`) for threat-intel sharing. **[issue]**
- [ ] **Markdown report** (`--md`) for case documentation. **[issue]**
- [ ] **PDF report** (`--pdf`) — exec-style with score banner, table, links. **[issue]**

### Bulk + I/O
- [ ] **Bulk mode** (`-f iocs.txt`) — one IOC per line, parallel enrich, combined report. **[issue]**
- [ ] **Pipe support** (`echo 1.2.3.4 | shadowscope enrich -`). **[issue]**
- [ ] **IOC extraction from text** — paste email body / log dump, auto-extract IPs/domains/hashes/URLs, enrich each. **[issue]**
- [ ] **Defang / refang** — convert `1[.]2[.]3[.]4` ↔ `1.2.3.4` on input/output. **[issue]**
- [ ] **Punycode decode** — catch IDN homograph attacks in domains. **[issue]**

### Cache / freshness
- [ ] **Configurable cache TTL** — env `CACHE_TTL_HOURS`. **[issue]**
- [ ] **Tor list auto-refresh** — daily fetch from `check.torproject.org`. **[issue]**
- [ ] **Force refresh flag** (`--no-cache`) to bypass cache. **[issue]**

---

## v0.4 — New Sources (intel breadth)

### Free / freemium IOC sources
- [ ] **GreyNoise** — flags internet-scanner noise vs targeted activity (huge FP killer). **[issue]**
- [ ] **AlienVault OTX** — community pulses, broad coverage. **[issue]**
- [ ] **URLscan.io** — URL screenshot + sibling domains + behavior (phishing gold). **[issue]**
- [ ] **abuse.ch URLhaus** — malware URLs, no API key required. **[issue]**
- [ ] **abuse.ch ThreatFox** — fresh IOC feed, no API key. **[issue]**
- [ ] **abuse.ch MalwareBazaar** — hash → sample + family classification. **[issue]**
- [ ] **abuse.ch Feodo Tracker** — botnet C2 list. **[issue]**
- [ ] **abuse.ch SSL Blacklist** — malicious cert fingerprints. **[issue]**
- [ ] **crt.sh certificate transparency** — pivot from cert to related domains. **[issue]**
- [ ] **SecurityTrails** — passive DNS, historical WHOIS, subdomain enum. **[issue]**
- [ ] **Pulsedive** — aggregator with built-in risk scoring. **[issue]**
- [ ] **IBM X-Force Exchange** — free tier reputation. **[issue]**
- [ ] **Cisco Talos** — IP/domain reputation. **[issue]**
- [ ] **Censys** — alternative to Shodan, free academic tier. **[issue]**
- [ ] **DNSDB / Farsight passive DNS** *(paid — optional)*. **[issue]**

### New IOC types
- [ ] **Email** — EmailRep, HaveIBeenPwned breach check. **[issue]**
- [ ] **CVE** — NVD + EPSS score + CISA KEV catalog flag. **[issue]**
- [ ] **ASN** — BGP info, abuse history, prefix reputation. **[issue]**
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

- [ ] **DGA detection** — entropy / ML scoring for algorithmically generated domains. **[issue]**
- [ ] **NRD flag** — newly registered domain (< 30 days) → bump score. **[issue]**
- [ ] **Typosquatting / homograph detection** — alert on lookalikes of org domains. **[issue]**
- [ ] **Pivot suggestions** — given IP, surface related domains via PDNS / cert overlap. **[issue]**
- [ ] **Reverse DNS** lookup on every IP. **[issue]**
- [ ] **Suspicious TLD scoring** — `.tk / .top / .xyz / .surf` bump. **[issue]**
- [ ] **First-seen / IP age** from PDNS data. **[issue]**
- [ ] **LLM summary** (local Ollama / Claude API) — natural-language verdict + reasoning. **[issue]**
- [ ] **Auto-tag with MITRE ATT&CK** technique mapping based on observed behavior. **[issue]**

---

## v0.7 — Case Management & Workflow

- [ ] **Tags + cases** — `shadowscope tag <ioc> --case=campaign-x`. **[issue]**
- [ ] **Notes per IOC** — append free-text notes stored in DB. **[issue]**
- [ ] **History view** — past queries, score over time, change alerts. **[issue]**
- [ ] **Allowlist** — skip enrichment for org-internal CIDRs. **[issue]**
- [ ] **Watch mode** — re-enrich daily, alert on score change > threshold. **[issue]**
- [ ] **Multiple workspaces** — isolate cases / engagements. **[issue]**
- [ ] **Compare two IOCs** (`shadowscope diff <ioc1> <ioc2>`). **[issue]**
- [ ] **Risk score history graph** (ASCII / terminal). **[issue]**
- [ ] **Source agreement matrix** — which sources flagged vs missed. **[issue]**

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

- [ ] **Web dashboard** — FastAPI + minimal HTML, table of recent queries, drill-down. **[issue]**
- [ ] **REST API server** — `shadowscope serve` exposes enrichment as HTTP. **[issue]**
- [ ] **GraphQL API** *(optional)*. **[issue]**
- [ ] **TUI** — full-screen terminal UI with `textual`. **[issue]**
- [ ] **Browser extension** — right-click any IP/domain → enrich popup. **[issue]**
- [ ] **VS Code extension** — hover any IP in code/logs → tooltip with score. **[issue]**
- [ ] **Burp Suite extension** — enrich findings inline. **[issue]**

---

## v1.0 — Packaging & Distribution

- [ ] **PyPI package** — `pip install shadowscope` + `shadowscope` entry point. **[issue]**
- [ ] **pipx install** docs. **[issue]**
- [ ] **Docker image** — minimal Alpine, `.env` mount pattern. **[issue]**
- [ ] **Docker Compose** stack — ShadowScope + Redis + dashboard. **[issue]**
- [ ] **Kubernetes Helm chart**. **[issue]**
- [ ] **Demo GIF / asciinema** in README. **[issue]**
- [ ] **SemVer + CHANGELOG.md** (Keep-a-Changelog format). **[issue]**

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

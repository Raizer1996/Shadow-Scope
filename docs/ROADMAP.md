# ShadowScope — Roadmap

Public backlog. Once the repo is pushed and Issues are enabled, items marked **[issue]** will be promoted to GitHub Issues with milestone labels.

## v0.2 — Quality + Speed

- [ ] **Async enrichment** — replace serial requests in `core.enrich` with `aiohttp` + `asyncio.gather()` for ~5–10× speedup on multi-source IP queries. **[issue]**
- [ ] **argparse subcommands** — replace `-1 / -2 / -3` flags with `shadowscope enrich <ioc>`, `shadowscope analyze <file>`, `shadowscope shodan <ip>`. **[issue]**
- [ ] **Pinned requirements** — pin versions in `requirements.txt` (`requests==2.32.x`, etc.) + generate `requirements-dev.txt`. **[issue]**
- [ ] **Pytest smoke tests** — one test per module covering parser, scorer, and a mocked API response. **[issue]**
- [ ] **GitHub Actions CI** — lint (ruff), test (pytest), Python 3.10/3.11/3.12 matrix. **[issue]**
- [ ] **Type hints + mypy** — annotate all public functions, mypy-clean. **[issue]**

## v0.3 — Output + Bulk

- [ ] **JSON output mode** — `--json` flag emits the full result dict for SIEM ingest. **[issue]**
- [ ] **CSV output mode** — flat CSV for spreadsheet/SOC handoff. **[issue]**
- [ ] **Bulk mode** — `-f iocs.txt` reads one IOC per line, parallel-enriches, single combined report. **[issue]**
- [ ] **Configurable cache TTL** — env var `CACHE_TTL_HOURS` overrides default 24 h. **[issue]**
- [ ] **Tor list auto-refresh** — daily fetch from `check.torproject.org` instead of static file. **[issue]**

## v0.4 — Extensibility

- [ ] **Plugin loader** — auto-discover modules in `ioc_tool/modules/` via `importlib`; drop-in modules require no edits to `enrich.py`. **[issue]**
- [ ] **Rate-limit handler** — per-source token bucket; back off on 429. **[issue]**
- [ ] **Additional sources** — Pulsedive, GreyNoise, AlienVault OTX, URLscan.io. **[issue]**
- [ ] **YARA hash lookup** — optional MalwareBazaar / VirusShare integration. **[issue]**

## v1.0 — Packaging + Distribution

- [ ] **PyPI package** — `pip install shadowscope` + `shadowscope` console entry point. **[issue]**
- [ ] **Docker image** — minimal Alpine-based image, `.env` mount pattern. **[issue]**
- [ ] **Pipx install docs** — single-command install for end users. **[issue]**
- [ ] **Demo GIF / asciinema** — embedded in README. **[issue]**
- [ ] **Versioning** — adopt SemVer + `CHANGELOG.md` (Keep-a-Changelog format). **[issue]**

## Stretch / future

- [ ] **Web dashboard** — Flask/FastAPI front-end serving the same enrichment pipeline.
- [ ] **MISP export** — push verdicts as MISP attributes.
- [ ] **Splunk app** — wrapper for `shadowscope enrich` as a custom search command.
- [ ] **TheHive / Cortex analyzer** — repackage modules as Cortex analyzers.

## Done

- [x] Repo hygiene — gitignore binaries / cache / debug scripts (2026-05-14)
- [x] `.env.example` ↔ README sync (2026-05-14)
- [x] GitHub-ready docs scaffold (CLAUDE.md, docs/, LICENSE, CI) (2026-05-14)

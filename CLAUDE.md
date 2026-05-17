# ShadowScope — Contributor & AI Guide

> Start here. This file is the orientation point for any AI assistant (Claude, Copilot, etc.) or human contributor working in this repo.

## Project

- **Name**: ShadowScope
- **Purpose**: terminal-based IOC enrichment + composite risk scoring for SOC / IR / threat-intel work
- **Root**: this directory
- **Language**: Python 3.10+ (developed on 3.13)
- **Runtime**: standard CPython, no virtualenv mandatory

## Source of truth

[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) is the single authoritative document for module map, data flow, scoring algorithm, and conventions.

[`docs/ROADMAP.md`](docs/ROADMAP.md) is the open work backlog. Update it whenever you finish a task or scope a new one.

[`docs/API_KEYS.md`](docs/API_KEYS.md) is the provider sign-up & free-tier reference.

## Conventions

- **Style**: PEP 8, 4-space indent, type hints on new code
- **Error handling**: API failures return `None` — never crash the CLI
- **Cache pattern**: every new enrichment source wraps its API call in the `should_refresh()` check pattern from `core/enrich.py`
- **Secrets**: only in `ioc_tool/.env` (gitignored). Never `print`, `log`, or commit credentials.
- **Commit prefixes**: `feat:`, `fix:`, `docs:`, `chore:`, `test:`, `refactor:`, `ci:`
- **One feature per PR / commit** — keep diffs reviewable

## Key paths

```
ioc_tool/main.py              — entry point
ioc_tool/ui/cli.py            — interactive menu + CLI flags
ioc_tool/core/enrich.py       — orchestrator (cache → fetch → score)
ioc_tool/core/score.py        — per-source scoring + composite formula
ioc_tool/core/database.py     — SQLite cache wrapper
ioc_tool/core/parser.py       — IOC type detection
ioc_tool/modules/<source>.py  — one file per threat-intel source
ioc_tool/web/                 — FastAPI REST API (shadowscope serve)
ioc_tool/.env.example         — secret template (commit this)
ioc_tool/.env                 — actual secrets (gitignored)
ioc_tool/data/ioc.db          — SQLite cache (gitignored)
docs/                         — architecture, roadmap, API keys
tests/                        — pytest (scaffolded)
.github/workflows/ci.yml      — CI (lint + test)
Dockerfile                    — multi-stage python:3.12-slim, non-root, /health healthcheck
docker-compose.yml            — single-service compose stack (named volume for cache)
.env.example                  — compose-style env template (root); see ioc_tool/.env.example for CLI users
```

## Workflow

1. Read `docs/ARCHITECTURE.md` (or at minimum the relevant module section)
2. Check `docs/ROADMAP.md` and pick the next item — confirm with the user before starting
3. Implement; keep cache + error patterns from existing modules
4. Add or update tests in `tests/`
5. Update `docs/ARCHITECTURE.md` if module map / flow / score formula changed
6. Move item from open backlog to "Done" in `docs/ROADMAP.md`
7. Commit with prefixed message; one feature per commit

## Local dev quick start

```bash
pip install -r requirements.txt
cp ioc_tool/.env.example ioc_tool/.env
nano ioc_tool/.env       # paste keys
python3 -m ioc_tool.main # interactive
```

Smoke test (after tests added):

```bash
pytest -q
```

## Adding a new enrichment source

See the dedicated section in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#adding-a-new-enrichment-source). TL;DR:

1. One file in `ioc_tool/modules/<source>.py` exposing `enrich_ip()` / `enrich_domain()` / `enrich_hash()` / `enrich_cve()` as appropriate.
2. **Always issue HTTP through `core.http`**, never `requests.*` directly. The helper centralises rate limiting, the 429 ledger that drives VT→OTX failover, and uniform timeouts.

   ```python
   from ioc_tool.core import http

   _SOURCE = "mysource"
   _BASE   = "https://api.example.com"
   _TIMEOUT_S = 10.0

   def enrich_ip(ip: str) -> dict | None:
       resp = http.get(_SOURCE, f"{_BASE}/lookup/{ip}", timeout=_TIMEOUT_S)
       if resp is None or resp.status_code != 200:
           return None  # soft-fail contract
       return resp.json()
   ```

3. **Register a rate-limit bucket** for the new source in `ioc_tool/core/ratelimit.py::_DEFAULT_BUCKETS` — even a generous one. The bucket key MUST match the `_SOURCE` string used in `http.get(...)`. Format: `"mysource": (CAPACITY, PERIOD_SECONDS)`. Skipping this step means the source runs unrestricted and risks burning the upstream's free-tier quota in a bulk fan-out.
4. Scoring helper in `core/score.py` if it produces a score; info-only sources should NOT push the composite (see PDNS for the pattern).
5. Wire into `core/enrich.py` next to existing source blocks (preserve the `should_refresh()` cache pattern).
6. Env var (if any) into `ioc_tool/.env.example` and `docs/API_KEYS.md`.
7. Smoke test in `tests/` — mock `core.http.get` with a stub that returns a `_FakeResponse` (see `tests/test_pdns.py` for the pattern).

## Don'ts

- **Don't** commit `.env`, `ioc.db`, malware samples (`*.exe`, `*.dll`), or large cache files — `.gitignore` covers these
- **Don't** display API keys in chat, logs, or error messages
- **Don't** call external APIs in tests — mock with `responses`, `pytest-mock`, or monkeypatched `core.http.get`
- **Don't** introduce new top-level dirs without updating `docs/ARCHITECTURE.md`
- **Don't** push directly to `main` once the repo is public — use feature branches + PRs
- **Don't** use `requests.get` / `requests.post` directly in new modules — route through `ioc_tool.core.http` so the rate-limiter, 429 ledger, and timeouts apply uniformly
- **Don't** accept webhook URLs (or any user-supplied URL pointed at outbound HTTP) without scheme + IP-range validation — treat user-supplied URLs as SSRF surface. The webhook helper in `core.http` is the single point of validation; new outbound paths should reuse it

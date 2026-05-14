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

See the dedicated section in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#adding-a-new-enrichment-source). TL;DR: one file in `ioc_tool/modules/`, scoring helper in `core/score.py`, wire into `core/enrich.py`, env var into `.env.example` + `docs/API_KEYS.md`, smoke test in `tests/`.

## Don'ts

- **Don't** commit `.env`, `ioc.db`, malware samples (`*.exe`, `*.dll`), or large cache files — `.gitignore` covers these
- **Don't** display API keys in chat, logs, or error messages
- **Don't** call external APIs in tests — mock with `responses` or `pytest-mock`
- **Don't** introduce new top-level dirs without updating `docs/ARCHITECTURE.md`
- **Don't** push directly to `main` once the repo is public — use feature branches + PRs

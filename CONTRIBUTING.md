# Contributing to ShadowScope

Thanks for the interest! ShadowScope is an open IOC-enrichment tool for the SOC / IR / threat-intel community. PRs, bug reports, and new-source modules are welcome.

## Quick start

```bash
git clone https://github.com/Raizer1996/Shadow-Scope.git
cd Shadow-Scope
pip install -r requirements.txt
cp ioc_tool/.env.example ioc_tool/.env
# add at least VT_API_KEY + ABUSEIPDB_API_KEY for meaningful output
python3 -m ioc_tool.main
```

## Project orientation

Read these before opening a PR:

1. [`CLAUDE.md`](CLAUDE.md) — conventions, key paths, workflow
2. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — module map, data flow, scoring algorithm
3. [`docs/ROADMAP.md`](docs/ROADMAP.md) — open backlog (pick an item or propose your own)

## How to contribute

### Add a new enrichment source

The most common contribution. See `docs/ARCHITECTURE.md#adding-a-new-enrichment-source` for the step-by-step. Summary:

1. Drop `ioc_tool/modules/<source>.py` with `enrich_ip()` / `enrich_domain()` / etc.
2. Add scoring helper in `ioc_tool/core/score.py` if the source produces a numeric risk signal.
3. Wire into `ioc_tool/core/enrich.py` following the existing cache-aware pattern.
4. Add the env-var name to `ioc_tool/.env.example` **and** `docs/API_KEYS.md`.
5. Add a smoke test in `tests/`.

### Fix a bug

1. Open an issue first if one isn't already tracking it.
2. Reproduce locally; add a failing test if possible.
3. Fix; ensure `pytest` passes.
4. PR with `fix: <short description>` title.

### Improve docs

Doc-only PRs are very welcome. README polish, clearer install steps, screenshots — all good.

## Conventions

- **Style**: PEP 8, 4-space indent, type hints on new code
- **Imports**: stdlib → third-party → local (blank line between groups)
- **Error handling**: API failures return `None`; never crash the CLI
- **Logging**: prefer `rich.print()` or `print()` for user-facing output; no key/secret leaks
- **Commits**: prefixed (`feat:`, `fix:`, `docs:`, `chore:`, `test:`, `refactor:`, `ci:`)
- **One feature per PR** — keep diffs reviewable

## Tests

```bash
pytest -q
```

External APIs are mocked with the `responses` lib — tests must never hit live services. The pattern is:

```python
@responses.activate
def test_vt_enrich_ip(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "fake-key-for-test")
    responses.add(
        responses.GET,
        "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4",
        json={"data": {"attributes": {"last_analysis_stats": {"malicious": 5}}}},
        status=200,
    )
    assert vt.enrich_ip("1.2.3.4")["last_analysis_stats"]["malicious"] == 5
```

See `tests/test_modules.py` for the full set.

## PR checklist

- [ ] Branch from `main`, named `feat/<scope>` / `fix/<scope>` / `docs/<scope>`
- [ ] Code follows PEP 8 + project conventions
- [ ] Tests added / updated and pass locally
- [ ] `docs/ARCHITECTURE.md` updated if module map / flow / scoring changed
- [ ] `docs/ROADMAP.md` updated if a backlog item is now done
- [ ] No secrets, no live API calls in tests
- [ ] Commit messages use prefix convention

## Reporting security issues

If you find a vulnerability in ShadowScope itself (not in a queried source), please open a private security advisory on GitHub rather than a public issue.

## License

By contributing you agree your contributions are licensed under the project's [MIT License](LICENSE).

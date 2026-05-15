"""Cache-policy tests — TTL env, --no-cache flag, freshness boundary."""

from datetime import datetime, timedelta

from ioc_tool.core import enrich

# ---------------------------------------------------------------------------
# CACHE_TTL_HOURS env
# ---------------------------------------------------------------------------


def test_cache_ttl_defaults_to_24h(monkeypatch):
    monkeypatch.delenv("CACHE_TTL_HOURS", raising=False)
    assert enrich._cache_ttl_hours() == 24.0


def test_cache_ttl_reads_env(monkeypatch):
    monkeypatch.setenv("CACHE_TTL_HOURS", "1")
    assert enrich._cache_ttl_hours() == 1.0


def test_cache_ttl_supports_fractional(monkeypatch):
    monkeypatch.setenv("CACHE_TTL_HOURS", "0.5")
    assert enrich._cache_ttl_hours() == 0.5


def test_cache_ttl_unparseable_falls_back(monkeypatch):
    monkeypatch.setenv("CACHE_TTL_HOURS", "not-a-number")
    assert enrich._cache_ttl_hours() == 24.0


def test_cache_ttl_zero_falls_back(monkeypatch):
    monkeypatch.setenv("CACHE_TTL_HOURS", "0")
    assert enrich._cache_ttl_hours() == 24.0


def test_cache_ttl_negative_falls_back(monkeypatch):
    monkeypatch.setenv("CACHE_TTL_HOURS", "-5")
    assert enrich._cache_ttl_hours() == 24.0


def test_cache_ttl_empty_string_falls_back(monkeypatch):
    monkeypatch.setenv("CACHE_TTL_HOURS", "")
    assert enrich._cache_ttl_hours() == 24.0


# ---------------------------------------------------------------------------
# should_refresh honours CACHE_TTL_HOURS
# ---------------------------------------------------------------------------


def _ts(delta: timedelta) -> str:
    """Return a SQLite-style timestamp ``now - delta``."""
    return (datetime.now() - delta).strftime("%Y-%m-%d %H:%M:%S")


def test_should_refresh_returns_true_for_empty():
    assert enrich.should_refresh(None) is True
    assert enrich.should_refresh("") is True


def test_should_refresh_returns_true_for_unparseable():
    assert enrich.should_refresh("not-a-date") is True


def test_should_refresh_default_24h_boundary(monkeypatch):
    monkeypatch.delenv("CACHE_TTL_HOURS", raising=False)
    # 12 h old → still fresh under the 24 h default
    assert enrich.should_refresh(_ts(timedelta(hours=12))) is False
    # 25 h old → stale
    assert enrich.should_refresh(_ts(timedelta(hours=25))) is True


def test_should_refresh_short_ttl_makes_old_rows_stale(monkeypatch):
    """A 1-hour TTL must mark a 2-hour-old row stale even though it'd be fresh under default."""
    monkeypatch.setenv("CACHE_TTL_HOURS", "1")
    assert enrich.should_refresh(_ts(timedelta(hours=2))) is True


def test_should_refresh_long_ttl_keeps_old_rows_fresh(monkeypatch):
    """A 168-hour TTL (1 week) must keep a 3-day-old row fresh."""
    monkeypatch.setenv("CACHE_TTL_HOURS", "168")
    assert enrich.should_refresh(_ts(timedelta(days=3))) is False


# ---------------------------------------------------------------------------
# --no-cache flag
# ---------------------------------------------------------------------------


def test_no_cache_arg_bypasses_cache_hit(monkeypatch, tmp_path):
    """When no_cache=True, even a fresh cached row triggers a refetch."""
    from ioc_tool.core import database as _db
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "ioc.db"))
    _db.init_db()

    # Seed a "fresh" cached row.
    ioc_id = _db.add_or_update_ioc("8.8.8.8", "ip")
    _db.add_enrichment(ioc_id, "virustotal", '{"stale": "yes"}', 42)

    fetcher_calls = []

    def _fetcher():
        fetcher_calls.append(1)
        return {"fresh": True}

    # no_cache=False → cached row wins, fetcher never called
    enrich._run_source(
        ioc_id, "virustotal", "VirusTotal",
        _fetcher, lambda d: 0,
        no_cache=False,
    )
    assert fetcher_calls == []  # cache hit, no fetch

    # no_cache=True → cache skipped, fetcher runs
    enrich._run_source(
        ioc_id, "virustotal", "VirusTotal",
        _fetcher, lambda d: 0,
        no_cache=True,
    )
    assert fetcher_calls == [1]  # forced refetch


def test_no_cache_ctxvar_bypasses_cache_hit(monkeypatch, tmp_path):
    """The ContextVar path works too — that's how the CLI flag propagates."""
    from ioc_tool.core import database as _db
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "ioc.db"))
    _db.init_db()

    ioc_id = _db.add_or_update_ioc("1.2.3.4", "ip")
    _db.add_enrichment(ioc_id, "abuseipdb", '{"x": 1}', 0)

    fetcher_calls = []

    def _fetcher():
        fetcher_calls.append(1)
        return {"fresh": True}

    token = enrich.no_cache_ctx.set(True)
    try:
        enrich._run_source(
            ioc_id, "abuseipdb", "AbuseIPDB",
            _fetcher, lambda d: 0,
        )
    finally:
        enrich.no_cache_ctx.reset(token)
    assert fetcher_calls == [1]


def test_cli_parser_accepts_no_cache_flag():
    """The --no-cache flag should be recognised on the enrich subcommand."""
    from ioc_tool.ui import cli
    parser = cli.build_parser()
    args = parser.parse_args(['enrich', '8.8.8.8', '--no-cache'])
    assert args.no_cache is True


def test_cli_parser_no_cache_defaults_false():
    from ioc_tool.ui import cli
    parser = cli.build_parser()
    args = parser.parse_args(['enrich', '8.8.8.8'])
    assert args.no_cache is False

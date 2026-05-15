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

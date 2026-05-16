"""Tests for cache-retention functions: prune by age, keep-last-N, clear, stats."""

from datetime import datetime, timedelta

import pytest


# ---------------------------------------------------------------------------
# helpers — every test uses a tmp_path-backed SQLite so we never touch the
# analyst's real ioc.db. Pattern matches tests/test_cache.py.
# ---------------------------------------------------------------------------


@pytest.fixture
def db(monkeypatch, tmp_path):
    from ioc_tool.core import database as _db
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "ioc.db"))
    _db.init_db()
    return _db


def _seed_row(db, ioc_value: str, source: str, age: timedelta, score: int = 50) -> int:
    """Insert one enrichment row aged ``now - age``. Returns ioc_id."""
    ioc_id = db.add_or_update_ioc(ioc_value, "ip")
    ts = (datetime.now() - age).strftime("%Y-%m-%d %H:%M:%S")
    conn = db.get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO enrichments (ioc_id, source, data, timestamp, score) VALUES (?,?,?,?,?)",
        (ioc_id, source, "{}", ts, score),
    )
    conn.commit()
    conn.close()
    return ioc_id


def _count_enrichments(db) -> int:
    conn = db.get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM enrichments")
    n = int(cur.fetchone()[0])
    conn.close()
    return n


# ---------------------------------------------------------------------------
# prune_enrichments_older_than
# ---------------------------------------------------------------------------


def test_prune_older_than_removes_stale_rows(db):
    _seed_row(db, "1.1.1.1", "vt", timedelta(days=120))   # stale
    _seed_row(db, "1.1.1.1", "vt", timedelta(days=10))    # fresh
    removed = db.prune_enrichments_older_than(90)
    assert removed == 1
    assert _count_enrichments(db) == 1


def test_prune_older_than_keeps_everything_when_younger(db):
    _seed_row(db, "1.1.1.1", "vt", timedelta(days=5))
    _seed_row(db, "1.1.1.1", "abuseipdb", timedelta(days=10))
    removed = db.prune_enrichments_older_than(90)
    assert removed == 0
    assert _count_enrichments(db) == 2


def test_prune_older_than_zero_is_noop(db):
    """Zero / negative retention must not wipe the cache."""
    _seed_row(db, "1.1.1.1", "vt", timedelta(days=365))
    assert db.prune_enrichments_older_than(0) == 0
    assert db.prune_enrichments_older_than(-5) == 0
    assert _count_enrichments(db) == 1


def test_prune_older_than_supports_fractional_days(db):
    _seed_row(db, "1.1.1.1", "vt", timedelta(hours=20))    # > 0.5d
    _seed_row(db, "1.1.1.1", "abuseipdb", timedelta(hours=2))  # < 0.5d
    removed = db.prune_enrichments_older_than(0.5)
    assert removed == 1


# ---------------------------------------------------------------------------
# prune_enrichments_keep_last_n
# ---------------------------------------------------------------------------


def test_keep_last_n_per_source_pair(db):
    # 5 rows for same (ioc, source) — newest 2 should survive
    for i in range(5):
        _seed_row(db, "2.2.2.2", "vt", timedelta(hours=i))
    removed = db.prune_enrichments_keep_last_n(2)
    assert removed == 3
    assert _count_enrichments(db) == 2


def test_keep_last_n_isolates_per_source(db):
    """Cap applies independently to each (ioc, source) group."""
    for i in range(4):
        _seed_row(db, "3.3.3.3", "vt", timedelta(hours=i))
        _seed_row(db, "3.3.3.3", "abuseipdb", timedelta(hours=i))
    removed = db.prune_enrichments_keep_last_n(1)
    # 4 vt - 1 + 4 abuseipdb - 1 = 6
    assert removed == 6
    assert _count_enrichments(db) == 2


def test_keep_last_n_zero_is_noop(db):
    _seed_row(db, "4.4.4.4", "vt", timedelta(hours=1))
    assert db.prune_enrichments_keep_last_n(0) == 0
    assert db.prune_enrichments_keep_last_n(-3) == 0
    assert _count_enrichments(db) == 1


# ---------------------------------------------------------------------------
# clear_enrichments
# ---------------------------------------------------------------------------


def test_clear_by_source(db):
    _seed_row(db, "5.5.5.5", "vt", timedelta(hours=1))
    _seed_row(db, "5.5.5.5", "abuseipdb", timedelta(hours=1))
    removed = db.clear_enrichments(source="vt")
    assert removed == 1
    assert _count_enrichments(db) == 1


def test_clear_by_ioc_value(db):
    _seed_row(db, "6.6.6.6", "vt", timedelta(hours=1))
    _seed_row(db, "6.6.6.6", "abuseipdb", timedelta(hours=1))
    _seed_row(db, "7.7.7.7", "vt", timedelta(hours=1))
    removed = db.clear_enrichments(ioc_value="6.6.6.6")
    assert removed == 2
    assert _count_enrichments(db) == 1


def test_clear_all(db):
    _seed_row(db, "8.8.8.8", "vt", timedelta(hours=1))
    _seed_row(db, "9.9.9.9", "vt", timedelta(hours=1))
    removed = db.clear_enrichments(all=True)
    assert removed == 2
    assert _count_enrichments(db) == 0


def test_clear_requires_exactly_one_filter(db):
    _seed_row(db, "8.8.8.8", "vt", timedelta(hours=1))
    with pytest.raises(ValueError):
        db.clear_enrichments()  # no filter
    with pytest.raises(ValueError):
        db.clear_enrichments(source="vt", all=True)  # two filters


# ---------------------------------------------------------------------------
# cache_stats
# ---------------------------------------------------------------------------


def test_cache_stats_empty(db):
    stats = db.cache_stats()
    assert stats["ioc_count"] == 0
    assert stats["enrichment_count"] == 0
    assert stats["oldest_timestamp"] is None
    assert stats["newest_timestamp"] is None
    assert stats["per_source"] == []


def test_cache_stats_populated(db):
    _seed_row(db, "1.1.1.1", "vt", timedelta(hours=10))
    _seed_row(db, "1.1.1.1", "vt", timedelta(hours=1))
    _seed_row(db, "1.1.1.1", "abuseipdb", timedelta(hours=5))
    stats = db.cache_stats()
    assert stats["ioc_count"] == 1
    assert stats["enrichment_count"] == 3
    assert stats["oldest_timestamp"] is not None
    assert stats["newest_timestamp"] >= stats["oldest_timestamp"]
    by_src = {r["source"]: r["rows"] for r in stats["per_source"]}
    assert by_src == {"vt": 2, "abuseipdb": 1}


# ---------------------------------------------------------------------------
# meta key-value (used by auto-prune scheduling)
# ---------------------------------------------------------------------------


def test_meta_get_missing_returns_none(db):
    assert db.get_meta("nope") is None


def test_meta_set_then_get_roundtrip(db):
    db.set_meta("last_prune", "2026-05-16T10:00:00")
    assert db.get_meta("last_prune") == "2026-05-16T10:00:00"


def test_meta_set_overwrites_existing(db):
    db.set_meta("k", "v1")
    db.set_meta("k", "v2")
    assert db.get_meta("k") == "v2"


# ---------------------------------------------------------------------------
# auto-prune hook in core/enrich.py
# ---------------------------------------------------------------------------


@pytest.fixture
def fresh_auto_prune_state(monkeypatch):
    """Reset the module-level ``_auto_prune_done`` set per test."""
    from ioc_tool.core import enrich
    monkeypatch.setattr(enrich, "_auto_prune_done", set())
    return enrich


def test_retention_days_defaults_to_90(monkeypatch, fresh_auto_prune_state):
    monkeypatch.delenv("RETENTION_DAYS", raising=False)
    assert fresh_auto_prune_state._retention_days() == 90.0


def test_retention_days_reads_env(monkeypatch, fresh_auto_prune_state):
    monkeypatch.setenv("RETENTION_DAYS", "30")
    assert fresh_auto_prune_state._retention_days() == 30.0


def test_retention_days_unparseable_falls_back(monkeypatch, fresh_auto_prune_state):
    monkeypatch.setenv("RETENTION_DAYS", "garbage")
    assert fresh_auto_prune_state._retention_days() == 90.0


def test_retention_days_zero_falls_back(monkeypatch, fresh_auto_prune_state):
    monkeypatch.setenv("RETENTION_DAYS", "0")
    assert fresh_auto_prune_state._retention_days() == 90.0


def test_auto_prune_disabled_when_env_zero(monkeypatch, fresh_auto_prune_state):
    monkeypatch.setenv("AUTO_PRUNE", "0")
    assert fresh_auto_prune_state._auto_prune_enabled() is False


def test_auto_prune_default_enabled(monkeypatch, fresh_auto_prune_state):
    monkeypatch.delenv("AUTO_PRUNE", raising=False)
    assert fresh_auto_prune_state._auto_prune_enabled() is True


def test_maybe_auto_prune_removes_stale_rows(db, monkeypatch, fresh_auto_prune_state):
    """With RETENTION_DAYS=10 and a 30-day-old row, the hook should drop it."""
    monkeypatch.setenv("RETENTION_DAYS", "10")
    monkeypatch.setenv("AUTO_PRUNE", "1")
    _seed_row(db, "1.1.1.1", "vt", timedelta(days=30))
    _seed_row(db, "1.1.1.1", "abuseipdb", timedelta(days=2))

    fresh_auto_prune_state.maybe_auto_prune()

    assert _count_enrichments(db) == 1
    # Records last_prune so the second call is a no-op.
    assert db.get_meta("last_prune") is not None


def test_maybe_auto_prune_skips_when_recent(db, monkeypatch, fresh_auto_prune_state):
    """If last_prune is < 24h ago, the hook is a no-op even with stale rows."""
    monkeypatch.setenv("RETENTION_DAYS", "10")
    monkeypatch.setenv("AUTO_PRUNE", "1")
    _seed_row(db, "1.1.1.1", "vt", timedelta(days=30))
    db.set_meta("last_prune", (datetime.now() - timedelta(hours=1)).isoformat())

    fresh_auto_prune_state.maybe_auto_prune()
    assert _count_enrichments(db) == 1  # stale row still present


def test_maybe_auto_prune_runs_when_last_prune_is_old(db, monkeypatch, fresh_auto_prune_state):
    monkeypatch.setenv("RETENTION_DAYS", "10")
    monkeypatch.setenv("AUTO_PRUNE", "1")
    _seed_row(db, "1.1.1.1", "vt", timedelta(days=30))
    db.set_meta("last_prune", (datetime.now() - timedelta(hours=48)).isoformat())

    fresh_auto_prune_state.maybe_auto_prune()
    assert _count_enrichments(db) == 0


def test_maybe_auto_prune_respects_disable_env(db, monkeypatch, fresh_auto_prune_state):
    monkeypatch.setenv("RETENTION_DAYS", "10")
    monkeypatch.setenv("AUTO_PRUNE", "0")
    _seed_row(db, "1.1.1.1", "vt", timedelta(days=30))

    fresh_auto_prune_state.maybe_auto_prune()
    assert _count_enrichments(db) == 1  # untouched
    assert db.get_meta("last_prune") is None  # never recorded


def test_maybe_auto_prune_only_runs_once_per_process(db, monkeypatch, fresh_auto_prune_state):
    """Even with no last_prune marker, the in-memory guard short-circuits."""
    monkeypatch.setenv("RETENTION_DAYS", "10")
    monkeypatch.setenv("AUTO_PRUNE", "1")
    _seed_row(db, "1.1.1.1", "vt", timedelta(days=30))

    fresh_auto_prune_state.maybe_auto_prune()
    assert _count_enrichments(db) == 0
    # Add another stale row and clear the meta marker — second call must
    # NOT touch it because the in-memory guard already saw this workspace.
    _seed_row(db, "2.2.2.2", "vt", timedelta(days=30))
    conn = db.get_db_connection()
    conn.execute("DELETE FROM meta WHERE key = 'last_prune'")
    conn.commit()
    conn.close()

    fresh_auto_prune_state.maybe_auto_prune()
    assert _count_enrichments(db) == 1  # untouched by second call

"""Tests for the score_history snapshot table + helpers.

Cover three behaviours:

1. ``update_last_score`` writes a snapshot row alongside the iocs UPDATE.
2. ``get_score_history`` returns rows in chronological order, respects
   the limit clamp, and tolerates a non-existent IOC.
3. The schema is forward-compat — an older DB without the table picks
   the table up on the next ``init_db`` call (idempotent).
"""

from __future__ import annotations

import pytest

from ioc_tool.core import database


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "ioc.db"))
    database.init_db()
    yield database


def _insert_ioc(db, value="evil.example", ioc_type="domain") -> int:
    conn = db.get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO iocs (value, type, first_seen, last_seen) "
            "VALUES (?, ?, datetime('now'), datetime('now'))",
            (value, ioc_type),
        )
        conn.commit()
        return int(cur.lastrowid or 0)
    finally:
        conn.close()


def test_update_last_score_appends_history(db):
    ioc_id = _insert_ioc(db)
    db.update_last_score(ioc_id, 42)
    db.update_last_score(ioc_id, 80)

    history = db.get_score_history(ioc_id)
    assert [row["score"] for row in history] == [42, 80]


def test_get_score_history_chronological(db):
    ioc_id = _insert_ioc(db)
    db.update_last_score(ioc_id, 10)
    # Same-millisecond inserts: id breaks the tie so we still see
    # insertion order.
    db.update_last_score(ioc_id, 20)
    db.update_last_score(ioc_id, 30)

    history = db.get_score_history(ioc_id)
    assert [row["score"] for row in history] == [10, 20, 30]


def test_get_score_history_limit_clamp(db):
    ioc_id = _insert_ioc(db)
    for i in range(5):
        db.update_last_score(ioc_id, i)

    out = db.get_score_history(ioc_id, limit=3)
    assert len(out) == 3
    # ORDER BY recorded_at ASC, id ASC → first 3 inserted snapshots win.
    assert [row["score"] for row in out] == [0, 1, 2]


def test_get_score_history_invalid_limit(db):
    ioc_id = _insert_ioc(db)
    db.update_last_score(ioc_id, 5)
    assert db.get_score_history(ioc_id, limit=0) == []
    assert db.get_score_history(ioc_id, limit=-1) == []


def test_get_score_history_unknown_ioc(db):
    assert db.get_score_history(99999) == []


def test_update_last_score_stamps_iocs_row_too(db):
    """Snapshot must not break the original `last_score` stamp."""
    ioc_id = _insert_ioc(db)
    db.update_last_score(ioc_id, 73)

    conn = db.get_db_connection()
    try:
        row = conn.execute(
            "SELECT last_score FROM iocs WHERE id = ?", (ioc_id,)
        ).fetchone()
    finally:
        conn.close()
    assert int(row["last_score"]) == 73


def test_init_db_idempotent_on_existing_history(db):
    """Second init_db must not blow away the history rows."""
    ioc_id = _insert_ioc(db)
    db.update_last_score(ioc_id, 50)
    assert len(db.get_score_history(ioc_id)) == 1

    db.init_db()
    assert len(db.get_score_history(ioc_id)) == 1

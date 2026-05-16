"""Tests for the `enrichment_fields` pivot index.

Cover three things:
  1. ``_iter_indexable_fields`` extracts the right (kind, value) tuples
     from a representative payload (tag arrays, malware/family strings,
     registrar in WHOIS).
  2. ``add_enrichment`` populates the side table as it inserts.
  3. ``find_iocs_by_field`` returns the same rows via the indexed lookup
     that the old LIKE path returned (regression guard against pivot
     behaviour drift).
  4. ``rebuild_field_index`` (and the init-time backfill) catches up a
     legacy cache where enrichments exist but the index is empty.
"""

from __future__ import annotations

import json

import pytest

from ioc_tool.core import database


@pytest.fixture
def db(tmp_path, monkeypatch):
    """Point the SQLite path at a per-test file and init the schema."""
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "ioc.db"))
    database.init_db()
    yield database


# ---------------------------------------------------------------------------
# Extractor
# ---------------------------------------------------------------------------


def test_extract_tag_string_array():
    payload = {"tags": ["emotet", "phishing"]}
    pairs = list(database._iter_indexable_fields(payload))
    assert ("tag", "emotet") in pairs
    assert ("tag", "phishing") in pairs


def test_extract_malware_and_family():
    payload = {
        "malware": "AgentTesla",
        "signature": "AgentTesla_Loader",
    }
    pairs = list(database._iter_indexable_fields(payload))
    assert ("malware", "AgentTesla") in pairs
    assert ("family", "AgentTesla_Loader") in pairs


def test_extract_registrar_from_whois_shape():
    payload = {"registrar": "NameSilo, LLC", "creation_date": "2024-01-01"}
    pairs = list(database._iter_indexable_fields(payload))
    assert ("registrar", "NameSilo, LLC") in pairs


def test_extract_recurses_into_nested_dicts():
    payload = {
        "extra": {"meta": {"malware": "Emotet"}},
        "tags": ["c2"],
    }
    pairs = list(database._iter_indexable_fields(payload))
    assert ("malware", "Emotet") in pairs
    assert ("tag", "c2") in pairs


def test_extract_ignores_non_string_values():
    payload = {"malware": 42, "tags": [None, "ok", 7]}
    pairs = list(database._iter_indexable_fields(payload))
    assert ("malware", 42) not in pairs
    assert ("tag", "ok") in pairs
    # None / int entries silently skipped.
    assert len([p for p in pairs if p[0] == "tag"]) == 1


# ---------------------------------------------------------------------------
# add_enrichment populates the index
# ---------------------------------------------------------------------------


def _insert_ioc(db, value, ioc_type="domain") -> int:
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


def _field_rows(db):
    conn = db.get_db_connection()
    try:
        rows = conn.execute(
            "SELECT kind, value FROM enrichment_fields ORDER BY kind, value"
        ).fetchall()
        return [(r["kind"], r["value"]) for r in rows]
    finally:
        conn.close()


def test_add_enrichment_writes_fields(db):
    ioc_id = _insert_ioc(db, "evil.example", "domain")
    db.add_enrichment(ioc_id, "threatfox", {"malware": "Emotet", "tags": ["c2"]}, 80)
    rows = _field_rows(db)
    assert ("malware", "Emotet") in rows
    assert ("tag", "c2") in rows


def test_add_enrichment_dedupes_within_a_row(db):
    ioc_id = _insert_ioc(db, "evil.example", "domain")
    db.add_enrichment(
        ioc_id, "threatfox",
        {"tags": ["c2", "c2", "C2"]},  # case-insensitive dup
        80,
    )
    tag_rows = [v for k, v in _field_rows(db) if k == "tag"]
    # Original casing of first hit wins; duplicates collapsed.
    assert tag_rows == ["c2"]


# ---------------------------------------------------------------------------
# find_iocs_by_field round-trips via the index
# ---------------------------------------------------------------------------


def test_find_iocs_by_field_uses_index(db):
    id1 = _insert_ioc(db, "evil-1.example", "domain")
    id2 = _insert_ioc(db, "evil-2.example", "domain")
    _insert_ioc(db, "unrelated.example", "domain")
    db.add_enrichment(id1, "threatfox", {"malware": "Emotet"}, 80)
    db.add_enrichment(id2, "malwarebazaar", {"signature": "Emotet"}, 70)

    hits = db.find_iocs_by_field("Emotet", kind="malware", limit=10)
    values = {h["value"] for h in hits}
    assert "evil-1.example" in values
    # malwarebazaar stores family under 'signature' → kind='family', so
    # a 'malware' pivot must NOT return evil-2 (regression guard against
    # accidental cross-kind matching).
    assert "evil-2.example" not in values


def test_find_iocs_by_field_family_via_signature(db):
    id1 = _insert_ioc(db, "evil-2.example", "domain")
    db.add_enrichment(id1, "malwarebazaar", {"signature": "Emotet"}, 70)

    hits = db.find_iocs_by_field("Emotet", kind="family", limit=10)
    assert any(h["value"] == "evil-2.example" for h in hits)


def test_find_iocs_by_field_case_insensitive(db):
    ioc_id = _insert_ioc(db, "evil.example", "domain")
    db.add_enrichment(ioc_id, "threatfox", {"malware": "Emotet"}, 80)
    hits = db.find_iocs_by_field("emotet", kind="malware", limit=10)
    assert len(hits) == 1


def test_find_iocs_by_field_excludes_value(db):
    id1 = _insert_ioc(db, "evil-1.example", "domain")
    id2 = _insert_ioc(db, "evil-2.example", "domain")
    db.add_enrichment(id1, "threatfox", {"malware": "Emotet"}, 80)
    db.add_enrichment(id2, "threatfox", {"malware": "Emotet"}, 80)

    hits = db.find_iocs_by_field(
        "Emotet", kind="malware", limit=10, exclude_value="evil-1.example"
    )
    values = {h["value"] for h in hits}
    assert values == {"evil-2.example"}


# ---------------------------------------------------------------------------
# Backfill catches up a legacy cache
# ---------------------------------------------------------------------------


def test_backfill_repopulates_empty_index(db):
    ioc_id = _insert_ioc(db, "evil.example", "domain")
    db.add_enrichment(ioc_id, "threatfox", {"malware": "Emotet"}, 80)

    # Simulate a legacy DB: blow away the index, the rebuild rebuilds.
    conn = db.get_db_connection()
    conn.execute("DELETE FROM enrichment_fields")
    conn.commit()
    conn.close()
    assert _field_rows(db) == []

    written = db.rebuild_field_index()
    assert written >= 1
    assert ("malware", "Emotet") in _field_rows(db)


def test_backfill_skips_unparseable_payloads(db):
    """Bad JSON in `enrichments.data` must not crash the backfill."""
    ioc_id = _insert_ioc(db, "evil.example", "domain")
    conn = db.get_db_connection()
    conn.execute(
        "INSERT INTO enrichments (ioc_id, source, data, timestamp, score) "
        "VALUES (?, ?, ?, datetime('now'), ?)",
        (ioc_id, "broken", "{not-valid-json", 0),
    )
    # And a good row so we have something to index.
    conn.execute(
        "INSERT INTO enrichments (ioc_id, source, data, timestamp, score) "
        "VALUES (?, ?, ?, datetime('now'), ?)",
        (ioc_id, "threatfox", json.dumps({"malware": "Trickbot"}), 80),
    )
    conn.execute("DELETE FROM enrichment_fields")
    conn.commit()
    conn.close()

    written = db.rebuild_field_index()
    assert written >= 1
    assert ("malware", "Trickbot") in _field_rows(db)

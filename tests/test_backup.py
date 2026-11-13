"""Backup and restore of the local database (core.backup + /api/ui/backup, /api/ui/restore)."""

from __future__ import annotations

import glob
import sqlite3

import pytest
from fastapi.testclient import TestClient

from ioc_tool.core import backup
from ioc_tool.core import database as _db
from ioc_tool.web import api

client = TestClient(api.app)
CONFIRM = {"X-Confirm": "restore"}


@pytest.fixture
def db(monkeypatch, tmp_path):
    monkeypatch.delenv("SHADOWSCOPE_API_TOKEN", raising=False)
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "ioc.db"))
    _db.init_db()
    ioc_id = _db.add_or_update_ioc("203.0.113.10", "ip")
    _db.add_enrichment(ioc_id, "abuseipdb", {"abuseConfidenceScore": 100}, 100)
    _db.update_last_score(ioc_id, 90, 2)
    _db.add_note(ioc_id, "keep me")
    _db.set_verdict(ioc_id, "malicious")
    return tmp_path


def _download():
    r = client.get("/api/ui/backup")
    assert r.status_code == 200, r.text
    return r


def test_backup_download_is_a_valid_complete_copy(db):
    r = _download()
    assert r.headers["content-type"] == "application/octet-stream"
    assert 'filename="shadowscope-backup-' in r.headers["content-disposition"]
    assert r.content[:16] == b"SQLite format 3\x00"
    copy = db / "copy.db"
    copy.write_bytes(r.content)
    info = backup.inspect(str(copy))
    assert info["counts"]["iocs"] == 1 and info["counts"]["enrichments"] == 1 and info["counts"]["ioc_notes"] == 1
    con = sqlite3.connect(copy)
    assert con.execute("SELECT verdict FROM iocs").fetchone()[0] == "malicious"
    con.close()
    # Nothing is left behind next to the live database.
    assert glob.glob(str(db / "*.tmp")) == []


def test_restore_round_trip_saves_the_current_database_first(db):
    saved = _download().content
    # Change the live data after the backup was taken.
    other = _db.add_or_update_ioc("198.51.100.5", "ip")
    _db.add_note(other, "added later")
    _db.set_verdict(_db.get_ioc_id("203.0.113.10"), "benign")

    preview = client.post("/api/ui/restore", params={"dry_run": "true"}, content=saved)
    assert preview.status_code == 200, preview.text
    body = preview.json()
    assert body["dry_run"] is True
    assert body["backup"]["counts"]["iocs"] == 1 and body["current"]["iocs"] == 2
    assert _db.get_ioc_id("198.51.100.5") is not None  # dry run changed nothing
    assert glob.glob(str(db / "*.pre-restore-*.bak")) == []

    done = client.post("/api/ui/restore", content=saved, headers=CONFIRM)
    assert done.status_code == 200, done.text
    out = done.json()
    assert out["restored"]["iocs"] == 1 and out["previous_saved_as"].startswith("ioc.db.pre-restore-")
    assert _db.get_ioc_id("198.51.100.5") is None
    assert _db.get_verdict(_db.get_ioc_id("203.0.113.10"))["verdict"] == "malicious"
    assert [n["body"] for n in _db.list_notes(_db.get_ioc_id("203.0.113.10"))] == ["keep me"]

    # The replaced database is still on disk and still holds the later data.
    kept = glob.glob(str(db / "ioc.db.pre-restore-*.bak"))
    assert len(kept) == 1
    assert backup.inspect(kept[0])["counts"]["iocs"] == 2


def test_restore_needs_explicit_confirmation(db):
    saved = _download().content
    assert client.post("/api/ui/restore", content=saved).status_code == 400
    assert client.post("/api/ui/restore", content=saved, headers={"X-Confirm": "yes"}).status_code == 400
    assert _db.get_ioc_id("203.0.113.10") is not None


def test_restore_rejects_files_that_are_not_shadowscope_backups(db):
    def attempt(payload):
        r = client.post("/api/ui/restore", content=payload, headers=CONFIRM)
        return r.status_code, r.json().get("detail", "")

    assert attempt(b"") == (422, "empty upload")
    assert attempt(b"hello, this is not a database")[1] == "not a SQLite database file"
    # Real SQLite, wrong application.
    foreign = db / "foreign.db"
    con = sqlite3.connect(foreign)
    con.execute("CREATE TABLE cats (name TEXT)")
    con.commit()
    con.close()
    status, detail = attempt(foreign.read_bytes())
    assert status == 422 and detail.startswith("not a ShadowScope database")
    # Truncated SQLite file.
    status, detail = attempt(_download().content[:3000])
    assert status == 422
    # Live data untouched by any of it, and no pre-restore copies made.
    assert _db.get_ioc_id("203.0.113.10") is not None
    assert glob.glob(str(db / "*.pre-restore-*.bak")) == []
    assert glob.glob(str(db / "*.tmp")) == []


def test_upload_size_cap(db, monkeypatch):
    monkeypatch.setattr(api, "_RESTORE_MAX_BYTES", 1000)
    r = client.post("/api/ui/restore", content=b"x" * 5000, headers=CONFIRM)
    assert r.status_code == 413
    assert glob.glob(str(db / "*.tmp")) == []


def test_old_schema_backup_is_migrated_on_restore(db):
    old = db / "old.db"
    con = sqlite3.connect(old)
    con.execute("CREATE TABLE iocs (id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT UNIQUE NOT NULL, "
                "type TEXT NOT NULL, first_seen TIMESTAMP, last_seen TIMESTAMP, tags TEXT)")
    con.execute("CREATE TABLE enrichments (id INTEGER PRIMARY KEY AUTOINCREMENT, ioc_id INTEGER, source TEXT, "
                "data TEXT, timestamp TIMESTAMP, score INTEGER)")
    con.execute("INSERT INTO iocs (value, type) VALUES ('8.8.8.8', 'ip')")
    con.commit()
    con.close()
    assert client.post("/api/ui/restore", content=old.read_bytes(), headers=CONFIRM).status_code == 200
    ioc_id = _db.get_ioc_id("8.8.8.8")
    _db.set_verdict(ioc_id, "benign")  # column added by the migration
    assert _db.get_verdict(ioc_id)["verdict"] == "benign"


def test_only_the_newest_pre_restore_copies_are_kept(db):
    saved = _download().content
    src = db / "src.db"
    src.write_bytes(saved)
    for n in range(5):
        (db / f"ioc.db.pre-restore-2020010{n}-000000.bak").write_bytes(saved)
    backup.restore(str(src))
    kept = sorted(p.rsplit("pre-restore-", 1)[1] for p in glob.glob(str(db / "ioc.db.pre-restore-*.bak")))
    assert len(kept) == backup.KEEP_PRE_RESTORE and kept[0].startswith("20200103")

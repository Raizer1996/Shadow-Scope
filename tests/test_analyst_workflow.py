"""Cases management, manual verdict, notes and watchlist (API + DB)."""

from __future__ import annotations

import sqlite3

import pytest
from fastapi.testclient import TestClient

from ioc_tool.core import database as _db
from ioc_tool.web import api

client = TestClient(api.app)


@pytest.fixture
def db(monkeypatch, tmp_path):
    monkeypatch.delenv("SHADOWSCOPE_API_TOKEN", raising=False)
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "ioc.db"))
    _db.init_db()
    ids = {}
    for value, kind, score in (("203.0.113.70", "ip", 90), ("evil.example", "domain", 30)):
        ids[value] = _db.add_or_update_ioc(value, kind)
        _db.update_last_score(ids[value], score, 2)
    return ids


def test_verdict_set_clear_and_validation(db):
    r = client.post(
        "/api/ui/verdict",
        json={"ioc": "203[.]0[.]113[.]70", "verdict": "false_positive", "note": "our scanner"},
    )
    assert r.status_code == 200 and r.json()["verdict"]["verdict"] == "false_positive"
    assert _db.get_verdict(db["203.0.113.70"])["note"] == "our scanner"
    cleared = client.post("/api/ui/verdict", json={"ioc": "203.0.113.70", "verdict": None})
    assert cleared.json()["verdict"] is None
    assert client.post("/api/ui/verdict", json={"ioc": "203.0.113.70", "verdict": "evil"}).status_code == 422
    assert client.post("/api/ui/verdict", json={"ioc": "198.51.100.1", "verdict": "benign"}).status_code == 404


def test_notes_add_list_delete(db):
    r = client.post("/api/ui/notes", json={"ioc": "evil.example", "body": "seen in phishing mail"})
    notes = r.json()["notes"]
    assert [n["body"] for n in notes] == ["seen in phishing mail"]
    assert client.post("/api/ui/notes", json={"ioc": "evil.example", "body": "   "}).status_code == 422
    assert client.delete(f"/api/ui/notes/{notes[0]['id']}").json() == {"removed": 1}
    assert _db.list_notes(db["evil.example"]) == []


def test_ui_shape_carries_verdict_notes_watch(db):
    _db.set_verdict(db["203.0.113.70"], "malicious", "c2")
    _db.add_note(db["203.0.113.70"], "blocked on fw")
    _db.watch_add(db["203.0.113.70"], 15)
    shaped = api._to_ui_shape(
        {"ioc": "203.0.113.70", "type": "ip", "final_score": 90, "modules": {}}, None
    )
    assert shaped["verdict"]["verdict"] == "malicious"
    assert shaped["notes"][0]["body"] == "blocked on fw"
    assert shaped["watch"] == {"threshold": 15}


def test_case_lifecycle(db):
    created = client.post("/api/ui/cases", json={"name": "phish-nov", "description": "Nov wave"})
    assert created.status_code == 200
    listed = {c["id"]: c for c in client.get("/api/ui/cases").json()}
    # A case with no members yet is still listed.
    assert listed["phish-nov"]["ioc_count"] == 0 and listed["phish-nov"]["status"] == "open"

    assert _db.set_ioc_case("evil.example", "phish-nov")
    closed = client.patch("/api/ui/cases/phish-nov", json={"status": "closed"})
    assert closed.json()["status"] == "closed"
    renamed = client.patch("/api/ui/cases/phish-nov", json={"rename": "phish-2026-11"})
    assert renamed.json()["case"] == "phish-2026-11"
    listed = {c["id"]: c for c in client.get("/api/ui/cases").json()}
    assert "phish-nov" not in listed
    assert listed["phish-2026-11"]["iocs"] == ["evil.example"]
    assert listed["phish-2026-11"]["status"] == "closed"
    assert listed["phish-2026-11"]["description"] == "Nov wave"

    client.post("/api/ui/cases", json={"name": "other"})
    assert client.patch("/api/ui/cases/other", json={"rename": "phish-2026-11"}).status_code == 409
    assert client.patch("/api/ui/cases/other", json={"status": "weird"}).status_code == 422

    assert client.delete("/api/ui/cases/phish-2026-11").json()["removed"] >= 1
    assert "phish-2026-11" not in {c["id"] for c in client.get("/api/ui/cases").json()}


def test_case_export_markdown(db):
    _db.set_ioc_case("203.0.113.70", "incident-7")
    _db.upsert_case("incident-7", "C2 beaconing from finance VLAN")
    _db.set_verdict(db["203.0.113.70"], "malicious", "confirmed by EDR")
    _db.add_note(db["203.0.113.70"], "blocked at perimeter")
    body = client.get("/api/ui/cases/incident-7/export").json()
    md = body["markdown"]
    assert body["filename"] == "case-incident-7.md"
    assert "# Case: incident-7" in md and "C2 beaconing" in md
    # Defanged indicator, real score and tier, analyst verdict.
    assert "`203[.]0[.]113[.]70`" in md and "| 90 | Critical | malicious |" in md
    assert "confirmed by EDR" in md and "blocked at perimeter" in md
    assert client.get("/api/ui/cases/nope/export").status_code == 404


def test_watchlist_add_list_remove(db):
    added = client.post("/api/ui/watchlist", json={"ioc": "203.0.113.70", "threshold": 10})
    assert added.json()["watch"] == {"threshold": 10}
    # Second POST updates the threshold instead of adding a duplicate.
    client.post("/api/ui/watchlist", json={"ioc": "203.0.113.70", "threshold": 25})
    rows = client.get("/api/ui/watchlist").json()
    assert [(r["value"], r["threshold"], r["score"]) for r in rows] == [("203.0.113.70", 25, 90)]
    assert client.post("/api/ui/watchlist", json={"ioc": "203.0.113.70", "threshold": 0}).status_code == 422
    assert client.post("/api/ui/watchlist", json={"ioc": "198.51.100.1"}).status_code == 404
    removed = client.delete("/api/ui/watchlist", params={"ioc": "203.0.113.70"})
    assert removed.json()["removed"] == 1
    assert client.get("/api/ui/watchlist").json() == []


def test_watch_check_alerts_on_threshold_and_skips_degraded(db, monkeypatch):
    _db.watch_add(db["203.0.113.70"], 20)  # stored score 90
    _db.watch_add(db["evil.example"], 20)  # stored score 30
    seen: list[tuple[str, bool]] = []

    async def fake(value, ioc_type, *, no_cache=False):
        seen.append((value, no_cache))
        if value == "203.0.113.70":
            return {"ioc": value, "type": ioc_type, "final_score": 40, "degraded": False, "unavailable": {}}
        return {
            "ioc": value, "type": ioc_type, "final_score": 0,
            "degraded": True, "unavailable": {"VirusTotal": "timeout"},
        }

    monkeypatch.setattr(api.enrich, "enrich_ioc_async", fake)
    out = client.post("/api/ui/watchlist/check").json()
    assert all(no_cache for _, no_cache in seen)  # always a fresh fetch
    assert out["watched"] == 2 and out["checked"] == 1
    assert out["alerts"] == [{
        "ioc": "203.0.113.70", "type": "ip", "previous": 90, "score": 40,
        "delta": -50, "threshold": 20, "tier": "Medium",
    }]
    assert out["degraded"] == [{"ioc": "evil.example", "unavailable": {"VirusTotal": "timeout"}}]
    rows = {r["value"]: r for r in _db.watch_list()}
    assert rows["203.0.113.70"]["checked_score"] == 40
    assert rows["203.0.113.70"]["last_delta"] == -50
    assert rows["evil.example"]["checked_score"] is None  # degraded run is not recorded


def test_old_cache_migrates(monkeypatch, tmp_path):
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.execute(
        "CREATE TABLE iocs (id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT UNIQUE NOT NULL, "
        "type TEXT NOT NULL, first_seen TIMESTAMP, last_seen TIMESTAMP, tags TEXT)"
    )
    con.execute("INSERT INTO iocs (value, type) VALUES ('8.8.8.8', 'ip')")
    con.commit()
    con.close()
    monkeypatch.setattr(_db, "DB_PATH", str(path))
    _db.init_db()
    ioc_id = _db.get_ioc_id("8.8.8.8")
    _db.set_verdict(ioc_id, "benign")
    _db.watch_add(ioc_id)
    assert _db.get_verdict(ioc_id)["verdict"] == "benign"
    assert _db.watch_get(ioc_id) == {"threshold": 20}

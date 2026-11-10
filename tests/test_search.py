"""Search across the local cache + saved filters (core.search, /api/ui/search, /api/ui/filters)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from ioc_tool.core import database as _db
from ioc_tool.core import search as search_mod
from ioc_tool.web import api

client = TestClient(api.app)


@pytest.fixture
def db(monkeypatch, tmp_path):
    monkeypatch.delenv("SHADOWSCOPE_API_TOKEN", raising=False)
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "ioc.db"))
    _db.init_db()
    ids = {}

    def add(value, kind, score, **sources):
        ids[value] = _db.add_or_update_ioc(value, kind)
        if score is not None:
            _db.update_last_score(ids[value], score, 2)
        for source, data in sources.items():
            _db.add_enrichment(ids[value], source, data, score or 0)
        return ids[value]

    add("203.0.113.10", "ip", 90, threatfox={"malware": "win.emotet", "tags": ["epoch5"]},
        shodan={"org": "Bulletproof Hosting Ltd", "hostnames": ["mail.evil.example"]})
    add("evil.example", "domain", 70, whois={"registrar": "Shady Registrar LLC"})
    add("http://evil.example/login.php", "url", 55)
    add("198.51.100.5", "ip", 10)
    add("192.0.2.77", "ip", None)
    _db.set_verdict(ids["203.0.113.10"], "malicious", "confirmed by EDR")
    _db.add_note(ids["evil.example"], "seen in the invoice phishing mail")
    _db.tag_ioc(ids["evil.example"], case="op-nov")
    _db.tag_ioc(ids["203.0.113.10"], tag="c2")
    _db.watch_add(ids["198.51.100.5"], 20)
    return ids


def _find(**params):
    r = client.get("/api/ui/search", params=params)
    assert r.status_code == 200, r.text
    return r.json()


def _values(**params):
    return [row["ioc"] for row in _find(**params)["rows"]]


def test_parse_terms_quotes_refang_dedup_and_cap():
    assert search_mod.parse_terms('  Emotet "invoice phishing" emotet ') == ["emotet", "invoice phishing"]
    assert search_mod.parse_terms("203[.]0[.]113[.]10 hxxp://evil[.]example") == [
        "203.0.113.10", "http://evil.example",
    ]
    assert len(search_mod.parse_terms(" ".join(f"w{n}" for n in range(30)))) == search_mod.MAX_TERMS


def test_empty_query_lists_everything_by_score_unscored_last(db):
    out = _find()
    assert out["total"] == 5
    assert [r["ioc"] for r in out["rows"]] == [
        "203.0.113.10", "evil.example", "http://evil.example/login.php", "198.51.100.5", "192.0.2.77",
    ]
    top = out["rows"][0]
    assert (top["score"], top["tier"], top["verdict"], top["watched"]) == (90, "Critical", "malicious", False)
    assert out["rows"][-1]["score"] is None and out["rows"][-1]["tier"] is None


def test_text_matches_each_place_and_says_where(db):
    def where(q):
        return {r["ioc"]: r["matched"] for r in _find(q=q)["rows"]}

    assert where("evil.example") == {
        "evil.example": ["indicator"],
        "http://evil.example/login.php": ["indicator"],
        "203.0.113.10": ["source data: shodan"],
    }
    assert where("EDR") == {"203.0.113.10": ["verdict"]}
    assert where('"invoice phishing"') == {"evil.example": ["note"]}
    assert where("op-nov") == {"evil.example": ["case"]}
    assert where("c2") == {"203.0.113.10": ["tag"]}
    assert where("emotet") == {"203.0.113.10": ["source field", "source data: threatfox"]}
    assert where("bulletproof") == {"203.0.113.10": ["source data: shodan"]}
    assert where("zzz-not-there") == {}


def test_words_are_anded_and_deep_can_be_switched_off(db):
    assert _values(q="evil login") == ["http://evil.example/login.php"]
    assert _values(q="emotet shady") == []
    assert _values(q="bulletproof", deep="false") == []
    assert _values(q="emotet", deep="false") == ["203.0.113.10"]  # still in the field index


def test_like_wildcards_in_the_query_are_literal(db):
    assert _values(q="%") == []
    assert _values(q="203_0") == []
    assert _values(q="login.php") == ["http://evil.example/login.php"]


def test_structured_filters(db):
    assert _values(type="ip") == ["203.0.113.10", "198.51.100.5", "192.0.2.77"]
    assert _values(type="domain,url") == ["evil.example", "http://evil.example/login.php"]
    assert _values(min_score=60) == ["203.0.113.10", "evil.example"]
    assert _values(max_score=10) == ["198.51.100.5", "192.0.2.77"]
    assert _values(verdict="malicious") == ["203.0.113.10"]
    assert _values(verdict="any") == ["203.0.113.10"]
    assert "203.0.113.10" not in _values(verdict="none") and len(_values(verdict="none")) == 4
    assert _values(case="op-nov") == ["evil.example"]
    assert _values(case="any") == ["evil.example"]
    assert len(_values(case="none")) == 4
    assert _values(watched="true") == ["198.51.100.5"]
    assert _values(has_notes="true") == ["evil.example"]
    assert _values(q="evil", type="url", min_score=50) == ["http://evil.example/login.php"]
    assert _values(since_days=1)[0] == "203.0.113.10" and len(_values(since_days=1)) == 5


def test_sort_limit_offset(db):
    assert _values(sort="value")[:2] == ["192.0.2.77", "198.51.100.5"]
    page = _find(limit=2, offset=2)
    assert page["total"] == 5
    assert [r["ioc"] for r in page["rows"]] == ["http://evil.example/login.php", "198.51.100.5"]


def test_bad_parameters_are_rejected(db):
    assert client.get("/api/ui/search", params={"verdict": "evil"}).status_code == 422
    assert client.get("/api/ui/search", params={"sort": "random"}).status_code == 422
    assert client.get("/api/ui/search", params={"type": "ip,banana"}).status_code == 422
    assert client.get("/api/ui/search", params={"min_score": 101}).status_code == 422


def test_saved_filters_roundtrip(db):
    assert client.get("/api/ui/filters").json() == []
    saved = client.post("/api/ui/filters", json={
        "name": "hot ips", "params": {"type": "ip", "min_score": 60, "q": "emotet", "junk": "dropped"},
    })
    assert saved.status_code == 200
    assert saved.json() == {"name": "hot ips", "params": {"type": "ip", "min_score": 60, "q": "emotet"}}
    # Same name overwrites.
    client.post("/api/ui/filters", json={"name": "hot ips", "params": {"min_score": 80}})
    client.post("/api/ui/filters", json={"name": "a-first", "params": {"watched": True}})
    listed = client.get("/api/ui/filters").json()
    assert [(f["name"], f["params"]) for f in listed] == [
        ("a-first", {"watched": True}), ("hot ips", {"min_score": 80}),
    ]
    assert client.post("/api/ui/filters", json={"name": "  ", "params": {}}).status_code == 422
    assert client.delete("/api/ui/filters/hot ips").json() == {"removed": 1}
    assert client.delete("/api/ui/filters/hot ips").json() == {"removed": 0}
    assert [f["name"] for f in client.get("/api/ui/filters").json()] == ["a-first"]

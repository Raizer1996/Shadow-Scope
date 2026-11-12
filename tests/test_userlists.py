"""User-managed block / allow lists (core.userlists, enrichment hook, /api/ui/lists)."""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from ioc_tool.core import database as _db
from ioc_tool.core import enrich, userlists
from ioc_tool.core import score as score_mod
from ioc_tool.web import api

client = TestClient(api.app)
SHA256 = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F"


@pytest.fixture
def db(monkeypatch, tmp_path):
    monkeypatch.delenv("SHADOWSCOPE_API_TOKEN", raising=False)
    monkeypatch.delenv("ALLOWLIST_CIDRS", raising=False)
    monkeypatch.delenv("ALLOWLIST_DOMAINS", raising=False)
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "ioc.db"))
    _db.init_db()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("203[.]0[.]113[.]10", ("ip", "203.0.113.10")),
        ("203.0.113.77/24", ("cidr", "203.0.113.0/24")),
        ("2001:db8::/32", ("cidr", "2001:db8::/32")),
        ("Evil.Example.", ("domain", "evil.example")),
        ("*.evil.example", ("domain", "evil.example")),
        ("hxxp://Evil.example/A", ("url", "http://evil.example/a")),
        (SHA256, ("hash", SHA256.lower())),
        ("cve-2021-44228", ("cve", "CVE-2021-44228")),
        ("as64500", ("asn", "AS64500")),
    ],
)
def test_normalize(raw, expected):
    assert userlists.normalize(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "not an indicator", "0.0.0.0/0", "10.0.0.0/7", "*.203.0.113.10", "a@b.example"])
def test_normalize_rejects(raw):
    with pytest.raises(ValueError):
        userlists.normalize(raw)


def test_match_rules_and_precedence(db):
    userlists.add("allow", "corp.example", "our own")
    userlists.add("block", "evil.corp.example", "compromised host")
    userlists.add("block", "203.0.113.0/24")
    userlists.add("allow", "203.0.113.10", "our scanner")
    userlists.add("block", "198.51.100.5")
    userlists.add("allow", "198.51.100.5")
    userlists.add("block", SHA256)

    def which(value, kind):
        hit = userlists.match(value, kind)
        return (hit["list"], hit["pattern"]) if hit else None

    assert which("www.corp.example", "domain") == ("allow", "corp.example")
    assert which("corp.example", "domain") == ("allow", "corp.example")
    assert which("notcorp.example", "domain") is None
    # Longer suffix is more specific.
    assert which("a.evil.corp.example", "domain") == ("block", "evil.corp.example")
    # Exact IP beats the range around it.
    assert which("203.0.113.10", "ip") == ("allow", "203.0.113.10")
    assert which("203.0.113.11", "ip") == ("block", "203.0.113.0/24")
    assert which("203.0.114.1", "ip") is None
    # Same pattern on both lists: block wins.
    assert which("198.51.100.5", "ip") == ("block", "198.51.100.5")
    assert which(SHA256.lower(), "hash") == ("block", SHA256.lower())
    # URLs fall back to their host (domain or IP).
    assert which("https://www.corp.example/x", "url") == ("allow", "corp.example")
    assert which("http://203.0.113.11/payload", "url") == ("block", "203.0.113.0/24")
    userlists.add("block", "https://www.corp.example/x")
    assert which("https://www.corp.example/x", "url") == ("block", "https://www.corp.example/x")


def test_missing_table_is_not_an_error(monkeypatch, tmp_path):
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "fresh.db"))  # no init_db
    assert userlists.entries() == [] and userlists.match("203.0.113.10", "ip") is None


def test_allow_entry_short_circuits_enrichment(db, monkeypatch):
    userlists.add("allow", "corp.example", "ours")

    def boom(*a, **k):
        raise AssertionError("an allowlisted indicator must not reach any source")

    monkeypatch.setattr(enrich, "_build_enrich_tasks", boom)
    out = asyncio.run(enrich._enrich_ioc_inner("vpn.corp.example", "domain"))
    assert out["allowlisted"] is True and out["final_score"] == 0
    assert out["modules"]["Allowlist"]["data"] == {"reason": "your allowlist", "match": "corp.example", "note": "ours"}


def test_block_entry_is_a_full_weight_source(db):
    assert score_mod.SOURCE_WEIGHTS[userlists.BLOCK_SOURCE] == 1.0
    userlists.add("block", "203.0.113.0/24", "known bad range")
    ioc_id = _db.add_or_update_ioc("203.0.113.10", "ip")
    out = enrich._finalize_enrich("203.0.113.10", "ip", ioc_id, {"AbuseIPDB": {"score": 0, "data": {}}},
                                  [("AbuseIPDB", 0)], {"AbuseIPDB"})
    assert out["final_score"] == 100
    assert out["modules"]["Blocklist"]["data"]["match"] == "203.0.113.0/24"
    assert out["modules"]["Blocklist"]["data"]["note"] == "known bad range"
    # Not listed -> no Blocklist module, score untouched.
    other = _db.add_or_update_ioc("198.51.100.5", "ip")
    clean = enrich._finalize_enrich("198.51.100.5", "ip", other, {"AbuseIPDB": {"score": 0, "data": {}}},
                                    [("AbuseIPDB", 0)], {"AbuseIPDB"})
    assert "Blocklist" not in clean["modules"] and clean["final_score"] == 0


def test_api_crud_and_live_effect_on_cached_indicators(db):
    ioc_id = _db.add_or_update_ioc("203.0.113.10", "ip")
    _db.add_enrichment(ioc_id, "abuseipdb", {"abuseConfidenceScore": 0}, 0)
    _db.update_last_score(ioc_id, 0, 2)

    def cached():
        return client.get("/api/ui/recent", params={"limit": 5}).json()[0]

    assert cached()["final_score"] == 0 and cached()["listed"] is None

    added = client.post("/api/ui/lists", json={"list": "block", "pattern": "203[.]0[.]113[.]0/24", "note": "bad range"})
    assert added.status_code == 200
    entry = added.json()
    assert (entry["list"], entry["kind"], entry["pattern"], entry["note"]) == ("block", "cidr", "203.0.113.0/24", "bad range")
    # Adding the same pattern again does not duplicate it.
    client.post("/api/ui/lists", json={"list": "block", "pattern": "203.0.113.0/24"})
    assert [e["pattern"] for e in client.get("/api/ui/lists").json()] == ["203.0.113.0/24"]

    row = cached()  # no re-enrichment happened
    assert row["final_score"] == 100 and row["modules"]["Blocklist"]["score"] == 100
    assert row["listed"] == {"id": entry["id"], "list": "block", "pattern": "203.0.113.0/24", "note": "bad range"}

    assert client.delete(f"/api/ui/lists/{entry['id']}").json() == {"removed": 1}
    row = cached()
    assert row["final_score"] == 0 and "Blocklist" not in row["modules"] and row["listed"] is None

    assert client.post("/api/ui/lists", json={"list": "block", "pattern": "nonsense"}).status_code == 422
    assert client.post("/api/ui/lists", json={"list": "grey", "pattern": "203.0.113.10"}).status_code == 422
    assert client.post("/api/ui/lists", json={"list": "allow", "pattern": "0.0.0.0/0"}).status_code == 422

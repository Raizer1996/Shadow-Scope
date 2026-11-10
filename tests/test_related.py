"""Related-indicators panel: cache-only pivots (core.related + /api/ui/related)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from ioc_tool.core import database as _db
from ioc_tool.core import related
from ioc_tool.web import api

client = TestClient(api.app)


@pytest.fixture
def db(monkeypatch, tmp_path):
    monkeypatch.delenv("SHADOWSCOPE_API_TOKEN", raising=False)
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "ioc.db"))
    _db.init_db()

    def add(value, kind, score, **sources):
        ioc_id = _db.add_or_update_ioc(value, kind)
        _db.update_last_score(ioc_id, score, 2)
        for source, data in sources.items():
            _db.add_enrichment(ioc_id, source, data, score)
        return ioc_id

    return add


def _groups(value):
    r = client.get("/api/ui/related", params={"ioc": value})
    assert r.status_code == 200, r.text
    return {g["key"]: g for g in r.json()["groups"]}


def test_registered_domain():
    assert related.registered_domain("a.b.evil.example") == "evil.example"
    assert related.registered_domain("www.shop.co.uk") == "shop.co.uk"
    assert related.registered_domain("Evil.Example.") == "evil.example"


def test_same_network_uses_announced_prefix_then_falls_back_to_slash24(db):
    db("203.0.113.10", "ip", 80, virustotal={"network": "203.0.112.0/23"})
    db("203.0.112.200", "ip", 95)  # inside the /23, outside the /24
    db("203.0.113.77", "ip", 10)
    db("198.51.100.5", "ip", 99)   # unrelated
    net = _groups("203.0.113.10")["network"]
    assert net["pivot"] == "203.0.112.0/23"
    # Highest score first.
    assert [i["ioc"] for i in net["items"]] == ["203.0.112.200", "203.0.113.77"]

    # No prefix reported -> /24 only.
    net = _groups("203.0.113.77")["network"]
    assert net["pivot"] == "203.0.113.0/24"
    assert [i["ioc"] for i in net["items"]] == ["203.0.113.10"]


def test_absurdly_wide_prefix_is_ignored(db):
    db("203.0.113.10", "ip", 80, virustotal={"network": "203.0.0.0/8"})
    db("203.9.9.9", "ip", 50)
    assert "network" not in _groups("203.0.113.10")


def test_same_domain_groups_subdomains_and_urls_but_not_lookalikes(db):
    db("evil.example", "domain", 70)
    db("cdn.evil.example", "domain", 60)
    db("http://login.evil.example/a.php", "url", 90)
    db("notevil.example", "domain", 50)       # shares a suffix string only
    db("evil.example.attacker.test", "domain", 50)
    dom = _groups("cdn.evil.example")["domain"]
    assert dom["pivot"] == "evil.example"
    assert [i["ioc"] for i in dom["items"]] == ["http://login.evil.example/a.php", "evil.example"]


def test_ip_lists_cached_urls_hosted_on_it(db):
    db("203.0.113.10", "ip", 80)
    db("http://203.0.113.10/payload.bin", "url", 100)
    db("http://203.0.113.100/x", "url", 100)  # different host
    dom = _groups("203.0.113.10")["domain"]
    assert dom["title"] == "HOSTED ON THIS IP"
    assert [i["ioc"] for i in dom["items"]] == ["http://203.0.113.10/payload.bin"]


def test_seen_with_marks_cached_vs_not_yet_enriched(db):
    db(
        "203.0.113.10", "ip", 80,
        rdns={"ptr": "mail.evil.example", "aliases": []},
        shodan={"hostnames": ["mail.evil.example", "c2.evil.example"], "domains": ["evil.example"]},
        pdns={"top_rrnames": ["old.evil.example."], "record_count": 4},
        abstractapi={"domains": {"domains": []}},  # dict under a host key must not crash
    )
    db("c2.evil.example", "domain", 100)
    seen = _groups("203.0.113.10")["seen_with"]
    by = {i["ioc"]: i for i in seen["items"]}
    assert set(by) == {"mail.evil.example", "c2.evil.example", "evil.example", "old.evil.example"}
    assert by["c2.evil.example"]["cached"] is True and by["c2.evil.example"]["score"] == 100
    assert by["mail.evil.example"]["cached"] is False and by["mail.evil.example"]["score"] is None
    assert seen["items"][0]["ioc"] == "c2.evil.example"  # cached + scored sorts first


def test_domain_dns_records_and_certificate_subdomains(db):
    db(
        "evil.example", "domain", 70,
        virustotal={"last_dns_records": [
            {"type": "A", "value": "203.0.113.10"},
            {"type": "TXT", "value": "v=spf1 -all"},
        ]},
        crtsh={"unique_subdomains": ["*.evil.example", "vpn.evil.example", "evil.example"]},
    )
    g = _groups("evil.example")
    assert [i["ioc"] for i in g["seen_with"]["items"]] == ["203.0.113.10"]
    assert g["seen_with"]["items"][0]["type"] == "ip"
    # Wildcard collapses to the apex (= self, dropped); self is never listed.
    assert [i["ioc"] for i in g["certs"]["items"]] == ["vpn.evil.example"]


def test_url_names_its_own_host(db):
    db("http://evil.example/a", "url", 90)
    seen = _groups("http://evil.example/a")["seen_with"]
    assert [(i["ioc"], i["cached"]) for i in seen["items"]] == [("evil.example", False)]


def test_shared_family_tags_case_and_registrar(db):
    a = db("203.0.113.10", "ip", 80, threatfox={"malware": "win.emotet", "tags": ["emotet", "epoch5"]})
    db("198.51.100.5", "ip", 60, threatfox={"malware": "win.emotet", "tags": ["Emotet"]})
    db("192.0.2.9", "ip", 20, otx={"tags": ["epoch5", "emotet"]})
    db("192.0.2.200", "ip", 5, otx={"tags": ["unrelated"]})
    c = db("evil.example", "domain", 70, whois={"registrar": "Shady Registrar LLC"})
    db("other.example", "domain", 30, whois={"registrar": "shady registrar llc"})
    _db.tag_ioc(a, case="op-nov")
    _db.tag_ioc(c, case="op-nov")

    g = _groups("203.0.113.10")
    assert g["family"]["pivot"] == "win.emotet"
    assert [i["ioc"] for i in g["family"]["items"]] == ["198.51.100.5"]
    assert [i["ioc"] for i in g["tags"]["items"]] == ["198.51.100.5", "192.0.2.9"]
    assert set(g["tags"]["items"][1]["why"].split(",")) == {"emotet", "epoch5"}
    assert g["case"]["pivot"] == "op-nov"
    assert [i["ioc"] for i in g["case"]["items"]] == ["evil.example"]

    reg = _groups("evil.example")["registrar"]
    assert [i["ioc"] for i in reg["items"]] == ["other.example"]


def test_nested_tags_and_signatures_do_not_relate_indicators(db):
    # OTX returns the tags of every pulse mentioning an indicator, and Shodan
    # returns TLS certificate signatures. Neither describes the indicator.
    pulses = {"pulse_info": {"pulses": [{"tags": ["emotet", "log4j"]}]}}
    cert = {"data": [{"ssl": {"cert": {"signature": "68f151b7e1ff7629"}}}]}
    db("203.0.113.10", "ip", 80, otx=pulses, shodan=cert, virustotal={"tags": []})
    db("198.51.100.5", "ip", 60, otx=pulses, shodan=cert, threatfox={"tags": ["emotet"]})
    g = _groups("203.0.113.10")
    assert "tags" not in g and "family" not in g

    # The other direction: my own tag, theirs only nested -> still not related.
    assert "tags" not in _groups("198.51.100.5")


def test_limit_caps_items_but_reports_total(db):
    db("203.0.113.1", "ip", 50)
    for n in range(2, 30):
        db(f"203.0.113.{n}", "ip", n)
    r = client.get("/api/ui/related", params={"ioc": "203.0.113.1", "limit": 5}).json()
    net = r["groups"][0]
    assert net["key"] == "network" and net["total"] == 28 and len(net["items"]) == 5
    assert net["items"][0]["score"] == 29


def test_nothing_related_and_unknown_ioc(db):
    db("203.0.113.10", "ip", 80)
    assert client.get("/api/ui/related", params={"ioc": "203[.]0[.]113[.]10"}).json() == {
        "ioc": "203.0.113.10", "type": "ip", "groups": [],
    }
    assert client.get("/api/ui/related", params={"ioc": "198.51.100.1"}).status_code == 404

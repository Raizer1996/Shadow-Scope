"""Import from STIX / CSV / plain text (core.importer + /api/ui/import/*)."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from ioc_tool.core import database as _db
from ioc_tool.web import api

client = TestClient(api.app)

SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

STIX = {
    "type": "bundle", "id": "bundle--1",
    "objects": [
        {"type": "malware", "id": "malware--1", "name": "Emotet"},
        {"type": "indicator", "id": "indicator--1", "name": "Emotet C2", "description": "Epoch 5 tier-1 node",
         "labels": ["malicious-activity"], "indicator_types": ["c2"], "pattern_type": "stix",
         "pattern": "[ipv4-addr:value = '203.0.113.10'] OR [domain-name:value = 'evil.example']"},
        {"type": "relationship", "id": "relationship--1", "relationship_type": "indicates",
         "source_ref": "indicator--1", "target_ref": "malware--1"},
        {"type": "indicator", "id": "indicator--2", "name": "Dropper",
         "pattern": f"[file:hashes.'SHA-256' = '{SHA256}']"},
        {"type": "indicator", "id": "indicator--3", "pattern_type": "yara", "pattern": "rule x {}"},
        {"type": "indicator", "id": "indicator--4", "pattern": "[process:name = 'evil.exe']"},
        {"type": "url", "id": "url--1", "value": "http://evil.example/login.php"},
        {"type": "ipv4-addr", "id": "ipv4-addr--1", "value": "203.0.113.10"},
        {"type": "autonomous-system", "id": "autonomous-system--1", "number": 64500},
        {"type": "file", "id": "file--1", "hashes": {"MD5": "44d88612fea8a8f36de82e1278abb02f"}},
        {"type": "vulnerability", "id": "vulnerability--1", "name": "CVE-2021-44228", "description": "Log4Shell"},
        {"type": "identity", "id": "identity--1", "name": "ACME"},
    ],
}


@pytest.fixture
def db(monkeypatch, tmp_path):
    monkeypatch.delenv("SHADOWSCOPE_API_TOKEN", raising=False)
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "ioc.db"))
    _db.init_db()


def _preview(text):
    r = client.post("/api/ui/import/preview", json={"text": text})
    assert r.status_code == 200, r.text
    return r.json()


def test_stix_bundle(db):
    out = _preview(json.dumps(STIX))
    assert out["format"] == "stix"
    by = {r["ioc"]: r for r in out["rows"]}
    assert list(by) == [
        "203.0.113.10", "evil.example", SHA256, "http://evil.example/login.php",
        "AS64500", "44d88612fea8a8f36de82e1278abb02f", "CVE-2021-44228",
    ]
    c2 = by["203.0.113.10"]
    assert c2["type"] == "ip" and c2["tags"] == ["malicious-activity", "c2", "Emotet"]
    assert c2["note"] == "Emotet C2 — Epoch 5 tier-1 node"
    assert by["evil.example"]["tags"] == c2["tags"]
    assert by[SHA256]["type"] == "hash" and by[SHA256]["note"] == "Dropper"
    assert by["CVE-2021-44228"]["note"] == "Log4Shell"
    assert out["skipped"] == 2  # the YARA indicator and the process pattern
    assert out["known"] == 0 and all(r["cached"] is False for r in out["rows"])


def test_stix_list_and_single_object_and_non_stix_json(db):
    assert _preview(json.dumps([{"type": "domain-name", "value": "evil.example"}]))["format"] == "stix"
    assert _preview(json.dumps({"type": "ipv4-addr", "value": "203.0.113.10"}))["rows"][0]["ioc"] == "203.0.113.10"
    # Arbitrary JSON falls back to text extraction instead of failing.
    out = _preview(json.dumps({"alerts": [{"src": "203.0.113.10", "host": "evil.example"}]}))
    assert out["format"] == "text" and {r["ioc"] for r in out["rows"]} == {"203.0.113.10", "evil.example"}


def test_csv_with_metadata_columns(db):
    text = (
        "Indicator;Type;Case;Tags;Comment;Verdict\n"
        "203[.]0[.]113[.]10;ip;op-nov;c2|emotet;seen on fw;Malicious\n"
        "hxxp://evil[.]example/a;url;op-nov;;;FP\n"
        "not-an-ioc;x;;;;\n"
        ";;;;;\n"
        "203.0.113.10;ip;other;extra;;benign\n"
    )
    out = _preview(text)
    assert out["format"] == "csv" and out["skipped"] == 1
    rows = out["rows"]
    assert rows[0] == {
        "ioc": "203.0.113.10", "type": "ip", "case": "op-nov", "tags": ["c2", "emotet", "extra"],
        "note": "seen on fw", "verdict": "malicious", "cached": False,
    }  # repeat row merged: first case/verdict kept, new tag added
    assert (rows[1]["ioc"], rows[1]["verdict"], rows[1]["tags"]) == ("http://evil.example/a", "false_positive", [])


def test_csv_several_indicator_columns_and_bom(db):
    out = _preview("﻿ip,domain,note\n203.0.113.10,evil.example,pair\n,other.example,\n")
    assert out["format"] == "csv"
    assert [(r["ioc"], r["note"]) for r in out["rows"]] == [
        ("203.0.113.10", "pair"), ("evil.example", "pair"), ("other.example", None),
    ]


def test_plain_text_and_headerless_csv_fall_back_to_extraction(db):
    out = _preview("# report\nBeacon to 203[.]0[.]113[.]10 and hxxps://evil[.]example/x\nCVE-2021-44228\nAS64500\n")
    assert out["format"] == "text"
    assert {r["ioc"] for r in out["rows"]} >= {"203.0.113.10", "https://evil.example/x", "CVE-2021-44228", "AS64500"}
    assert _preview("203.0.113.10,evil.example\n198.51.100.5,other.example\n")["format"] == "text"
    assert _preview("")["rows"] == []


def test_preview_marks_cached_rows_and_caps(db):
    _db.add_or_update_ioc("203.0.113.10", "ip")
    out = _preview("203.0.113.10\n198.51.100.5\n")
    assert out["known"] == 1 and [r["cached"] for r in out["rows"]] == [True, False]
    big = _preview("\n".join(f"10.{n // 250}.{n % 250}.1" for n in range(2100)))
    assert big["total"] == 2100 and len(big["rows"]) == 2000 and big["truncated"] == 100


def test_apply_registers_metadata_without_enriching_and_is_idempotent(db, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("import must not enrich")

    monkeypatch.setattr(api.enrich, "enrich_ioc_async", boom)
    rows = _preview(json.dumps(STIX))["rows"]
    rows[0]["verdict"] = "malicious"
    r = client.post("/api/ui/import/apply", json={"rows": rows, "case": "stix-drop"})
    assert r.status_code == 200, r.text
    assert r.json() == {"imported": 7, "new": 7, "cases": 7, "tags": 6, "notes": 4, "verdicts": 1, "rejected": 0}

    ioc_id = _db.get_ioc_id("203.0.113.10")
    tags = _db.get_tags_for_ioc(ioc_id)
    assert {t["tag"] for t in tags if t["tag"]} == {"malicious-activity", "c2", "Emotet"}
    assert [t["case_name"] for t in tags if t["case_name"]] == ["stix-drop"]
    assert [n["body"] for n in _db.list_notes(ioc_id)] == ["Emotet C2 — Epoch 5 tier-1 node"]
    assert _db.get_verdict(ioc_id)["verdict"] == "malicious"
    assert {c["id"]: c["ioc_count"] for c in client.get("/api/ui/cases").json()} == {"stix-drop": 7}

    # Second run: nothing new, nothing duplicated, analyst's verdict untouched.
    _db.set_verdict(ioc_id, "benign", "checked")
    again = client.post("/api/ui/import/apply", json={"rows": rows, "case": "another"}).json()
    assert again == {"imported": 7, "new": 0, "cases": 0, "tags": 0, "notes": 0, "verdicts": 0, "rejected": 0}
    assert _db.get_verdict(ioc_id)["verdict"] == "benign"
    assert len(_db.list_notes(ioc_id)) == 1
    # The imported rows are findable although never enriched.
    found = client.get("/api/ui/search", params={"q": "emotet"}).json()
    assert {x["ioc"] for x in found["rows"]} == {"203.0.113.10", "evil.example"}


def test_apply_revalidates_rows_from_the_client(db):
    r = client.post("/api/ui/import/apply", json={"rows": [
        {"ioc": "definitely not an indicator"}, {"ioc": "someone@example.com"}, {"ioc": "198[.]51[.]100[.]5", "verdict": "pwned"},
    ]})
    assert r.json() == {"imported": 1, "new": 1, "cases": 0, "tags": 0, "notes": 0, "verdicts": 0, "rejected": 2}
    assert _db.get_ioc_id("198.51.100.5") is not None


def test_limits(db):
    assert client.post("/api/ui/import/preview", json={"text": "x" * 2_000_001}).status_code == 422
    too_many = [{"ioc": "198.51.100.5"}] * 2001
    assert client.post("/api/ui/import/apply", json={"rows": too_many}).status_code == 422

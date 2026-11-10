"""POST /api/ui/extract — Batch tab paste box (extraction only, no enrichment)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from ioc_tool.core import ratelimit
from ioc_tool.web import api

client = TestClient(api.app)


def _post(text: str):
    return client.post("/api/ui/extract", json={"text": text})


def test_extracts_lines_and_free_text(monkeypatch):
    monkeypatch.delenv("SHADOWSCOPE_API_TOKEN", raising=False)
    body = _post(
        "1[.]2[.]3[.]4\n"
        "evil-domain.example\n"
        "CVE-2024-3400\n"
        "as15169\n"
        "# a comment line\n"
        "beacon seen to 203.0.113.9 and hxxp://bad[.]example/payload today\n"
        "1.2.3.4\n"
    ).json()
    got = {(i["value"], i["type"]) for i in body["iocs"]}
    assert ("1.2.3.4", "ip") in got and ("CVE-2024-3400", "cve") in got and ("AS15169", "asn") in got
    assert ("203.0.113.9", "ip") in got and ("evil-domain.example", "domain") in got
    assert any(t == "url" and v.startswith("http://bad.example") for v, t in got)
    assert sum(1 for v, _ in got if v == "1.2.3.4") == 1          # defanged + plain de-duplicated
    assert body["count"] == len(body["iocs"]) and body["truncated"] == 0


def test_no_enrichment_happens(monkeypatch):
    monkeypatch.delenv("SHADOWSCOPE_API_TOKEN", raising=False)

    async def boom(*a, **k):
        raise AssertionError("extract must not enrich")

    monkeypatch.setattr(api.enrich, "enrich_ioc_async", boom)
    assert _post("8.8.8.8").json()["iocs"] == [{"value": "8.8.8.8", "type": "ip"}]


def test_caps(monkeypatch):
    monkeypatch.delenv("SHADOWSCOPE_API_TOKEN", raising=False)
    many = "\n".join(f"10.{i // 250}.{i % 250}.1" for i in range(260))
    body = _post(many).json()
    assert body["count"] == 200 and body["truncated"] == 60
    assert _post("x" * 256_001).status_code == 422
    assert _post("nothing here at all").json() == {"iocs": [], "count": 0, "truncated": 0, "skipped": 0}


def test_requires_token_when_configured(monkeypatch):
    monkeypatch.setenv("SHADOWSCOPE_API_TOKEN", "t0k")
    assert _post("8.8.8.8").status_code == 401
    assert client.post("/api/ui/extract", json={"text": "8.8.8.8"}, headers={"Authorization": "Bearer t0k"}).status_code == 200


def test_query_api_buckets_allow_a_batch():
    """A 10-indicator fan-out must fit inside one bucket for the per-IOC query APIs."""
    for key in ("urlhaus", "threatfox", "urlscan", "malwarebazaar", "ipqs", "otx", "pulsedive", "pdns"):
        capacity, _period = ratelimit._DEFAULT_BUCKETS[key]
        assert capacity >= 10, key

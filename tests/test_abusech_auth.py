"""abuse.ch Auth-Key handling for URLhaus / ThreatFox / MalwareBazaar."""

from __future__ import annotations

from typing import Any

from ioc_tool.core import http
from ioc_tool.modules import _abusech, malwarebazaar, threatfox, urlhaus


class _Resp:
    def __init__(self, payload: Any, status_code: int = 200):
        self._p, self.status_code = payload, status_code

    def json(self) -> Any:
        return self._p


def _capture(monkeypatch, resp):
    calls: list[dict[str, Any]] = []

    def fake_post(source, url, **kw):
        calls.append({"source": source, "url": url, **kw})
        return resp
    monkeypatch.setattr(http, "post", fake_post)
    return calls


def test_header_sent_on_every_abusech_call(monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "abc123")
    calls = _capture(monkeypatch, _Resp({"query_status": "ok", "data": [{"x": 1}], "url_count": 1}))
    urlhaus.enrich_url("http://evil.test/a")
    urlhaus.enrich_host("evil.test")
    threatfox.enrich("evil.test")
    malwarebazaar.enrich_hash("a" * 64)
    assert len(calls) == 4
    assert all(c["headers"] == {"Auth-Key": "abc123"} for c in calls)
    assert {c["source"] for c in calls} == {"urlhaus", "threatfox", "malwarebazaar"}


def test_no_key_skips_request(monkeypatch):
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    calls = _capture(monkeypatch, _Resp({"query_status": "ok"}))
    assert urlhaus.enrich_url("http://evil.test/a") is None
    assert urlhaus.enrich_host("evil.test") is None
    assert threatfox.enrich("evil.test") is None
    assert malwarebazaar.enrich_hash("a" * 64) is None
    assert calls == []
    assert _abusech.auth_headers() == {}


def test_401_soft_fails(monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "revoked")
    _capture(monkeypatch, _Resp({"error": "Unauthorized"}, status_code=401))
    assert threatfox.enrich("evil.test") is None
    assert malwarebazaar.enrich_hash("a" * 64) is None
    assert urlhaus.enrich_host("evil.test") is None

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


# --- ThreatFox exact-match filtering (search_ioc is a substring search) ----

_TF_SUBSTRING_NOISE = {
    "query_status": "ok",
    "data": [
        {"ioc": "rate-limited-proxy-66-249-87-132.google.com", "ioc_type": "domain", "confidence_level": 50, "malware_printable": "php.shin_webshell"},
        {"ioc": "https://sites.google.com/view/github-launcher", "ioc_type": "url", "confidence_level": 75, "malware_printable": "WARDENStealer"},
        {"ioc": "https://drive.google.com/uc?export=download&id=1", "ioc_type": "url", "confidence_level": 100, "malware_printable": "IClickFix"},
    ],
}


def test_threatfox_ignores_substring_matches(monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "k")
    _capture(monkeypatch, _Resp(_TF_SUBSTRING_NOISE))
    assert threatfox.enrich("google.com") is None


def test_threatfox_exact_match_wins_and_counts_related(monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "k")
    payload = {"query_status": "ok", "data": _TF_SUBSTRING_NOISE["data"] + [
        {"ioc": "evil.example", "ioc_type": "domain", "confidence_level": 60, "malware_printable": "Vidar"},
        {"ioc": "EVIL.example", "ioc_type": "domain", "confidence_level": 90, "malware_printable": "Vidar"},
    ]}
    _capture(monkeypatch, _Resp(payload))
    out = threatfox.enrich("evil.example")
    assert out is not None and out["confidence_level"] == 90   # highest-confidence exact
    assert out["related_hits"] == 3


def test_threatfox_ip_port_and_url_forms_count_as_exact(monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "k")
    _capture(monkeypatch, _Resp({"query_status": "ok", "data": [
        {"ioc": "203.0.113.9:4444", "ioc_type": "ip:port", "confidence_level": 100},
    ]}))
    assert threatfox.enrich("203.0.113.9") is not None
    _capture(monkeypatch, _Resp({"query_status": "ok", "data": [
        {"ioc": "http://evil.example/p/", "ioc_type": "url", "confidence_level": 100},
    ]}))
    assert threatfox.enrich("http://evil.example/p") is not None
    assert threatfox.enrich("http://evil.example/other") is None

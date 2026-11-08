"""ctlogs.dev CT module + ctlogs→crt.sh fallback. No network: http.get is monkeypatched."""

from __future__ import annotations

from typing import Any

from ioc_tool.core import enrich, http
from ioc_tool.modules import crtsh, ctlogs


class _FakeResp:
    def __init__(self, payload: Any, status_code: int = 200, bad_json: bool = False):
        self._payload, self.status_code, self._bad = payload, status_code, bad_json

    def json(self) -> Any:
        if self._bad:
            raise ValueError("not json")
        return self._payload


HOSTS = {
    "hosts": [
        {"host": "example.com", "certs": 19, "first_seen": "2025-11-20T00:00:00Z", "last_seen": "2026-09-26T22:49:11Z"},
        {"host": "*.example.com", "certs": 16, "first_seen": "2026-05-31T21:39:00Z", "last_seen": "2026-09-26T22:49:11Z"},
        {"host": "mail.example.com", "certs": 2, "first_seen": "2026-10-20T19:58:47Z", "last_seen": "2026-10-20T21:19:03Z"},
    ],
    "has_next": False,
    "history_window_days": 90,
}
DOMAIN = {
    "rows": [
        {"match": "example.com", "not_before": "2026-09-26T22:49:11Z", "issuer": "SSL Corporation"},
        {"match": "example.com", "not_before": "2026-06-01T00:00:00Z", "issuer": "Let's Encrypt"},
        {"match": "example.com", "not_before": "2026-03-01T00:00:00Z", "issuer": "SSL Corporation"},
    ],
    "has_next": False,
}


def _route(monkeypatch, table: dict[str, Any], seen: list[dict[str, Any]] | None = None):
    def fake_get(source, url, **kw):
        if seen is not None:
            seen.append({"source": source, "url": url, **kw})
        for frag, resp in table.items():
            if frag in url:
                return resp
        return None
    monkeypatch.setattr(http, "get", fake_get)


def test_enrich_domain_shape_matches_crtsh(monkeypatch):
    seen: list[dict[str, Any]] = []
    _route(monkeypatch, {"/hosts/": _FakeResp(HOSTS), "/domain/": _FakeResp(DOMAIN)}, seen)
    out = ctlogs.enrich_domain("Example.COM.")
    assert out is not None
    assert out["provider"] == "ctlogs"
    assert out["total"] == 37
    assert out["unique_subdomains"] == ["*.example.com", "mail.example.com"]
    assert out["subdomain_count"] == 2
    assert out["top_issuers"][0] == {"issuer": "SSL Corporation", "count": 2}
    assert out["most_recent"]["not_before"] == "2026-09-26T22:49:11Z"
    assert out["most_recent"]["issuer"] == "SSL Corporation"
    assert all(s["source"] == "ctlogs" for s in seen)
    assert seen[0]["url"].endswith("/v1/hosts/example.com")


def test_key_sent_as_bearer_when_configured(monkeypatch):
    seen: list[dict[str, Any]] = []
    _route(monkeypatch, {"/hosts/": _FakeResp(HOSTS), "/domain/": _FakeResp(DOMAIN)}, seen)
    monkeypatch.delenv("CTLOGS_API_KEY", raising=False)
    ctlogs.enrich_domain("example.com")
    assert "Authorization" not in seen[0]["headers"]
    monkeypatch.setenv("CTLOGS_API_KEY", "k123")
    seen.clear()
    ctlogs.enrich_domain("example.com")
    assert seen[0]["headers"]["Authorization"] == "Bearer k123"


def test_soft_fail_paths(monkeypatch):
    _route(monkeypatch, {"/hosts/": _FakeResp({"error": "too many"}, status_code=422)})
    assert ctlogs.enrich_domain("amazonaws.com") is None
    _route(monkeypatch, {"/hosts/": _FakeResp(None, bad_json=True)})
    assert ctlogs.enrich_domain("example.com") is None
    _route(monkeypatch, {"/hosts/": _FakeResp({"hosts": []})})
    assert ctlogs.enrich_domain("never-seen.test") is None
    _route(monkeypatch, {})
    assert ctlogs.enrich_domain("example.com") is None
    assert ctlogs.enrich_domain("") is None


def test_domain_call_failure_keeps_host_data(monkeypatch):
    _route(monkeypatch, {"/hosts/": _FakeResp(HOSTS), "/domain/": _FakeResp({}, status_code=503)})
    out = ctlogs.enrich_domain("example.com")
    assert out is not None and out["subdomain_count"] == 2
    assert out["top_issuers"] == []
    assert out["most_recent"]["common_name"] == "mail.example.com"  # newest last_seen host


def test_ct_fetch_prefers_ctlogs(monkeypatch):
    monkeypatch.setattr(ctlogs, "enrich_domain", lambda v: {"provider": "ctlogs", "total": 1})
    monkeypatch.setattr(crtsh, "enrich_domain", lambda v: (_ for _ in ()).throw(AssertionError("crt.sh must not run")))
    assert enrich._ct_fetch("example.com")["provider"] == "ctlogs"


def test_ct_fetch_falls_back_to_crtsh(monkeypatch):
    monkeypatch.setattr(ctlogs, "enrich_domain", lambda v: None)
    monkeypatch.setattr(crtsh, "enrich_domain", lambda v: {"total": 5, "subdomain_count": 0})
    out = enrich._ct_fetch("example.com")
    assert out == {"total": 5, "subdomain_count": 0, "provider": "crt.sh"}


def test_ct_fetch_none_when_both_fail(monkeypatch):
    monkeypatch.setattr(ctlogs, "enrich_domain", lambda v: None)
    monkeypatch.setattr(crtsh, "enrich_domain", lambda v: None)
    assert enrich._ct_fetch("example.com") is None

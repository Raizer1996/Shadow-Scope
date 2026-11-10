"""Tri-state source results: no-hit vs unavailable, degraded flag, history skip."""

from __future__ import annotations

import asyncio
from typing import Any

import requests

from ioc_tool.core import database as _db
from ioc_tool.core import enrich, http


class _Resp:
    def __init__(self, status_code: int, headers: dict | None = None):
        self.status_code = status_code
        self.headers = headers or {}


def _with_ledgers(fn):
    tok_f = http.failures_ctx.set({})
    tok_r = http.rate_limited_ctx.set(set())
    try:
        return fn()
    finally:
        http.failures_ctx.reset(tok_f)
        http.rate_limited_ctx.reset(tok_r)


# --- http ledger -----------------------------------------------------------

def test_http_records_timeout_connection_5xx_auth_and_bucket(monkeypatch):
    monkeypatch.setattr(http.ratelimit, "acquire", lambda *a, **k: True)

    def run(case):
        if case == "timeout":
            monkeypatch.setattr(http.requests, "request", lambda *a, **k: (_ for _ in ()).throw(requests.Timeout()))
        elif case == "conn":
            monkeypatch.setattr(http.requests, "request", lambda *a, **k: (_ for _ in ()).throw(requests.ConnectionError()))
        else:
            monkeypatch.setattr(http.requests, "request", lambda *a, **k: _Resp(int(case)))
        return http.get("src", "https://x.test/")

    for case, reason in (("timeout", "timeout"), ("conn", "connection_error"), ("503", "upstream_error_503"), ("401", "auth_error_401"), ("403", "auth_error_403")):
        def body(case=case, reason=reason):
            r = run(case)
            assert http.failure_reason("src") == reason, case
            return r
        _with_ledgers(body)

    # 200 and 404 are answers, not failures
    for code in ("200", "404"):
        def ok(code=code):
            run(code)
            assert http.failure_reason("src") is None
        _with_ledgers(ok)

    # local bucket refusal
    monkeypatch.setattr(http.ratelimit, "acquire", lambda *a, **k: False)
    def bucket():
        assert http.get("src", "https://x.test/") is None
        assert http.failure_reason("src") == "rate_limited"
        assert http.was_rate_limited("src")
    _with_ledgers(bucket)


def test_http_ledger_is_noop_outside_orchestrator(monkeypatch):
    monkeypatch.setattr(http.ratelimit, "acquire", lambda *a, **k: True)
    monkeypatch.setattr(http.requests, "request", lambda *a, **k: _Resp(503))
    assert http.failures_ctx.get() is None
    http.get("src", "https://x.test/")          # must not raise
    assert http.failure_reason("src") is None


# --- _run_source tri-state -------------------------------------------------

def test_run_source_distinguishes_no_hit_from_unavailable():
    def case(fetcher, mark=None):
        def body():
            if mark:
                http.mark_failure(*mark)
            return enrich._run_source(1, "virustotal", "VirusTotal", fetcher, lambda d: 0, no_cache=True)
        return _with_ledgers(body)

    assert case(lambda: None) is None                                   # answered: no hit
    u = case(lambda: None, ("virustotal", "timeout"))
    assert isinstance(u, enrich.Unavailable) and (u.display_name, u.reason, u.contributes) == ("VirusTotal", "timeout", True)
    u = case(lambda: (_ for _ in ()).throw(ValueError("boom")))
    assert isinstance(u, enrich.Unavailable) and u.reason == "exception:ValueError"


def test_run_source_http_keys_alias():
    def body():
        http.mark_failure("asn", "upstream_error_502")
        u = enrich._run_source(1, "asn_bgpview", "ASN", lambda: None, None, info_only=True, no_cache=True, http_keys=("asn",))
        assert isinstance(u, enrich.Unavailable) and u.contributes is False
    _with_ledgers(body)


# --- collector + finalize --------------------------------------------------

def test_degraded_result_skips_history_when_opinion_source_missing(monkeypatch):
    calls: list[Any] = []
    monkeypatch.setattr(_db, "update_last_score", lambda *a, **k: calls.append(a))
    raw = [("AbuseIPDB", {"abuseConfidenceScore": 100}, 100, True), enrich.Unavailable("VirusTotal", "rate_limited", True), None]
    results, scores, unavailable = enrich._collect_raw_results(raw)
    out = enrich._finalize_enrich("203.0.113.9", "ip", 1, results, scores, set(), unavailable=unavailable)
    assert out["final_score"] == 90 and out["degraded"] is True
    assert out["unavailable"] == {"VirusTotal": "rate_limited"}
    assert calls == []                                                  # nothing persisted


def test_info_only_unavailable_still_persists(monkeypatch):
    calls: list[Any] = []
    monkeypatch.setattr(_db, "update_last_score", lambda *a, **k: calls.append(a))
    raw = [("AbuseIPDB", {}, 100, True), enrich.Unavailable("Shodan", "timeout", False)]
    results, scores, unavailable = enrich._collect_raw_results(raw)
    out = enrich._finalize_enrich("203.0.113.9", "ip", 1, results, scores, set(), unavailable=unavailable)
    assert out["degraded"] is True and out["unavailable"] == {"Shodan": "timeout"}
    assert len(calls) == 1


def test_clean_result_is_not_degraded(monkeypatch):
    calls: list[Any] = []
    monkeypatch.setattr(_db, "update_last_score", lambda *a, **k: calls.append(a))
    results, scores, unavailable = enrich._collect_raw_results([("AbuseIPDB", {}, 0, True), None])
    out = enrich._finalize_enrich("203.0.113.9", "ip", 1, results, scores, set(), unavailable=unavailable)
    assert out["degraded"] is False and out["unavailable"] == {} and len(calls) == 1


# --- stream path -----------------------------------------------------------

def test_stream_emits_reason_on_skipped_and_degraded_final(monkeypatch, tmp_path):
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "ioc.db"))
    _db.init_db()

    async def ok():
        return ("AbuseIPDB", {"abuseConfidenceScore": 50}, 50, True)

    async def dead():
        return enrich.Unavailable("VirusTotal", "timeout", True)

    monkeypatch.setattr(enrich, "_build_enrich_tasks", lambda v, t, i: ([("AbuseIPDB", ok()), ("VirusTotal", dead())], {"abuseipdb", "virustotal"}))

    async def collect():
        return [ev async for ev in enrich.enrich_ioc_stream("203.0.113.9", "ip")]

    events = asyncio.run(collect())
    skipped = [e for e in events if e["event"] == "skipped"]
    assert skipped == [{"event": "skipped", "name": "VirusTotal", "reason": "timeout"}]
    final = next(e for e in events if e["event"] == "final")["result"]
    assert final["degraded"] is True and final["unavailable"] == {"VirusTotal": "timeout"}
    assert final["final_score"] == 45

"""Quota meter: per-source request counting (core.usage, core.http hook, /api/ui/usage)."""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
import requests
from fastapi.testclient import TestClient

from ioc_tool.core import database as _db
from ioc_tool.core import http, ratelimit, usage
from ioc_tool.web import api

client = TestClient(api.app)


@pytest.fixture
def db(monkeypatch, tmp_path):
    monkeypatch.delenv("SHADOWSCOPE_API_TOKEN", raising=False)
    monkeypatch.delenv("SHADOWSCOPE_QUOTAS", raising=False)
    monkeypatch.delenv("SHADOWSCOPE_USAGE", raising=False)
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "ioc.db"))
    _db.init_db()
    return tmp_path


class _Resp:
    def __init__(self, status, headers=None):
        self.status_code = status
        self.headers = headers or {}


def _row(source):
    con = sqlite3.connect(_db.DB_PATH)
    con.row_factory = sqlite3.Row
    r = con.execute("SELECT ok, limited, failed, held FROM api_usage WHERE source = ?", (source,)).fetchone()
    con.close()
    return tuple(r) if r else None


def test_http_requests_are_counted_by_outcome(db, monkeypatch):
    monkeypatch.setattr(ratelimit, "acquire", lambda *a, **k: True)
    monkeypatch.setattr("time.sleep", lambda s: None)
    answers = iter([_Resp(200), _Resp(404), _Resp(503), _Resp(401), requests.Timeout(), requests.ConnectionError(),
                    _Resp(429), _Resp(200),      # throttled, retry succeeds
                    _Resp(429), _Resp(429)])     # throttled twice

    def fake(method, url, **kw):
        item = next(answers)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(requests, "request", fake)
    for _ in range(8):
        http.get("demo", "https://api.example.test/x")
    # ok: 200, 404, retry-200 | limited: three 429s | failed: 503, 401, timeout, connection error
    assert _row("demo") == (3, 3, 4, 0)


def test_requests_held_by_the_local_limiter_are_not_counted_as_sent(db, monkeypatch):
    monkeypatch.setattr(ratelimit, "acquire", lambda *a, **k: False)
    monkeypatch.setattr(requests, "request", lambda *a, **k: pytest.fail("must not be sent"))
    assert http.get("demo", "https://api.example.test/x") is None
    assert _row("demo") == (0, 0, 0, 1)
    row = next(s for s in usage.summary()["sources"] if s["source"] == "demo")
    assert (row["today"], row["held_today"]) == (0, 1)


def test_recording_never_creates_a_database_or_raises(monkeypatch, tmp_path):
    missing = tmp_path / "nope" / "ioc.db"
    monkeypatch.setattr(_db, "DB_PATH", str(missing))
    usage.record("demo", "ok")
    assert not missing.exists() and not missing.parent.exists()
    # A database without the table (older schema) is tolerated too.
    old = tmp_path / "old.db"
    sqlite3.connect(old).close()
    monkeypatch.setattr(_db, "DB_PATH", str(old))
    usage.record("demo", "ok")
    usage.record("demo", "not-an-outcome")
    assert usage.summary()["sources"][0]["today"] == 0  # only the default-quota rows


def test_can_be_switched_off(db, monkeypatch):
    monkeypatch.setenv("SHADOWSCOPE_USAGE", "0")
    usage.record("demo", "ok")
    assert _row("demo") is None and usage.summary()["enabled"] is False


def test_summary_windows_and_quota_math(db, monkeypatch):
    now = datetime.now(timezone.utc)
    day = lambda n: (now - timedelta(days=n)).strftime("%Y-%m-%d")  # noqa: E731
    con = sqlite3.connect(_db.DB_PATH)
    con.executemany("INSERT INTO api_usage (source, day, ok, limited, failed, held) VALUES (?, ?, ?, ?, ?, ?)", [
        ("virustotal", day(0), 120, 5, 0, 2),
        ("virustotal", day(3), 40, 0, 0, 0),
        ("virustotal", day(40), 999, 9, 0, 0),   # outside every window
        ("shodan", day(0), 7, 0, 1, 0),
    ])
    con.commit()
    con.close()
    monkeypatch.setenv("SHADOWSCOPE_QUOTAS", "shodan=10/month, abuseipdb=0, junk, censys=abc, otx=5/fortnight")
    out = usage.summary()
    by = {s["source"]: s for s in out["sources"]}

    vt = by["virustotal"]
    assert (vt["today"], vt["week"], vt["limited_today"], vt["held_today"], vt["last_limited"]) == (125, 165, 5, 2, day(0))
    assert vt["quota"] == {"limit": 500, "period": "day", "assumed": True, "used": 125, "left": 375, "pct": 25}
    # User-stated quota: monthly, not assumed.
    assert by["shodan"]["quota"]["assumed"] is False and by["shodan"]["quota"]["period"] == "month"
    assert by["shodan"]["quota"]["used"] == 8 and by["shodan"]["quota"]["pct"] == 80
    # abuseipdb=0 removes the default; bad entries are ignored; censys keeps its default.
    assert "abuseipdb" not in by and by["censys"]["quota"]["limit"] == 250 and "otx" not in by
    # Fullest quota first.
    assert out["sources"][0]["source"] == "shodan"


def test_quota_percentage_caps_at_100(db, monkeypatch):
    con = sqlite3.connect(_db.DB_PATH)
    con.execute("INSERT INTO api_usage (source, day, ok) VALUES ('virustotal', ?, 900)",
                (datetime.now(timezone.utc).strftime("%Y-%m-%d"),))
    con.commit()
    con.close()
    q = next(s for s in usage.summary()["sources"] if s["source"] == "virustotal")["quota"]
    assert (q["pct"], q["left"]) == (100, 0)


def test_api(db):
    usage.record("otx", "ok")
    out = client.get("/api/ui/usage").json()
    assert out["enabled"] is True and out["day"] == datetime.now(timezone.utc).strftime("%Y-%m-%d")
    otx = next(s for s in out["sources"] if s["source"] == "otx")
    assert otx["today"] == 1 and otx["quota"] is None
    assert os.path.exists(_db.DB_PATH)

"""urlscan.io screenshots: listing from cache, guarded fetch, disk cache, API. No network."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from ioc_tool.core import database as _db
from ioc_tool.core import screenshots
from ioc_tool.web import api

client = TestClient(api.app)

U1 = "01a1c526-ce45-7364-aaa0-03e32c1022e3"
U2 = "01a1c526-ce45-7364-aaa0-03e32c1022e4"
U3 = "99999999-0000-0000-0000-000000000000"   # belongs to a different indicator
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


class _Resp:
    def __init__(self, content=PNG, status=200):
        self.content = content
        self.status_code = status
        self.headers = {}


def _scan(uuid, time, url="https://evil.example/login", title="Sign in", status=200, shot=True):
    out = {"_id": uuid, "task": {"time": time, "url": url}, "page": {"url": url, "title": title, "status": status}}
    if shot:
        out["screenshot"] = f"https://urlscan.io/screenshots/{uuid}.png"
    return out


@pytest.fixture
def db(monkeypatch, tmp_path):
    monkeypatch.delenv("SHADOWSCOPE_API_TOKEN", raising=False)
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "ioc.db"))
    _db.init_db()
    a = _db.add_or_update_ioc("evil.example", "domain")
    _db.add_enrichment(a, "urlscan", {"total": 4, "results": [
        _scan(U1, "2026-11-01T10:00:00.000Z"),
        _scan(U2, "2026-11-09T10:00:00.000Z", title="Parked"),
        _scan(U1, "2026-11-01T10:00:00.000Z"),                       # duplicate
        _scan("../../etc/passwd", "2026-11-10T10:00:00.000Z"),       # hostile id
        _scan("0" * 36, "2026-11-10T10:00:00.000Z"),                 # wrong shape
        _scan("aaaaaaaa-0000-0000-0000-000000000000", "2026-11-10T10:00:00.000Z", shot=False),
        "junk",
    ]}, 30)
    b = _db.add_or_update_ioc("other.example", "domain")
    _db.add_enrichment(b, "urlscan", {"results": [_scan(U3, "2026-11-05T10:00:00.000Z")]}, 0)
    _db.add_or_update_ioc("203.0.113.10", "ip")  # never scanned
    return tmp_path


@pytest.fixture
def net(monkeypatch):
    calls = []

    def install(answer):
        def fake(source, url, **kwargs):
            calls.append((source, url))
            return answer

        monkeypatch.setattr(screenshots.http, "get", fake)
        return calls

    return install


def test_list_is_cache_only_validated_and_newest_first(db, net):
    calls = net(_Resp())
    out = client.get("/api/ui/screenshots", params={"ioc": "evil[.]example"}).json()
    assert out["ioc"] == "evil.example"
    assert [(s["uuid"], s["title"], s["status"], s["cached"]) for s in out["scans"]] == [
        (U2, "Parked", "200", False), (U1, "Sign in", "200", False),
    ]
    assert out["scans"][0]["url"] == "https://evil.example/login"
    assert calls == []
    assert client.get("/api/ui/screenshots", params={"ioc": "203.0.113.10"}).json()["scans"] == []
    assert client.get("/api/ui/screenshots", params={"ioc": "192.0.2.1"}).status_code == 404


def test_image_is_fetched_once_then_served_from_disk(db, net):
    calls = net(_Resp())
    r = client.get("/api/ui/screenshot", params={"ioc": "evil.example", "uuid": U1})
    assert r.status_code == 200 and r.headers["content-type"] == "image/png" and r.content == PNG
    assert r.headers["cache-control"] == "private, max-age=86400"
    assert calls == [("urlscan", f"https://urlscan.io/screenshots/{U1}.png")]
    assert os.path.exists(db / "screenshots" / f"{U1}.png")

    again = client.get("/api/ui/screenshot", params={"ioc": "evil.example", "uuid": U1})
    assert again.content == PNG and len(calls) == 1
    listed = client.get("/api/ui/screenshots", params={"ioc": "evil.example"}).json()["scans"]
    assert {s["uuid"]: s["cached"] for s in listed} == {U1: True, U2: False}


def test_only_this_indicators_own_scans_can_be_requested(db, net):
    calls = net(_Resp())
    for uuid in (U3, "../../etc/passwd", "0" * 36, "", "aaaaaaaa-0000-0000-0000-000000000000"):
        r = client.get("/api/ui/screenshot", params={"ioc": "evil.example", "uuid": uuid})
        assert r.status_code in (404, 422), uuid
    assert calls == []
    assert not os.path.exists(db / "screenshots")


@pytest.mark.parametrize(
    "answer",
    [None, _Resp(status=404), _Resp(status=429), _Resp(content=b"<html>not an image</html>"),
     _Resp(content=PNG + b"\x00" * (screenshots.MAX_BYTES + 1)), _Resp(content="text")],
)
def test_bad_upstream_answers_are_not_served_or_cached(db, net, answer):
    net(answer)
    r = client.get("/api/ui/screenshot", params={"ioc": "evil.example", "uuid": U1})
    assert r.status_code == 502
    assert not os.path.exists(db / "screenshots" / f"{U1}.png")


def test_disk_cache_keeps_only_the_newest_files(db, net, monkeypatch):
    net(_Resp())
    monkeypatch.setattr(screenshots, "MAX_FILES", 3)
    folder = db / "screenshots"
    folder.mkdir()
    for n in range(5):
        f = folder / f"0000000{n}-0000-0000-0000-000000000000.png"
        f.write_bytes(PNG)
        os.utime(f, (1_600_000_000 + n, 1_600_000_000 + n))
    assert screenshots.fetch(U1) == PNG
    left = sorted(os.listdir(folder))
    assert len(left) == 3 and f"{U1}.png" in left and "00000000-0000-0000-0000-000000000000.png" not in left
    assert [f for f in left if f.endswith(".part")] == []


def test_uuid_validation():
    assert screenshots.valid_uuid(U1)
    for bad in (None, 5, "", U1.upper(), U1 + "x", U1.replace("-", "/"), "..", f"{U1}.png"):
        assert not screenshots.valid_uuid(bad)
    assert screenshots.fetch("../../x") is None

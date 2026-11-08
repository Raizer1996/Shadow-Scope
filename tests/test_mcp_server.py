"""Smoke tests for the MCP server tools (no network: orchestrator is stubbed)."""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("mcp")

from ioc_tool import mcp_server  # noqa: E402
from ioc_tool.core import database as _db  # noqa: E402


@pytest.fixture
def _isolated_db(monkeypatch, tmp_path):
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "ioc.db"))
    _db.init_db()


def _stub_enrich(monkeypatch):
    async def fake_async(value, ioc_type, *, no_cache=False):
        big = {"last_analysis_stats": {"malicious": 5, "harmless": 60}, "blob": "x" * 50_000}
        return {
            "ioc": value, "type": ioc_type, "final_score": 65,
            "modules": {"VirusTotal": {"score": 7, "data": big}},
        }

    async def fake_many(iocs, *, no_cache=False):
        return [await fake_async(v, t) for v, t in iocs]

    monkeypatch.setattr(mcp_server.enrich, "enrich_ioc_async", fake_async)
    monkeypatch.setattr(mcp_server.enrich, "enrich_many_async", fake_many)


def test_tools_are_registered():
    names = {t.name for t in asyncio.run(mcp_server.server.list_tools())}
    assert {
        "enrich_ioc", "enrich_many", "extract_and_enrich",
        "show_cached", "list_sources", "cache_stats",
    } <= names


def test_enrich_ioc_refangs_and_adds_tier(monkeypatch):
    _stub_enrich(monkeypatch)
    out = asyncio.run(mcp_server.enrich_ioc("1[.]2[.]3[.]4"))
    assert out["ioc"] == "1.2.3.4"
    assert out["type"] == "ip"
    assert out["risk_tier"] == "High"


def test_enrich_ioc_defang_output(monkeypatch):
    _stub_enrich(monkeypatch)
    out = asyncio.run(mcp_server.enrich_ioc("evil.com", defang_output=True))
    assert out["ioc"] == "evil[.]com"


def test_enrich_ioc_rejects_garbage():
    out = asyncio.run(mcp_server.enrich_ioc("not an ioc at all"))
    assert "error" in out


def test_enrich_many_dedups_and_reports_skipped(monkeypatch):
    _stub_enrich(monkeypatch)
    out = asyncio.run(mcp_server.enrich_many(["8.8.8.8", "8[.]8[.]8[.]8", "???"]))
    assert [r["ioc"] for r in out["results"]] == ["8.8.8.8"]
    assert out["skipped"][0]["ioc"] == "???"


def test_enrich_many_cap():
    out = asyncio.run(mcp_server.enrich_many(["1.1.1.1"] * 51))
    assert "error" in out


def test_extract_and_enrich(monkeypatch):
    _stub_enrich(monkeypatch)
    out = asyncio.run(
        mcp_server.extract_and_enrich("beacon to 203.0.113.9 and hxxp://evil[.]com/x")
    )
    assert "203.0.113.9" in out["extracted"].get("ip", [])
    assert {r["ioc"] for r in out["results"]} >= {"203.0.113.9"}


def test_show_cached_unknown_ioc(_isolated_db):
    out = mcp_server.show_cached("198.51.100.7")
    assert out == {"ioc": "198.51.100.7", "type": "ip", "cached": False}


def test_list_sources_shape(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    out = mcp_server.list_sources()
    assert out["VirusTotal"]["configured"] is False
    assert out["KEV"]["configured"] is True
    assert "cve" in out["KEV"]["types"]


def test_enrich_ioc_is_compact_by_default(monkeypatch):
    _stub_enrich(monkeypatch)
    out = asyncio.run(mcp_server.enrich_ioc("8.8.8.8"))
    vt = out["modules"]["VirusTotal"]
    assert vt["score"] == 7 and "detail" in vt and "data" not in vt
    assert len(str(out)) < 2_000


def test_enrich_ioc_verbose_returns_raw_data(monkeypatch):
    _stub_enrich(monkeypatch)
    out = asyncio.run(mcp_server.enrich_ioc("8.8.8.8", verbose=True))
    assert "blob" in out["modules"]["VirusTotal"]["data"]

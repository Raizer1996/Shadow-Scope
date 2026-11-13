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


# ---------------------------------------------------------------------------
# Analyst tools — local database only
# ---------------------------------------------------------------------------

@pytest.fixture
def _seeded(_isolated_db, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("analyst tools must not enrich")

    monkeypatch.setattr(mcp_server.enrich, "enrich_ioc_async", boom)
    a = _db.add_or_update_ioc("203.0.113.10", "ip")
    _db.update_last_score(a, 90, 2)
    _db.add_enrichment(a, "threatfox", {"malware": "win.emotet", "first_seen": "2026-06-02 08:00:00 UTC"}, 90)
    _db.add_enrichment(a, "rdns", {"ptr": "mail.evil.example"}, 0)
    b = _db.add_or_update_ioc("203.0.113.77", "ip")
    _db.update_last_score(b, 20, 2)
    return {"a": a, "b": b}


def test_analyst_tools_are_registered():
    names = {t.name for t in asyncio.run(mcp_server.server.list_tools())}
    assert {
        "search_cache", "related_indicators", "ioc_timeline", "report", "set_verdict",
        "add_note", "list_cases", "assign_case", "watchlist", "user_list",
    } <= names


def test_search_cache(_seeded):
    out = mcp_server.search_cache("emotet")
    assert [r["ioc"] for r in out["rows"]] == ["203.0.113.10"]
    assert mcp_server.search_cache(types="ip", min_score=50)["total"] == 1
    assert "error" in mcp_server.search_cache(types="banana")
    assert "error" in mcp_server.search_cache(verdict="evil")


def test_tools_refuse_uncached_or_unsupported_input(_seeded):
    for tool in (mcp_server.related_indicators, mcp_server.ioc_timeline):
        assert tool("198.51.100.99")["cached"] is False
        assert "unsupported" in tool("not an ioc")["error"]
    assert mcp_server.add_note("198.51.100.99", "x")["cached"] is False


def test_related_timeline_and_report(_seeded):
    groups = {g["key"]: g for g in mcp_server.related_indicators("203[.]0[.]113[.]10")["groups"]}
    assert [i["ioc"] for i in groups["network"]["items"]] == ["203.0.113.77"]
    assert groups["seen_with"]["items"][0] == {
        "ioc": "mail.evil.example", "type": "domain", "score": None, "cached": False, "why": "named by rdns",
    }
    tl = mcp_server.ioc_timeline("203.0.113.10", limit=2)
    assert tl["total"] >= 3 and len(tl["events"]) == 2
    md = mcp_server.report(ioc="203.0.113.10")["markdown"]
    assert md.startswith("# Indicator report: 203[.]0[.]113[.]10") and "Listed on ThreatFox" in md
    assert "error" in mcp_server.report() and "error" in mcp_server.report(ioc="203.0.113.10", case="x")
    assert "error" in mcp_server.report(case="nope")


def test_verdict_note_case_roundtrip(_seeded):
    assert mcp_server.set_verdict("203.0.113.10", "False Positive", "our scanner")["verdict"]["verdict"] == "false_positive"
    assert "error" in mcp_server.set_verdict("203.0.113.10", "pwned")
    assert mcp_server.set_verdict("203.0.113.10", "clear")["verdict"] is None
    assert [n["body"] for n in mcp_server.add_note("203.0.113.10", "  blocked on fw ")["notes"]] == ["blocked on fw"]
    assert "error" in mcp_server.add_note("203.0.113.10", "   ")

    assert mcp_server.assign_case("203.0.113.10", "op-nov") == {"ioc": "203.0.113.10", "case": "op-nov"}
    cases = mcp_server.list_cases()["cases"]
    assert cases == [{
        "case": "op-nov", "status": "open", "description": None, "max_score": 90,
        "indicators": [{"ioc": "203.0.113.10", "type": "ip", "score": 90}],
    }]
    assert "# Case report: op-nov" in mcp_server.report(case="op-nov")["markdown"]
    assert mcp_server.assign_case("203.0.113.10", "")["case"] is None
    # The case itself stays (empty) until deleted from the dashboard.
    assert mcp_server.list_cases()["cases"][0]["indicators"] == []


def test_watchlist_tool(_seeded):
    assert mcp_server.watchlist() == {"watched": []}
    assert mcp_server.watchlist("add", "203.0.113.10", 15)["watch"] == {"threshold": 15}
    assert "error" in mcp_server.watchlist("add", "203.0.113.10", 0)
    listed = mcp_server.watchlist("list")["watched"]
    assert [(w["ioc"], w["threshold"], w["score"]) for w in listed] == [("203.0.113.10", 15, 90)]
    assert mcp_server.watchlist("remove", "203.0.113.10")["removed"] == 1
    assert "error" in mcp_server.watchlist("explode")


def test_user_list_tool(_seeded):
    assert mcp_server.user_list() == {"entries": []}
    added = mcp_server.user_list("add", "block", "203.0.113.0/24", "bad range")["added"]
    assert (added["kind"], added["pattern"]) == ("cidr", "203.0.113.0/24")
    assert "error" in mcp_server.user_list("add", "block", "0.0.0.0/0")
    assert "error" in mcp_server.user_list("add", "grey", "203.0.113.10")
    assert mcp_server.user_list("check", pattern="203.0.113.10")["match"]["list"] == "block"
    assert mcp_server.user_list("check", pattern="198.51.100.5")["match"] is None
    assert "error" in mcp_server.user_list("remove")
    assert mcp_server.user_list("remove", entry_id=added["id"]) == {"removed": 1}
    assert "error" in mcp_server.user_list("explode")

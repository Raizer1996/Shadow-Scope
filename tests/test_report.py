"""Indicator and case reports in Markdown and printable HTML (core.report)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from ioc_tool.core import database as _db
from ioc_tool.core import report
from ioc_tool.web import api

client = TestClient(api.app)

EVIL = '<script>alert(1)</script> | **bold** [x](http://a)'


@pytest.fixture
def db(monkeypatch, tmp_path):
    monkeypatch.delenv("SHADOWSCOPE_API_TOKEN", raising=False)
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "ioc.db"))
    _db.init_db()
    a = _db.add_or_update_ioc("203.0.113.10", "ip")
    _db.update_last_score(a, 90, 2)
    _db.add_enrichment(a, "abuseipdb", {"abuseConfidenceScore": 100, "lastReportedAt": "2026-11-01T10:00:00+00:00"}, 100)
    _db.add_enrichment(a, "rdns", {"ptr": "mail.evil.example"}, 0)
    _db.set_verdict(a, "malicious", "confirmed by EDR")
    _db.add_note(a, EVIL)
    _db.tag_ioc(a, tag="c2")
    _db.watch_add(a, 15)
    _db.set_last_unavailable(a, {"VirusTotal": "timeout"})
    b = _db.add_or_update_ioc("evil.example", "domain")
    _db.update_last_score(b, 40, 2)
    c = _db.add_or_update_ioc("198.51.100.5", "ip")  # imported, never enriched
    for value in ("203.0.113.10", "evil.example", "198.51.100.5"):
        _db.set_ioc_case(value, "op-nov")
    _db.upsert_case("op-nov", "November phishing wave")
    return {"a": a, "b": b, "c": c}


def _get(path, **params):
    r = client.get(path, params=params)
    assert r.status_code == 200, r.text
    return r.json()


def test_indicator_markdown_report(db):
    out = _get("/api/ui/report", ioc="203[.]0[.]113[.]10")
    assert out["format"] == "md" and out["filename"] == "report-203.0.113.10.md"
    md = out["content"]
    assert md.startswith("# Indicator report: 203[.]0[.]113[.]10\n")
    # The live value never appears — reports are forwarded.
    assert "203.0.113.10" not in md
    for needle in (
        "- **Score:** 90 / 100 — Critical", "- **Analyst verdict:** Malicious", "- **Verdict note:** confirmed by EDR",
        "- **Case:** op-nov", "- **Tags:** c2", "- **Watchlist:** alert when score moves by 15 or more",
        "Incomplete: no answer from VirusTotal", "## Notes", "## Sources", "| abuseipdb | 100 |", "| rdns | 0 |",
        "## Timeline", "Latest abuse report (AbuseIPDB)", "Verdict set: malicious",
        "## Related indicators", "Same case — op-nov", "mail[.]evil[.]example — domain, not enriched",
    ):
        assert needle in md, needle
    # Highest-scoring source first.
    assert md.index("| abuseipdb |") < md.index("| rdns |")


def test_untrusted_text_cannot_inject_markup(db):
    md = _get("/api/ui/report", ioc="203.0.113.10")["content"]
    assert "<script>" not in md and "\\<script\\>" in md and "\\*\\*bold\\*\\*" in md
    page = _get("/api/ui/report", ioc="203.0.113.10", format="html")["content"]
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert page.count("<script") == 0  # the only script is the inline print handler attribute
    # A pipe inside a table cell must not open a new column.
    cell = report.to_markdown([("table", ["a"], [["x | y\nz"]])])
    assert "| x \\| y z |" in cell
    assert "[x]\\(http://a)" in md


def test_indicator_html_report_is_a_printable_page(db):
    out = _get("/api/ui/report", ioc="203.0.113.10", format="html")
    assert out["filename"] == "report-203.0.113.10.html"
    page = out["content"]
    assert page.startswith("<!doctype html>") and "window.print()" in page and "@media print" in page
    assert "<h1>Indicator report: 203[.]0[.]113[.]10</h1>" in page
    assert "<dt>Score</dt><dd>90 / 100 — Critical</dd>" in page
    assert "<th>Source</th><th>Score</th><th>Fetched (local time)</th>" in page


def test_never_enriched_indicator_still_reports(db):
    md = _get("/api/ui/report", ioc="198.51.100.5")["content"]
    assert "- **Score:** not enriched yet" in md and "- **Analyst verdict:** none" in md
    assert "## Sources" not in md


def test_case_report(db):
    out = _get("/api/ui/cases/op-nov/report")
    assert out["filename"] == "report-case-op-nov.md"
    md = out["content"]
    assert md.startswith("# Case report: op-nov\n") and "November phishing wave" in md
    assert "- **Indicators:** 3" in md and "## Summary" in md and "## Indicators" in md
    rows = [line for line in md.splitlines() if line.startswith("| ") and "[.]" in line]
    # Sorted by score, un-enriched last.
    assert [r.split("|")[1].strip() for r in rows[:3]] == ["203[.]0[.]113[.]10", "evil[.]example", "198[.]51[.]100[.]5"]
    assert "| 203[.]0[.]113[.]10 | ip | 90 | Critical | Malicious | 1 |" in md
    assert "### 203[.]0[.]113[.]10" in md
    # Per-indicator sections stay short: no timeline or related blocks in a case report.
    assert "Timeline" not in md and "Related indicators" not in md
    page = _get("/api/ui/cases/op-nov/report", format="html")["content"]
    assert "<h1>Case report: op-nov</h1>" in page and "<h3>203[.]0[.]113[.]10</h3>" in page


def test_errors(db):
    assert client.get("/api/ui/report", params={"ioc": "192.0.2.1"}).status_code == 404
    assert client.get("/api/ui/report", params={"ioc": "203.0.113.10", "format": "pdf"}).status_code == 422
    assert client.get("/api/ui/cases/nope/report").status_code == 404


def test_filename_is_safe():
    assert report.filename("http://evil.example/a?b=c&d", "md") == "report-http_evil.example_a_b_c_d.md"
    assert report.filename("../../etc/passwd", "html") == "report-etc_passwd.html"
    assert report.filename("///", "md") == "report-report.md"

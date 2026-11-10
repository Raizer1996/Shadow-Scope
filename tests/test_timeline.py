"""Per-indicator timeline (core.timeline + /api/ui/timeline)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from ioc_tool.core import database as _db
from ioc_tool.core import timeline
from ioc_tool.web import api

client = TestClient(api.app)


@pytest.fixture
def db(monkeypatch, tmp_path):
    monkeypatch.delenv("SHADOWSCOPE_API_TOKEN", raising=False)
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "ioc.db"))
    _db.init_db()


def _events(value):
    r = client.get("/api/ui/timeline", params={"ioc": value})
    assert r.status_code == 200, r.text
    return r.json()["events"]


@pytest.mark.parametrize(
    ("raw", "iso", "date_only"),
    [
        (809841600, "1995-08-31T04:00:00Z", False),                    # epoch seconds
        (1584586457000, "2020-03-19T02:54:17Z", False),                # epoch milliseconds
        ("2026-10-14T04:00:57+00:00", "2026-10-14T04:00:57Z", False),
        ("2021-12-10T10:15:09.143", "2021-12-10T10:15:09Z", False),    # naive ISO = UTC
        ("2020-03-25T02:54:17Z", "2020-03-25T02:54:17Z", False),
        ("2026-11-08 05:13:13 UTC", "2026-11-08T05:13:13Z", False),
        ("2019-05-21 18:49:33", "2019-05-21T18:49:33Z", False),
        ("2021-12-10", "2021-12-10T00:00:00Z", True),
        ("2026-06-01T12:00:00+02:00", "2026-06-01T10:00:00Z", False),
        ([None, "2021-12-10"], "2021-12-10T00:00:00Z", True),
    ],
)
def test_parse_when_formats(raw, iso, date_only):
    at, only = timeline.parse_when(raw)
    assert at.strftime("%Y-%m-%dT%H:%M:%SZ") == iso and only is date_only


@pytest.mark.parametrize("raw", [None, "", "None", "soon", True, 0, 12, "1900-01-01", 99999999999999999, {}, []])
def test_parse_when_rejects_junk(raw):
    assert timeline.parse_when(raw) is None


def test_external_events_merge_duplicates_and_flag_future(db):
    ioc_id = _db.add_or_update_ioc("evil.example", "domain")
    future = (datetime.now(timezone.utc) + timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    _db.add_enrichment(ioc_id, "whois", {
        "creation_date": ["2024-05-01T10:00:00+00:00"], "registrar": "Shady Registrar LLC",
        "updated_date": None, "expiration_date": future,
    }, 0)
    _db.add_enrichment(ioc_id, "virustotal", {"creation_date": 1714521600, "last_analysis_date": 1730000000}, 40)
    _db.add_enrichment(ioc_id, "threatfox", {"first_seen": "2024-06-02 08:00:00 UTC", "last_seen": None,
                                              "malware_printable": "Emotet"}, 90)
    _db.add_enrichment(ioc_id, "crtsh", {"most_recent": {"not_before": "2024-05-03T00:00:00Z", "issuer": "Let's Encrypt"}}, 0)
    _db.add_enrichment(ioc_id, "otx", {"pulse_info": {"pulses": [{"created": "2020-01-01"}]}}, 0)  # nested: ignored

    ev = [e for e in _events("evil.example") if e["kind"] == "source"]
    by = {e["label"]: e for e in ev}
    assert list(by) == [
        "Domain registration expires", "Last VirusTotal analysis", "Listed on ThreatFox",
        "Latest TLS certificate issued", "Domain registered",
    ]  # newest first
    reg = by["Domain registered"]
    # WHOIS and VirusTotal agree on the day -> one event naming both.
    assert reg["source"] == "whois, virustotal" and reg["detail"] == "Shady Registrar LLC"
    assert reg["at"] == "2024-05-01T10:00:00Z" and reg["future"] is False
    assert by["Domain registration expires"]["future"] is True
    assert by["Listed on ThreatFox"]["detail"] == "Emotet"
    assert by["Latest TLS certificate issued"]["detail"] == "Let's Encrypt"


def test_newest_payload_wins_per_source(db):
    ioc_id = _db.add_or_update_ioc("203.0.113.10", "ip")
    _db.add_enrichment(ioc_id, "greynoise", {"last_seen": "2026-01-01", "classification": "benign"}, 0)
    _db.add_enrichment(ioc_id, "greynoise", {"last_seen": "2026-03-01", "classification": "malicious"}, 90)
    ev = [e for e in _events("203.0.113.10") if e["kind"] == "source"]
    assert [(e["at"], e["detail"], e["date_only"]) for e in ev] == [("2026-03-01T00:00:00Z", "malicious", True)]


def test_local_events_scores_only_on_change_and_analyst_actions(db):
    ioc_id = _db.add_or_update_ioc("203.0.113.10", "ip")
    for value in (30, 30, 85, 85, 40):
        _db.update_last_score(ioc_id, value, 2)
    _db.set_verdict(ioc_id, "false_positive", "our scanner")
    _db.add_note(ioc_id, "blocked at perimeter")
    _db.tag_ioc(ioc_id, case="op-nov")
    _db.tag_ioc(ioc_id, tag="c2")
    _db.watch_add(ioc_id, 15)
    _db.watch_record(ioc_id, 40, -45)

    ev = _events("203.0.113.10")
    assert all(e["at"].endswith("Z") and not e["future"] for e in ev)
    scores = [e for e in ev if e["kind"] == "score"]
    assert [(e["label"], e["detail"]) for e in reversed(scores)] == [
        ("Score 30 · Low", None), ("Score 30 → 85 · Critical", "+55"), ("Score 85 → 40 · Medium", "-45"),
    ]
    analyst = {e["label"]: e["detail"] for e in ev if e["kind"] == "analyst"}
    assert analyst == {
        "Verdict set: false positive": "our scanner",
        "Note": "blocked at perimeter",
        "Added to case op-nov": None,
        "Tagged c2": None,
        "Added to watchlist": "alert when score moves by 15 or more",
    }
    local = {e["label"]: e["detail"] for e in ev if e["kind"] == "local"}
    assert local == {"First enriched here": None, "Latest watchlist check": "score 40 (-45)"}
    assert [e["at"] for e in ev] == sorted((e["at"] for e in ev), reverse=True)


def test_unknown_ioc_is_404(db):
    assert client.get("/api/ui/timeline", params={"ioc": "198.51.100.1"}).status_code == 404

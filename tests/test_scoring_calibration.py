"""Scoring calibration + the timezone bug that silently dropped WHOIS/NRD.

Covers the per-source recalibration pass: detection-count VirusTotal,
percentile-aware EPSS, timezone-safe domain-age handling, and the
heuristics composite taking the strongest sub-signal instead of a mean.
"""

from datetime import datetime, timedelta, timezone

import pytest

from ioc_tool.core import heuristics, score

# ---------------------------------------------------------------------------
# Timezone-aware WHOIS dates — previously raised TypeError, and because the
# exception surfaced inside a thread-pooled source the orchestrator's
# gather() swallowed it, losing both WHOIS and the NRD heuristic.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "value",
    [
        "2020-01-01T00:00:00+00:00",   # ISO with UTC offset
        "2020-01-01T00:00:00+03:00",   # ISO with non-UTC offset
        datetime(2020, 1, 1, tzinfo=timezone.utc),
        datetime(2020, 1, 1, tzinfo=timezone(timedelta(hours=-5))),
    ],
)
def test_whois_score_handles_aware_dates(value):
    assert score.calculate_whois_score(value) == 10  # mature domain


@pytest.mark.parametrize(
    "value",
    [
        "2020-01-01 00:00:00",
        "2020-01-01T00:00:00",
        datetime(2020, 1, 1),
    ],
)
def test_whois_score_still_handles_naive_dates(value):
    assert score.calculate_whois_score(value) == 10


def test_whois_score_unparseable_is_unknown():
    assert score.calculate_whois_score("not a date") == 50
    assert score.calculate_whois_score(None) == 50


def test_nrd_check_handles_aware_dates():
    """An offset-aware creation date must not kill the NRD signal."""
    fresh = datetime.now(timezone.utc) - timedelta(days=3)
    result = heuristics.nrd_check(fresh.isoformat())
    assert result is not None
    assert result["bucket"] == "fresh"
    assert result["score"] == 95


def test_nrd_check_aware_and_naive_agree():
    moment = datetime.now(timezone.utc) - timedelta(days=15)
    aware = heuristics.nrd_check(moment.isoformat())
    naive = heuristics.nrd_check(moment.replace(tzinfo=None).isoformat())
    assert aware is not None and naive is not None
    assert aware["bucket"] == naive["bucket"] == "nrd"


# ---------------------------------------------------------------------------
# VirusTotal — detection count, not ratio
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "malicious,expected",
    [(0, 0), (1, 35), (2, 35), (3, 65), (5, 65), (6, 85), (19, 85), (20, 95), (60, 95)],
)
def test_vt_score_buckets_on_count(malicious, expected):
    stats = {"malicious": malicious, "undetected": 94 - malicious}
    assert score.calculate_vt_score(stats) == expected


def test_vt_score_counts_suspicious_at_half():
    """Two suspicious verdicts weigh as one detection."""
    assert score.calculate_vt_score({"malicious": 0, "suspicious": 2, "undetected": 92}) == 35
    assert score.calculate_vt_score({"malicious": 2, "suspicious": 2, "undetected": 90}) == 65


def test_vt_score_empty_or_silent():
    assert score.calculate_vt_score(None) == 0
    assert score.calculate_vt_score({}) == 0
    assert score.calculate_vt_score({"malicious": 0, "undetected": 0}) == 0


def test_vt_score_survives_non_numeric_values():
    """VT payloads occasionally carry string members — must not crash."""
    assert score.calculate_vt_score({"malicious": 4, "undetected": 90, "note": "x"}) == 65


# ---------------------------------------------------------------------------
# EPSS — percentile-driven, raw probability as a floor
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "pct,expected",
    [(0.995, 90), (0.99, 90), (0.96, 75), (0.95, 75), (0.91, 60), (0.90, 60), (0.70, 35)],
)
def test_epss_percentile_buckets(pct, expected):
    assert score.calculate_epss_score({"epss": 0.001, "percentile": pct}) == expected


def test_epss_raw_probability_wins_when_higher():
    assert score.calculate_epss_score({"epss": "0.97", "percentile": "0.95"}) == 97


def test_epss_median_cve_scores_nothing():
    """The median CVE must not acquire a score from rounding noise."""
    assert score.calculate_epss_score({"epss": 0.0005, "percentile": 0.4}) == 0


def test_epss_empty_or_malformed():
    assert score.calculate_epss_score(None) == 0
    assert score.calculate_epss_score({}) == 0
    assert score.calculate_epss_score({"epss": "n/a", "percentile": None}) == 0


# ---------------------------------------------------------------------------
# Heuristics composite — strongest signal, not the mean
# ---------------------------------------------------------------------------

def test_heuristics_composite_keeps_strongest_signal(monkeypatch):
    """A quiet sub-check must not cancel out a real detection."""
    from ioc_tool.core import enrich

    monkeypatch.setattr(heuristics, "nrd_check", lambda _d: {"score": 0, "bucket": "mature"})
    monkeypatch.setattr(heuristics, "dga_check", lambda _v: {"score": 20})
    monkeypatch.setattr(heuristics, "typosquat_check", lambda _v: {"score": 95})
    monkeypatch.setattr(heuristics, "tld_check", lambda _v: None)
    monkeypatch.setattr(heuristics, "idn_check", lambda _v: None)
    monkeypatch.setattr(enrich.database, "update_last_score", lambda *a, **k: None)

    out = enrich._finalize_enrich("paypa1.com", "domain", 1, {}, [], set())
    assert out["modules"]["Heuristics"]["score"] == 95

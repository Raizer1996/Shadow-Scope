"""Unit tests for the local heuristics module."""

from datetime import datetime, timedelta

from ioc_tool.core import heuristics

# ---------------------------------------------------------------------------
# NRD — Newly Registered Domain
# ---------------------------------------------------------------------------


def test_nrd_none_when_no_creation_date():
    assert heuristics.nrd_check(None) is None
    assert heuristics.nrd_check([]) is None
    assert heuristics.nrd_check("not-a-date") is None


def test_nrd_fresh_bucket():
    """< 7 days → fresh, score 95."""
    fresh = datetime.now() - timedelta(days=3)
    result = heuristics.nrd_check(fresh)
    assert result is not None
    assert result["score"] == 95
    assert result["bucket"] == "fresh"
    assert result["age_days"] == 3


def test_nrd_classic_bucket():
    """7 ≤ age < 30 → nrd, score 75."""
    nrd_age = datetime.now() - timedelta(days=15)
    result = heuristics.nrd_check(nrd_age)
    assert result["score"] == 75
    assert result["bucket"] == "nrd"


def test_nrd_recent_bucket():
    """30 ≤ age < 90 → recent, score 40."""
    recent = datetime.now() - timedelta(days=60)
    result = heuristics.nrd_check(recent)
    assert result["score"] == 40
    assert result["bucket"] == "recent"


def test_nrd_mature_bucket():
    """≥ 90 days → mature, score 0."""
    mature = datetime.now() - timedelta(days=365)
    result = heuristics.nrd_check(mature)
    assert result["score"] == 0
    assert result["bucket"] == "mature"


def test_nrd_accepts_iso_string():
    iso = (datetime.now() - timedelta(days=5)).strftime("%Y-%m-%d %H:%M:%S")
    result = heuristics.nrd_check(iso)
    assert result is not None
    assert result["bucket"] == "fresh"


def test_nrd_accepts_list_of_dates():
    """Some registrars return [date1, date2] — we use the first."""
    first = datetime.now() - timedelta(days=2)
    second = datetime.now() - timedelta(days=200)
    result = heuristics.nrd_check([first, second])
    assert result["bucket"] == "fresh"


def test_nrd_future_date_returns_none():
    future = datetime.now() + timedelta(days=10)
    assert heuristics.nrd_check(future) is None


def test_nrd_includes_iso_date_string():
    """Output includes a human-readable creation date for the analyst."""
    creation = datetime(2026, 1, 1, 12, 0, 0)
    result = heuristics.nrd_check(creation)
    assert result["created"] == "2026-01-01"

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


# ---------------------------------------------------------------------------
# DGA — Domain Generation Algorithm detection
# ---------------------------------------------------------------------------


def test_dga_skips_short_labels():
    """Labels under 7 chars are too noisy to score."""
    assert heuristics.dga_check("ab.com") is None
    assert heuristics.dga_check("google.com") is None  # "google" = 6 chars
    assert heuristics.dga_check("microsoft.com") is not None  # 9 chars


def test_dga_clean_english_low_score():
    """A real English domain should score low."""
    result = heuristics.dga_check("microsoft.com")
    assert result is not None
    assert result["score"] < 40, f"Expected low score, got {result['score']}"
    assert result["label"] == "microsoft"


def test_dga_random_high_score():
    """An obviously algorithmic-looking domain should score high."""
    result = heuristics.dga_check("kq3v9z7hxnt8.com")
    assert result is not None
    assert result["score"] > 60, f"Expected high score, got {result['score']}"


def test_dga_long_consonant_run_bumps_score():
    """A long consonant run is a known DGA signal."""
    result = heuristics.dga_check("xkjptnvbw.com")
    assert result is not None
    assert result["longest_consonant_run"] >= 6
    assert result["score"] > 50


def test_dga_handles_subdomain():
    """Should extract the registrable label, ignoring subdomains."""
    result = heuristics.dga_check("api.cloudflare.com")
    assert result is not None
    assert result["label"] == "cloudflare"


def test_dga_reports_entropy():
    result = heuristics.dga_check("aaaaaaaa.com")  # zero entropy
    assert result is not None
    assert result["entropy"] < 0.1


# ---------------------------------------------------------------------------
# Typosquat / homograph
# ---------------------------------------------------------------------------


_WATCH = ["paypal", "google", "microsoft", "amazon"]


def test_typosquat_returns_none_with_empty_watchlist():
    assert heuristics.typosquat_check("paypa1.com", watchlist=[]) is None


def test_typosquat_returns_none_for_exact_match():
    """Brand on its own domain is not a squat."""
    assert heuristics.typosquat_check("paypal.com", watchlist=_WATCH) is None


def test_typosquat_returns_none_for_unrelated_domain():
    assert heuristics.typosquat_check("github.com", watchlist=_WATCH) is None


def test_typosquat_visual_substitution_scores_95():
    """Confusable-only lookalike (1→l) is the most dangerous bucket."""
    result = heuristics.typosquat_check("paypa1.com", watchlist=_WATCH)
    assert result is not None
    assert result["score"] == 95
    assert result["match"] == "paypal"
    assert result["distance"] == 0
    assert "1→l" in result["confusables"]


def test_typosquat_rn_to_m_substitution():
    result = heuristics.typosquat_check("rnicrosoft.com", watchlist=_WATCH)
    assert result is not None
    assert result["score"] == 95
    assert result["match"] == "microsoft"
    assert "rn→m" in result["confusables"]


def test_typosquat_zero_to_o():
    result = heuristics.typosquat_check("g00gle.com", watchlist=_WATCH)
    assert result is not None
    assert result["score"] == 95
    assert "0→o" in result["confusables"]


def test_typosquat_real_typo_distance_1_scores_85():
    """One-character real edit (no visual confusable) lands at 85."""
    result = heuristics.typosquat_check("paypall.com", watchlist=_WATCH)
    assert result is not None
    assert result["score"] == 85
    assert result["distance"] == 1
    assert result["confusables"] == []


def test_typosquat_handles_subdomain():
    """Subdomain doesn't matter — we score the registrable label."""
    result = heuristics.typosquat_check("login.paypa1.com", watchlist=_WATCH)
    assert result is not None
    assert result["score"] == 95


def test_typosquat_distance_3_skipped():
    """Too distant — not a typosquat."""
    assert heuristics.typosquat_check("paypalwhatever.com", watchlist=_WATCH) is None


def test_typosquat_short_label_skipped():
    """Labels < 4 chars can't be meaningfully scored."""
    assert heuristics.typosquat_check("pp.com", watchlist=_WATCH) is None


def test_typosquat_reads_watchlist_from_env(monkeypatch):
    monkeypatch.setenv("WATCHLIST_DOMAINS", "paypal.com,google.com")
    result = heuristics.typosquat_check("paypa1.com")
    assert result is not None
    assert result["match"] == "paypal"


def test_typosquat_returns_none_when_env_unset(monkeypatch):
    monkeypatch.delenv("WATCHLIST_DOMAINS", raising=False)
    assert heuristics.typosquat_check("paypa1.com") is None

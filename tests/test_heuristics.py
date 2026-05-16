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


# ---------------------------------------------------------------------------
# IDN / punycode
# ---------------------------------------------------------------------------


def test_idn_returns_none_for_pure_ascii():
    assert heuristics.idn_check("apple.com") is None
    assert heuristics.idn_check("paypal.com") is None
    assert heuristics.idn_check("8.8.8.8") is None  # not a domain shape, still ASCII


def test_idn_decodes_punycode_to_unicode():
    """Pure Cyrillic IDN (испытание.com) — legit, score 70 (punycode-encoded)."""
    result = heuristics.idn_check("xn--80akhbyknj4f.com")
    assert result is not None
    assert result["unicode"] == "испытание.com"
    assert result["mixed_script"] is False
    assert result["score"] == 70


def test_idn_flags_mixed_script_homograph_raw():
    """Cyrillic 'а' inside Latin context = classic homograph attack."""
    # 'аpple.com' — first char is U+0430 (Cyrillic), rest are Latin.
    result = heuristics.idn_check("аpple.com")
    assert result is not None
    assert result["mixed_script"] is True
    assert result["score"] == 90


def test_idn_flags_mixed_script_homograph_punycode():
    """Same homograph but punycode-encoded — should still flag at 90."""
    result = heuristics.idn_check("xn--pple-43d.com")
    assert result is not None
    assert result["mixed_script"] is True
    assert result["score"] == 90


def test_idn_legitimate_pure_script_label():
    """A label entirely in one non-Latin script is legit IDN — score 50."""
    result = heuristics.idn_check("мир.рф")
    assert result is not None
    assert result["mixed_script"] is False
    assert result["score"] == 50


def test_idn_exposes_both_forms():
    """ASCII (punycode) and unicode forms both appear in the output."""
    result = heuristics.idn_check("xn--80akhbyknj4f.com")
    assert result["ascii"] == "xn--80akhbyknj4f.com"
    assert result["unicode"] == "испытание.com"


def test_idn_decoding_failure_still_flags():
    """Garbage punycode that can't be decoded still gets flagged at 70."""
    result = heuristics.idn_check("xn--zzz.com")
    assert result is not None
    assert result["score"] == 70


# ---------------------------------------------------------------------------
# TLD reputation
# ---------------------------------------------------------------------------


def test_tld_high_tier_scores_60():
    result = heuristics.tld_check("freebitcoin.zip")
    assert result is not None
    assert result["score"] == 60
    assert result["tier"] == "high"
    assert result["tld"] == "zip"


def test_tld_medium_tier_scores_30():
    result = heuristics.tld_check("example.info")
    assert result is not None
    assert result["score"] == 30
    assert result["tier"] == "medium"


def test_tld_neutral_returns_none():
    assert heuristics.tld_check("anthropic.com") is None
    assert heuristics.tld_check("kernel.org") is None
    assert heuristics.tld_check("bbc.co.uk") is None


def test_tld_case_insensitive():
    result = heuristics.tld_check("Phish.XYZ")
    assert result is not None
    assert result["tld"] == "xyz"


def test_tld_trailing_dot_stripped():
    result = heuristics.tld_check("evil.top.")
    assert result is not None
    assert result["tld"] == "top"


def test_tld_subdomain_uses_rightmost():
    result = heuristics.tld_check("login.paypal.support.click")
    assert result is not None
    assert result["tld"] == "click"
    assert result["score"] == 60


def test_tld_empty_input_returns_none():
    assert heuristics.tld_check("") is None
    assert heuristics.tld_check(".") is None


def test_tld_freenom_ccTLDs_flagged():
    for tld in ("tk", "ml", "ga", "cf", "gq"):
        result = heuristics.tld_check(f"campaign.{tld}")
        assert result is not None, tld
        assert result["tier"] == "high"

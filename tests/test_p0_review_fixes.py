"""Regression tests for the P0 fixes from the 2026-11-07 review.

Covers: CLI refang before enrichment, documented IPQS env var name,
WHOIS error output on stderr, and the single ``core.score.risk_tier``
table shared by every surface.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from ioc_tool.core import heuristics, parser, score
from ioc_tool.core import llm as llm_mod
from ioc_tool.core import output as output_mod
from ioc_tool.modules import ip_quality_score, whois_mod
from ioc_tool.ui import cli

# ---------------------------------------------------------------------------
# 1. Defanged input is enriched in its live form
# ---------------------------------------------------------------------------


def test_normalize_value_refangs_network_types():
    assert parser.normalize_value("1[.]2[.]3[.]4", "ip") == "1.2.3.4"
    assert parser.normalize_value("evil[.]com", "domain") == "evil.com"
    assert parser.normalize_value("hxxp://evil[.]com/x", "url") == "http://evil.com/x"
    assert parser.normalize_value("  user[at]evil[.]com ", "email") == "user@evil.com"
    # Already-live values are untouched.
    assert parser.normalize_value("8.8.8.8", "ip") == "8.8.8.8"
    # CVE / ASN canonicalisation still applies.
    assert parser.normalize_value("cve-2024-1234", "cve") == "CVE-2024-1234"
    assert parser.normalize_value("as15169", "asn") == "AS15169"


def test_cli_enrich_passes_refanged_value_to_orchestrator(monkeypatch, capsys):
    seen: list[tuple[str, str]] = []

    def fake_enrich_ioc(value, ioc_type, no_cache=False):
        seen.append((value, ioc_type))
        return {"ioc": value, "type": ioc_type, "modules": {}, "final_score": 0}

    monkeypatch.setattr(cli.enrich, "enrich_ioc", fake_enrich_ioc)
    args = cli.build_parser().parse_args(["enrich", "1[.]2[.]3[.]4", "--json"])
    cli.handle_enrich(args)

    assert seen == [("1.2.3.4", "ip")]
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload[0]["ioc"] == "1.2.3.4"


# ---------------------------------------------------------------------------
# 2. IPQS reads the documented env var (legacy name still honoured)
# ---------------------------------------------------------------------------


def _capture_get(monkeypatch):
    calls: list[str] = []

    def fake_get(source, url, **kwargs):
        calls.append(url)
        return None

    monkeypatch.setattr(ip_quality_score.http, "get", fake_get)
    return calls


def test_ipqs_uses_documented_env_name(monkeypatch):
    monkeypatch.delenv("IP_QUALITY_SCORE", raising=False)
    monkeypatch.setenv("IPQS_API_KEY", "documented-key")
    calls = _capture_get(monkeypatch)
    ip_quality_score.enrich_ip("8.8.8.8")
    assert calls and "/documented-key/8.8.8.8" in calls[0]


def test_ipqs_legacy_env_name_still_works(monkeypatch):
    monkeypatch.delenv("IPQS_API_KEY", raising=False)
    monkeypatch.setenv("IP_QUALITY_SCORE", "legacy-key")
    calls = _capture_get(monkeypatch)
    ip_quality_score.enrich_ip("8.8.8.8")
    assert calls and "/legacy-key/8.8.8.8" in calls[0]


def test_ipqs_no_key_skips(monkeypatch):
    monkeypatch.delenv("IPQS_API_KEY", raising=False)
    monkeypatch.delenv("IP_QUALITY_SCORE", raising=False)
    calls = _capture_get(monkeypatch)
    assert ip_quality_score.enrich_ip("8.8.8.8") is None
    assert calls == []


# ---------------------------------------------------------------------------
# 3. WHOIS failures never touch stdout
# ---------------------------------------------------------------------------


def test_whois_error_goes_to_stderr_not_stdout(capsys):
    with patch("ioc_tool.modules.whois_mod.whois.whois", side_effect=RuntimeError("no match")):
        assert whois_mod.get_whois_data("nope.invalid") is None
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "WHOIS error" in captured.err


# ---------------------------------------------------------------------------
# 4. One tier table everywhere
# ---------------------------------------------------------------------------


def test_risk_tier_boundaries():
    assert score.risk_tier(0) == "Safe"
    assert score.risk_tier(19) == "Safe"
    assert score.risk_tier(20) == "Low"
    assert score.risk_tier(39) == "Low"
    assert score.risk_tier(40) == "Medium"
    assert score.risk_tier(59) == "Medium"
    assert score.risk_tier(60) == "High"
    assert score.risk_tier(79) == "High"
    assert score.risk_tier(80) == "Critical"
    assert score.risk_tier(100) == "Critical"
    assert score.risk_tier(None) == "Safe"
    assert score.risk_tier("junk") == "Safe"


def test_every_surface_uses_the_same_tier_table():
    for s in (0, 19, 20, 39, 40, 59, 60, 65, 79, 80, 100):
        expected = score.risk_tier(s)
        assert output_mod._risk_tier(s) == expected
        assert llm_mod._tier_for_score(s) == expected
        assert cli.get_score_color(s) == cli._TIER_COLORS[expected]


def test_cli_show_view_labels_65_as_high(capsys):
    # Pre-fix `show` printed "Low" for 65 while --json said "High".
    result = {"ioc": "8.8.8.8", "type": "ip", "modules": {}, "final_score": 65}
    cli.print_single_result(result)
    assert "High" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# 5. tz-aware WHOIS creation dates must not crash the scorer / NRD check
# ---------------------------------------------------------------------------


def test_whois_score_accepts_tz_aware_creation_date():
    old = datetime(1997, 9, 15, 4, 0, tzinfo=timezone.utc)
    assert score.calculate_whois_score(old) == 10
    assert score.calculate_whois_score(old.replace(tzinfo=None)) == 10
    fresh = datetime.now(timezone.utc) - timedelta(days=3)
    assert score.calculate_whois_score(fresh) == 90
    assert score.calculate_whois_score([fresh]) == 90


def test_nrd_check_accepts_tz_aware_creation_date():
    fresh = datetime.now(timezone.utc) - timedelta(days=3)
    out = heuristics.nrd_check(fresh)
    assert out is not None and out.get("age_days") == 3
    assert heuristics.nrd_check(fresh.replace(tzinfo=None)) is not None

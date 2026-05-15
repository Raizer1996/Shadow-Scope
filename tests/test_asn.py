"""Tests for ASN IOC type — parser, normalize, bgpview.io module."""

import responses

from ioc_tool.core import parser, score
from ioc_tool.modules import asn as asn_mod

# ---------------------------------------------------------------------------
# Parser — detect + normalize
# ---------------------------------------------------------------------------


def test_detect_asn_with_as_prefix():
    assert parser.detect_type("AS15169") == "asn"


def test_detect_asn_lowercase():
    assert parser.detect_type("as15169") == "asn"


def test_detect_asn_with_asn_prefix():
    assert parser.detect_type("ASN15169") == "asn"


def test_detect_bare_number_is_not_asn():
    """A bare integer is ambiguous — require the AS prefix."""
    assert parser.detect_type("15169") != "asn"


def test_normalize_asn_uppercases():
    assert parser.normalize_value("as15169", "asn") == "AS15169"


def test_normalize_asn_strips_asn_prefix():
    assert parser.normalize_value("asn15169", "asn") == "AS15169"


def test_normalize_asn_strips_leading_zeros():
    assert parser.normalize_value("AS007", "asn") == "AS7"


# ---------------------------------------------------------------------------
# bgpview.io module
# ---------------------------------------------------------------------------


_SAMPLE = {
    "status": "ok",
    "data": {
        "asn": 15169,
        "name": "GOOGLE",
        "description_short": "Google LLC",
        "country_code": "US",
        "rir_allocation": {"rir_name": "ARIN", "date_allocated": "2000-03-30"},
        "website": "https://www.google.com",
        "looking_glass": None,
        "traffic_estimation": None,
        "email_contacts": ["arin-contact@google.com"],
        "abuse_contacts": ["network-abuse@google.com"],
    },
}


@responses.activate
def test_asn_module_returns_summary():
    responses.add(responses.GET, f"{asn_mod.BASE_URL}/asn/15169", json=_SAMPLE, status=200)
    result = asn_mod.enrich("AS15169")
    assert result is not None
    assert result["asn"] == 15169
    assert result["name"] == "GOOGLE"
    assert result["country_code"] == "US"
    assert result["rir_name"] == "ARIN"
    assert "network-abuse@google.com" in result["abuse_contacts"]


@responses.activate
def test_asn_module_handles_404():
    responses.add(responses.GET, f"{asn_mod.BASE_URL}/asn/99999999", status=404)
    assert asn_mod.enrich("AS99999999") is None


@responses.activate
def test_asn_module_handles_500():
    responses.add(responses.GET, f"{asn_mod.BASE_URL}/asn/15169", status=500)
    assert asn_mod.enrich("AS15169") is None


@responses.activate
def test_asn_module_handles_malformed_json():
    responses.add(responses.GET, f"{asn_mod.BASE_URL}/asn/15169", body="not json", status=200)
    assert asn_mod.enrich("AS15169") is None


@responses.activate
def test_asn_module_handles_error_status():
    """``status != 'ok'`` in payload → treat as miss."""
    responses.add(
        responses.GET,
        f"{asn_mod.BASE_URL}/asn/15169",
        json={"status": "error", "status_message": "rate limited"},
        status=200,
    )
    assert asn_mod.enrich("AS15169") is None


def test_asn_module_invalid_input_returns_none():
    """A value without digits short-circuits without a network call."""
    assert asn_mod.enrich("AS") is None
    assert asn_mod.enrich("garbage") is None


# ---------------------------------------------------------------------------
# Scoring — info-only
# ---------------------------------------------------------------------------


def test_asn_score_is_always_zero():
    assert score.calculate_asn_score(None) == 0
    assert score.calculate_asn_score({}) == 0
    assert score.calculate_asn_score({"asn": 15169, "country_code": "RU"}) == 0

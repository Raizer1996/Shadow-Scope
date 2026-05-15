"""Tests for ASN IOC type — parser, normalize, RIPE Stat module."""

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
# RIPE Stat module
# ---------------------------------------------------------------------------


_OVERVIEW = {
    "status": "ok",
    "data": {
        "holder": "GOOGLE, US",
        "type": "as",
        "announced": True,
        "resource": "15169",
        "block": {"resource": "15169", "name": "AS15169"},
        "looking_glass": None,
    },
}

_PREFIXES = {
    "status": "ok",
    "data": {
        "prefixes": [
            {"prefix": "8.8.8.0/24"},
            {"prefix": "8.8.4.0/24"},
            {"prefix": "172.217.0.0/16"},
        ]
    },
}


@responses.activate
def test_asn_module_returns_summary():
    responses.add(
        responses.GET,
        f"{asn_mod.BASE_URL}/as-overview/data.json",
        json=_OVERVIEW,
        status=200,
    )
    responses.add(
        responses.GET,
        f"{asn_mod.BASE_URL}/announced-prefixes/data.json",
        json=_PREFIXES,
        status=200,
    )
    result = asn_mod.enrich("AS15169")
    assert result is not None
    assert result["asn"] == 15169
    assert result["name"] == "GOOGLE"
    assert result["description_short"] == "GOOGLE, US"
    assert result["rir_name"] == "RIPE NCC"
    assert result["announced_prefixes_count"] == 3
    assert result["is_active"] is True


@responses.activate
def test_asn_module_overview_404_returns_none():
    responses.add(
        responses.GET,
        f"{asn_mod.BASE_URL}/as-overview/data.json",
        status=404,
    )
    assert asn_mod.enrich("AS99999999") is None


@responses.activate
def test_asn_module_overview_500_returns_none():
    responses.add(
        responses.GET,
        f"{asn_mod.BASE_URL}/as-overview/data.json",
        status=500,
    )
    assert asn_mod.enrich("AS15169") is None


@responses.activate
def test_asn_module_handles_malformed_json():
    responses.add(
        responses.GET,
        f"{asn_mod.BASE_URL}/as-overview/data.json",
        body="not json",
        status=200,
    )
    assert asn_mod.enrich("AS15169") is None


@responses.activate
def test_asn_module_error_status_returns_none():
    responses.add(
        responses.GET,
        f"{asn_mod.BASE_URL}/as-overview/data.json",
        json={"status": "error"},
        status=200,
    )
    assert asn_mod.enrich("AS15169") is None


@responses.activate
def test_asn_module_prefixes_failure_does_not_block_overview():
    """If the prefix-count secondary call fails, the overview still returns."""
    responses.add(
        responses.GET,
        f"{asn_mod.BASE_URL}/as-overview/data.json",
        json=_OVERVIEW,
        status=200,
    )
    responses.add(
        responses.GET,
        f"{asn_mod.BASE_URL}/announced-prefixes/data.json",
        status=500,
    )
    result = asn_mod.enrich("AS15169")
    assert result is not None
    assert result["asn"] == 15169
    assert result["announced_prefixes_count"] is None


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

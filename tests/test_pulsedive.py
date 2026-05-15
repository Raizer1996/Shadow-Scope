"""Tests for the Pulsedive enrichment module + scoring."""

import responses

from ioc_tool.core import score
from ioc_tool.modules import pulsedive


@responses.activate
def test_pulsedive_returns_payload_on_hit():
    responses.add(
        responses.GET,
        pulsedive.BASE_URL,
        json={
            "indicator": "evil.example.com",
            "type": "domain",
            "risk": "high",
            "risk_recommended": "high",
            "threats": [{"name": "Phishing"}],
            "feeds": [],
        },
        status=200,
    )
    result = pulsedive.enrich("evil.example.com", "domain")
    assert result is not None
    assert result["risk"] == "high"
    assert result["threats"][0]["name"] == "Phishing"


@responses.activate
def test_pulsedive_error_envelope_is_none():
    """Pulsedive returns ``{"error": "..."}`` on miss — treat as no signal."""
    responses.add(
        responses.GET, pulsedive.BASE_URL,
        json={"error": "Indicator not found"}, status=200,
    )
    assert pulsedive.enrich("8.8.8.8", "ip") is None


@responses.activate
def test_pulsedive_handles_500():
    responses.add(responses.GET, pulsedive.BASE_URL, status=500)
    assert pulsedive.enrich("8.8.8.8", "ip") is None


@responses.activate
def test_pulsedive_handles_malformed_json():
    responses.add(responses.GET, pulsedive.BASE_URL, body="not json", status=200)
    assert pulsedive.enrich("8.8.8.8", "ip") is None


def test_pulsedive_rejects_unsupported_types():
    """Hash + CVE + email skip the network call entirely."""
    assert pulsedive.enrich("d41d8cd98f00b204e9800998ecf8427e", "hash") is None
    assert pulsedive.enrich("CVE-2024-1234", "cve") is None
    assert pulsedive.enrich("foo@bar.com", "email") is None


@responses.activate
def test_pulsedive_uses_key_when_set(monkeypatch):
    """When PULSEDIVE_API_KEY is set, it's passed as a query param."""
    monkeypatch.setenv("PULSEDIVE_API_KEY", "deadbeef")
    responses.add(
        responses.GET, pulsedive.BASE_URL,
        json={"indicator": "8.8.8.8", "risk": "none"}, status=200,
    )
    pulsedive.enrich("8.8.8.8", "ip")
    assert "key=deadbeef" in responses.calls[0].request.url


@responses.activate
def test_pulsedive_no_key_omits_param(monkeypatch):
    monkeypatch.delenv("PULSEDIVE_API_KEY", raising=False)
    responses.add(
        responses.GET, pulsedive.BASE_URL,
        json={"indicator": "8.8.8.8", "risk": "none"}, status=200,
    )
    pulsedive.enrich("8.8.8.8", "ip")
    assert "key=" not in responses.calls[0].request.url


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def test_pulsedive_score_critical():
    assert score.calculate_pulsedive_score({"risk": "critical"}) == 95


def test_pulsedive_score_high():
    assert score.calculate_pulsedive_score({"risk": "high"}) == 80


def test_pulsedive_score_medium():
    assert score.calculate_pulsedive_score({"risk": "medium"}) == 55


def test_pulsedive_score_low():
    assert score.calculate_pulsedive_score({"risk": "low"}) == 25


def test_pulsedive_score_unknown_or_none():
    assert score.calculate_pulsedive_score({"risk": "unknown"}) == 0
    assert score.calculate_pulsedive_score({"risk": "none"}) == 0
    assert score.calculate_pulsedive_score(None) == 0
    assert score.calculate_pulsedive_score({}) == 0

"""Mocked tests for enrichment modules.

All external API calls are intercepted with the `responses` library so the
suite never touches a live service. Each test sets the relevant env var via
``monkeypatch.setenv`` so the module's ``os.getenv`` reads a fake key rather
than whatever happens to live in ``ioc_tool/.env``.

If a module switches HTTP libraries (e.g. ``httpx``) update the corresponding
test — the contract being verified is: parses success payloads, returns
``None`` (or ``{"error": ...}`` where the implementation chose that shape) on
failure, and never crashes the caller.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
import responses

from ioc_tool.modules import (
    abuseipdb,
    greynoise,
    ipinfo_mod,
    ip_quality_score,
    shodan_mod,
    tor,
    urlhaus,
    vt,
    whois_mod,
)
from ioc_tool.core import score as score_mod
import requests


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------


@responses.activate
def test_vt_enrich_ip_returns_stats(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VT_API_KEY", "fake-key-for-test")
    responses.add(
        responses.GET,
        "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4",
        json={
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "harmless": 60,
                        "suspicious": 0,
                        "undetected": 35,
                    }
                }
            }
        },
        status=200,
    )
    result = vt.enrich_ip("1.2.3.4")
    assert result is not None
    assert result["last_analysis_stats"]["malicious"] == 5


@responses.activate
def test_vt_enrich_ip_handles_unauthorized(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VT_API_KEY", "bad-key")
    responses.add(
        responses.GET,
        "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4",
        json={"error": {"code": "AuthenticationRequiredError"}},
        status=401,
    )
    assert vt.enrich_ip("1.2.3.4") is None


@responses.activate
def test_vt_enrich_domain_returns_attributes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VT_API_KEY", "fake-key-for-test")
    responses.add(
        responses.GET,
        "https://www.virustotal.com/api/v3/domains/evil.example",
        json={
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 2,
                        "harmless": 70,
                        "suspicious": 1,
                        "undetected": 27,
                    },
                    "reputation": -15,
                }
            }
        },
        status=200,
    )
    result = vt.enrich_domain("evil.example")
    assert result is not None
    assert result["reputation"] == -15
    assert result["last_analysis_stats"]["suspicious"] == 1


@responses.activate
def test_vt_enrich_hash_handles_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VT_API_KEY", "fake-key-for-test")
    responses.add(
        responses.GET,
        "https://www.virustotal.com/api/v3/files/abc123",
        json={"error": {"code": "QuotaExceededError"}},
        status=429,
    )
    assert vt.enrich_hash("abc123") is None


def test_vt_enrich_ip_skips_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """No API key → short-circuit to None, no HTTP call attempted."""
    monkeypatch.delenv("VT_API_KEY", raising=False)
    assert vt.enrich_ip("1.2.3.4") is None


# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------


@responses.activate
def test_abuseipdb_enrich_ip_returns_data(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fake-key-for-test")
    responses.add(
        responses.GET,
        "https://api.abuseipdb.com/api/v2/check",
        json={
            "data": {
                "ipAddress": "1.2.3.4",
                "abuseConfidenceScore": 73,
                "countryCode": "US",
                "totalReports": 42,
            }
        },
        status=200,
    )
    result = abuseipdb.enrich_ip("1.2.3.4")
    assert result is not None
    assert result["abuseConfidenceScore"] == 73
    assert result["totalReports"] == 42


@responses.activate
def test_abuseipdb_enrich_ip_returns_none_on_server_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fake-key-for-test")
    responses.add(
        responses.GET,
        "https://api.abuseipdb.com/api/v2/check",
        json={"errors": [{"detail": "Internal Server Error"}]},
        status=500,
    )
    assert abuseipdb.enrich_ip("1.2.3.4") is None


def test_abuseipdb_enrich_ip_skips_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    assert abuseipdb.enrich_ip("1.2.3.4") is None


# ---------------------------------------------------------------------------
# Shodan
# ---------------------------------------------------------------------------


@responses.activate
def test_shodan_host_search_returns_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHODAN_API_KEY", "fake-key-for-test")
    responses.add(
        responses.GET,
        "https://api.shodan.io/shodan/host/1.2.3.4",
        json={
            "ip_str": "1.2.3.4",
            "ports": [22, 80, 443],
            "hostnames": ["host.example.com"],
            "country_name": "United States",
        },
        status=200,
    )
    result = shodan_mod.host_search("1.2.3.4")
    assert "error" not in result
    assert result["ports"] == [22, 80, 443]
    assert result["ip_str"] == "1.2.3.4"


@responses.activate
def test_shodan_host_search_returns_error_dict_on_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHODAN_API_KEY", "bad-key")
    responses.add(
        responses.GET,
        "https://api.shodan.io/shodan/host/1.2.3.4",
        json={"error": "Invalid API key"},
        status=401,
    )
    result = shodan_mod.host_search("1.2.3.4")
    assert "error" in result
    assert "401" in result["error"]


def test_shodan_host_search_reports_missing_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    result = shodan_mod.host_search("1.2.3.4")
    assert result == {"error": "Missing SHODAN_API_KEY"}


# ---------------------------------------------------------------------------
# IPQualityScore
# ---------------------------------------------------------------------------


@responses.activate
def test_ipqs_enrich_ip_returns_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IP_QUALITY_SCORE", "fake-key-for-test")
    responses.add(
        responses.GET,
        "https://www.ipqualityscore.com/api/json/ip/fake-key-for-test/1.2.3.4",
        json={
            "success": True,
            "fraud_score": 88,
            "country_code": "US",
            "proxy": True,
            "vpn": False,
            "tor": False,
        },
        status=200,
    )
    result = ip_quality_score.enrich_ip("1.2.3.4")
    assert result is not None
    assert result["fraud_score"] == 88
    assert result["proxy"] is True


@responses.activate
def test_ipqs_enrich_ip_returns_none_on_500(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IP_QUALITY_SCORE", "fake-key-for-test")
    responses.add(
        responses.GET,
        "https://www.ipqualityscore.com/api/json/ip/fake-key-for-test/1.2.3.4",
        json={"success": False, "message": "internal error"},
        status=500,
    )
    assert ip_quality_score.enrich_ip("1.2.3.4") is None


def test_ipqs_enrich_ip_skips_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IP_QUALITY_SCORE", raising=False)
    assert ip_quality_score.enrich_ip("1.2.3.4") is None


# ---------------------------------------------------------------------------
# IPinfo
# ---------------------------------------------------------------------------


@responses.activate
def test_ipinfo_enrich_ip_returns_geo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IP_INFO_API", "fake-key-for-test")
    responses.add(
        responses.GET,
        "https://ipinfo.io/1.2.3.4",
        json={
            "ip": "1.2.3.4",
            "city": "Mountain View",
            "region": "California",
            "country": "US",
            "org": "AS15169 Google LLC",
        },
        status=200,
    )
    result = ipinfo_mod.enrich_ip("1.2.3.4")
    assert result is not None
    assert result["country"] == "US"
    assert result["org"].startswith("AS15169")


@responses.activate
def test_ipinfo_enrich_ip_returns_none_on_429(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IP_INFO_API", "fake-key-for-test")
    responses.add(
        responses.GET,
        "https://ipinfo.io/1.2.3.4",
        json={"error": {"title": "RateLimitExceeded"}},
        status=429,
    )
    assert ipinfo_mod.enrich_ip("1.2.3.4") is None


def test_ipinfo_enrich_ip_skips_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IP_INFO_API", raising=False)
    assert ipinfo_mod.enrich_ip("1.2.3.4") is None


# ---------------------------------------------------------------------------
# Tor exit-node list
# ---------------------------------------------------------------------------


def test_tor_is_tor_node_hit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """A known IP in the cached exit-list is detected as a Tor exit node."""
    fake_cache = tmp_path / "tor_nodes.txt"
    fake_cache.write_text("9.9.9.9\n10.10.10.10\n171.25.193.20\n")
    monkeypatch.setattr(tor, "CACHE_FILE", str(fake_cache))
    assert tor.is_tor_node("10.10.10.10") is True


def test_tor_is_tor_node_miss(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    fake_cache = tmp_path / "tor_nodes.txt"
    fake_cache.write_text("9.9.9.9\n10.10.10.10\n")
    monkeypatch.setattr(tor, "CACHE_FILE", str(fake_cache))
    assert tor.is_tor_node("8.8.8.8") is False


@responses.activate
def test_tor_update_writes_cache(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """update_tor_list fetches the bulk list and writes it to the cache file."""
    fake_cache = tmp_path / "tor_nodes.txt"
    monkeypatch.setattr(tor, "CACHE_FILE", str(fake_cache))
    responses.add(
        responses.GET,
        "https://check.torproject.org/torbulkexitlist",
        body="1.1.1.1\n2.2.2.2\n",
        status=200,
    )
    assert tor.update_tor_list() is True
    assert fake_cache.read_text() == "1.1.1.1\n2.2.2.2\n"


@responses.activate
def test_tor_update_returns_false_on_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    fake_cache = tmp_path / "tor_nodes.txt"
    monkeypatch.setattr(tor, "CACHE_FILE", str(fake_cache))
    responses.add(
        responses.GET,
        "https://check.torproject.org/torbulkexitlist",
        body="",
        status=503,
    )
    assert tor.update_tor_list() is False
    assert not fake_cache.exists()


# ---------------------------------------------------------------------------
# WHOIS — python-whois uses raw sockets, so we patch the library entry point
# rather than going through `responses`.
# ---------------------------------------------------------------------------


def test_whois_get_whois_data_returns_record() -> None:
    """A successful whois call returns the library's dict-like record."""
    fake_record = {
        "domain_name": "EXAMPLE.COM",
        "registrar": "Reserved",
        "creation_date": "1995-08-14",
    }
    with patch("ioc_tool.modules.whois_mod.whois.whois", return_value=fake_record):
        result = whois_mod.get_whois_data("example.com")
    assert result == fake_record
    assert result["registrar"] == "Reserved"


def test_whois_get_whois_data_returns_none_on_exception() -> None:
    """Any error in the whois lookup yields None (and doesn't propagate)."""
    with patch(
        "ioc_tool.modules.whois_mod.whois.whois",
        side_effect=Exception("network error"),
    ):
        result = whois_mod.get_whois_data("example.com")
    assert result is None


# ---------------------------------------------------------------------------
# URLhaus (abuse.ch) — no API key required
# ---------------------------------------------------------------------------


class TestURLhaus:
    """Cover the URLhaus module: hit, miss, network error, and scoring."""

    @responses.activate
    def test_urlhaus_url_hit(self) -> None:
        """A malicious URL lookup returns the parsed payload."""
        responses.add(
            responses.POST,
            "https://urlhaus-api.abuse.ch/v1/url/",
            json={
                "query_status": "ok",
                "id": "12345",
                "url": "http://malicious.example/payload.exe",
                "url_status": "online",
                "threat": "malware_download",
                "tags": ["emotet", "cobaltstrike"],
                "date_added": "2024-01-15 12:34:56",
                "host": "malicious.example",
                "payloads": [
                    {
                        "filename": "payload.exe",
                        "response_md5": "deadbeef",
                        "response_sha256": "cafe1234",
                        "file_type": "exe",
                    }
                ],
            },
            status=200,
        )
        result = urlhaus.enrich_url("http://malicious.example/payload.exe")
        assert result is not None
        assert result["query_status"] == "ok"
        assert result["url_status"] == "online"
        assert result["threat"] == "malware_download"
        assert "emotet" in result["tags"]

    @responses.activate
    def test_urlhaus_url_no_result(self) -> None:
        """query_status != 'ok' is treated as a miss → None."""
        responses.add(
            responses.POST,
            "https://urlhaus-api.abuse.ch/v1/url/",
            json={"query_status": "no_results"},
            status=200,
        )
        assert urlhaus.enrich_url("http://benign.example/index.html") is None

    @responses.activate
    def test_urlhaus_host_hit(self) -> None:
        """Host lookup returns the parsed payload with url history."""
        responses.add(
            responses.POST,
            "https://urlhaus-api.abuse.ch/v1/host/",
            json={
                "query_status": "ok",
                "host": "evil.example.com",
                "url_count": "3",
                "urls": [
                    {
                        "id": "1",
                        "url": "http://evil.example.com/a.exe",
                        "url_status": "online",
                        "threat": "malware_download",
                    }
                ],
            },
            status=200,
        )
        result = urlhaus.enrich_host("evil.example.com")
        assert result is not None
        assert result["host"] == "evil.example.com"
        assert result["url_count"] == "3"
        assert len(result["urls"]) == 1

    @responses.activate
    def test_urlhaus_request_exception(self) -> None:
        """Network/connection errors return None without crashing."""
        responses.add(
            responses.POST,
            "https://urlhaus-api.abuse.ch/v1/url/",
            body=requests.exceptions.ConnectionError("kaboom"),
        )
        assert urlhaus.enrich_url("http://anything.example/x") is None

    @responses.activate
    def test_urlhaus_host_request_exception(self) -> None:
        """ConnectionError on the host endpoint also returns None cleanly."""
        responses.add(
            responses.POST,
            "https://urlhaus-api.abuse.ch/v1/host/",
            body=requests.exceptions.ConnectionError("network down"),
        )
        assert urlhaus.enrich_host("evil.example.com") is None

    def test_calculate_urlhaus_score_online(self) -> None:
        """url_status='online' is the strongest signal → 95."""
        assert (
            score_mod.calculate_urlhaus_score(
                {"query_status": "ok", "url_status": "online"}
            )
            == 95
        )

    def test_calculate_urlhaus_score_offline(self) -> None:
        """url_status='offline' = 70 (less severe than live infrastructure)."""
        assert (
            score_mod.calculate_urlhaus_score(
                {"query_status": "ok", "url_status": "offline"}
            )
            == 70
        )

    def test_calculate_urlhaus_score_other_hit(self) -> None:
        """A hit with no url_status (e.g. host-level) defaults to 80."""
        assert score_mod.calculate_urlhaus_score({"query_status": "ok"}) == 80

    def test_calculate_urlhaus_score_none(self) -> None:
        """None / empty payload → score 0."""
        assert score_mod.calculate_urlhaus_score(None) == 0
        assert score_mod.calculate_urlhaus_score({}) == 0


# ---------------------------------------------------------------------------
# GreyNoise (Community API) — IP-only background-noise classification
# ---------------------------------------------------------------------------


class TestGreyNoise:
    """Cover the GreyNoise module: hit, miss, errors, and scoring."""

    @responses.activate
    def test_greynoise_benign_noise_hit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Benign noise hit (e.g. Censys scanner) returns the full payload."""
        monkeypatch.setenv("GREYNOISE_API_KEY", "fake-key-for-test")
        responses.add(
            responses.GET,
            "https://api.greynoise.io/v3/community/1.2.3.4",
            json={
                "ip": "1.2.3.4",
                "noise": True,
                "riot": False,
                "classification": "benign",
                "name": "Censys",
                "link": "https://viz.greynoise.io/ip/1.2.3.4",
                "last_seen": "2024-12-01",
                "message": "Success",
            },
            status=200,
        )
        result = greynoise.enrich_ip("1.2.3.4")
        assert result is not None
        assert result["classification"] == "benign"
        assert result["noise"] is True
        assert result["name"] == "Censys"

    @responses.activate
    def test_greynoise_malicious_hit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Malicious classification surfaces as-is for scoring."""
        monkeypatch.setenv("GREYNOISE_API_KEY", "fake-key-for-test")
        responses.add(
            responses.GET,
            "https://api.greynoise.io/v3/community/5.6.7.8",
            json={
                "ip": "5.6.7.8",
                "noise": True,
                "riot": False,
                "classification": "malicious",
                "name": "Mirai",
                "message": "Success",
            },
            status=200,
        )
        result = greynoise.enrich_ip("5.6.7.8")
        assert result is not None
        assert result["classification"] == "malicious"
        assert result["name"] == "Mirai"

    @responses.activate
    def test_greynoise_unknown_response(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """classification='unknown' still returns the dict — not filtered out."""
        monkeypatch.setenv("GREYNOISE_API_KEY", "fake-key-for-test")
        responses.add(
            responses.GET,
            "https://api.greynoise.io/v3/community/9.9.9.9",
            json={
                "ip": "9.9.9.9",
                "noise": False,
                "riot": False,
                "classification": "unknown",
                "message": (
                    "IP not observed scanning the internet or contained in "
                    "RIOT data set"
                ),
            },
            status=200,
        )
        result = greynoise.enrich_ip("9.9.9.9")
        assert result is not None
        assert result["classification"] == "unknown"

    def test_greynoise_no_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Missing GREYNOISE_API_KEY → returns None without an HTTP call."""
        monkeypatch.delenv("GREYNOISE_API_KEY", raising=False)
        # No responses.add() — if a request were attempted under
        # @responses.activate it would error. Plain call here is enough
        # since we short-circuit before requests.get is invoked.
        assert greynoise.enrich_ip("1.2.3.4") is None

    @responses.activate
    def test_greynoise_unauthorized(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A 401 from a bad/expired key returns None."""
        monkeypatch.setenv("GREYNOISE_API_KEY", "bad-key")
        responses.add(
            responses.GET,
            "https://api.greynoise.io/v3/community/1.2.3.4",
            json={"message": "forbidden"},
            status=401,
        )
        assert greynoise.enrich_ip("1.2.3.4") is None

    @responses.activate
    def test_greynoise_request_exception(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Network/connection error returns None cleanly (never raises)."""
        monkeypatch.setenv("GREYNOISE_API_KEY", "fake-key-for-test")
        responses.add(
            responses.GET,
            "https://api.greynoise.io/v3/community/1.2.3.4",
            body=requests.exceptions.ConnectionError("kaboom"),
        )
        assert greynoise.enrich_ip("1.2.3.4") is None

    def test_calculate_greynoise_score_malicious(self) -> None:
        """classification='malicious' → 90."""
        assert (
            score_mod.calculate_greynoise_score(
                {"classification": "malicious", "noise": True}
            )
            == 90
        )

    def test_calculate_greynoise_score_benign(self) -> None:
        """benign noise scanners + RIOT trusted services both score 0."""
        assert (
            score_mod.calculate_greynoise_score(
                {"classification": "benign", "noise": True}
            )
            == 0
        )
        assert (
            score_mod.calculate_greynoise_score(
                {"classification": "benign", "riot": True}
            )
            == 0
        )

    def test_calculate_greynoise_score_none(self) -> None:
        """None / empty payload / unknown classification all score 0."""
        assert score_mod.calculate_greynoise_score(None) == 0
        assert score_mod.calculate_greynoise_score({}) == 0
        assert (
            score_mod.calculate_greynoise_score({"classification": "unknown"}) == 0
        )

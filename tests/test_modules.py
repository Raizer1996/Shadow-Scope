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
import requests
import responses

from ioc_tool.core import score as score_mod
from ioc_tool.modules import (
    abuseipdb,
    epss,
    greynoise,
    ip_quality_score,
    ipinfo_mod,
    kev,
    malwarebazaar,
    nvd,
    otx,
    shodan_mod,
    threatfox,
    tor,
    urlhaus,
    urlscan,
    vt,
    whois_mod,
)

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


# ---------------------------------------------------------------------------
# ThreatFox (abuse.ch) — no API key required, broad IOC scope
# ---------------------------------------------------------------------------


class TestThreatFox:
    """Cover the ThreatFox module: hit (ip/hash), miss flavors, errors, scoring."""

    @responses.activate
    def test_threatfox_ip_hit(self) -> None:
        """An IP lookup with a botnet_cc match returns the first data entry."""
        responses.add(
            responses.POST,
            "https://threatfox-api.abuse.ch/api/v1/",
            json={
                "query_status": "ok",
                "data": [
                    {
                        "id": "12345",
                        "ioc": "1.2.3.4:443",
                        "ioc_type": "ip:port",
                        "threat_type": "botnet_cc",
                        "malware": "Emotet",
                        "malware_alias": "Geodo",
                        "first_seen": "2024-01-01 12:00:00 UTC",
                        "confidence_level": 100,
                        "tags": ["emotet", "c2"],
                    }
                ],
            },
            status=200,
        )
        result = threatfox.enrich("1.2.3.4")
        assert result is not None
        assert result["malware"] == "Emotet"
        assert result["threat_type"] == "botnet_cc"
        assert result["confidence_level"] == 100

    @responses.activate
    def test_threatfox_hash_hit(self) -> None:
        """A hash IOC also routes through the same /api/v1/ endpoint."""
        responses.add(
            responses.POST,
            "https://threatfox-api.abuse.ch/api/v1/",
            json={
                "query_status": "ok",
                "data": [
                    {
                        "id": "98765",
                        "ioc": "abc123def456",
                        "ioc_type": "sha256_hash",
                        "threat_type": "payload",
                        "malware": "TrickBot",
                        "confidence_level": 90,
                        "tags": ["trickbot"],
                    }
                ],
            },
            status=200,
        )
        result = threatfox.enrich(
            "d3486ae9136e7856bc42212385ea797094475802bcc9b2a8b6f23f5a1f5f4b6c"
        )
        assert result is not None
        assert result["malware"] == "TrickBot"
        assert result["ioc_type"] == "sha256_hash"

    @responses.activate
    def test_threatfox_no_result(self) -> None:
        """query_status 'no_result' is a clean miss → None."""
        responses.add(
            responses.POST,
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query_status": "no_result"},
            status=200,
        )
        assert threatfox.enrich("8.8.8.8") is None

    @responses.activate
    def test_threatfox_illegal_search(self) -> None:
        """An illegal_search_term response is treated as miss → None."""
        responses.add(
            responses.POST,
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query_status": "illegal_search_term"},
            status=200,
        )
        assert threatfox.enrich("???") is None

    @responses.activate
    def test_threatfox_request_exception(self) -> None:
        """Network errors return None without crashing."""
        responses.add(
            responses.POST,
            "https://threatfox-api.abuse.ch/api/v1/",
            body=requests.exceptions.ConnectionError("kaboom"),
        )
        assert threatfox.enrich("1.2.3.4") is None

    def test_calculate_threatfox_score_high_confidence(self) -> None:
        """confidence_level 100 → 95 (top severity)."""
        assert (
            score_mod.calculate_threatfox_score(
                {"malware": "Emotet", "confidence_level": 100}
            )
            == 95
        )

    def test_calculate_threatfox_score_medium(self) -> None:
        """confidence_level 60 → 80 (medium-confidence hit)."""
        assert (
            score_mod.calculate_threatfox_score(
                {"malware": "Cobalt Strike", "confidence_level": 60}
            )
            == 80
        )

    def test_calculate_threatfox_score_low(self) -> None:
        """confidence_level 30 → 60 (lower confidence but still a hit)."""
        assert (
            score_mod.calculate_threatfox_score(
                {"malware": "unknown", "confidence_level": 30}
            )
            == 60
        )

    def test_calculate_threatfox_score_none(self) -> None:
        """None / empty payload → 0."""
        assert score_mod.calculate_threatfox_score(None) == 0
        assert score_mod.calculate_threatfox_score({}) == 0


# ---------------------------------------------------------------------------
# MalwareBazaar (abuse.ch) — hash-only, no API key
# ---------------------------------------------------------------------------


class TestMalwareBazaar:
    """Cover the MalwareBazaar module: hit, miss, network error, scoring."""

    @responses.activate
    def test_malwarebazaar_hash_hit(self) -> None:
        """A hash lookup with an Emotet sample returns the first data entry."""
        responses.add(
            responses.POST,
            "https://mb-api.abuse.ch/api/v1/",
            json={
                "query_status": "ok",
                "data": [
                    {
                        "sha256_hash": "abc123def456",
                        "md5_hash": "deadbeef",
                        "sha1_hash": "cafe1234",
                        "file_name": "invoice.exe",
                        "file_size": 12345,
                        "file_type": "exe",
                        "signature": "Emotet",
                        "tags": ["emotet", "exe"],
                        "first_seen": "2024-01-01 12:00:00",
                        "delivery_method": "email",
                    }
                ],
            },
            status=200,
        )
        result = malwarebazaar.enrich_hash("abc123def456")
        assert result is not None
        assert result["signature"] == "Emotet"
        assert result["file_type"] == "exe"
        assert result["file_size"] == 12345

    @responses.activate
    def test_malwarebazaar_not_found(self) -> None:
        """query_status 'hash_not_found' is a clean miss → None."""
        responses.add(
            responses.POST,
            "https://mb-api.abuse.ch/api/v1/",
            json={"query_status": "hash_not_found"},
            status=200,
        )
        assert malwarebazaar.enrich_hash("0" * 64) is None

    @responses.activate
    def test_malwarebazaar_request_exception(self) -> None:
        """Network errors return None without crashing."""
        responses.add(
            responses.POST,
            "https://mb-api.abuse.ch/api/v1/",
            body=requests.exceptions.ConnectionError("kaboom"),
        )
        assert malwarebazaar.enrich_hash("abc123") is None

    def test_calculate_malwarebazaar_score_hit(self) -> None:
        """Any hit → 95 (presence of a sample is a strong signal)."""
        assert (
            score_mod.calculate_malwarebazaar_score(
                {"signature": "Emotet", "file_type": "exe"}
            )
            == 95
        )

    def test_calculate_malwarebazaar_score_none(self) -> None:
        """None / empty payload → 0."""
        assert score_mod.calculate_malwarebazaar_score(None) == 0
        assert score_mod.calculate_malwarebazaar_score({}) == 0


# ---------------------------------------------------------------------------
# AlienVault OTX — community pulses across IP / domain / URL / hash
# ---------------------------------------------------------------------------


class TestOTX:
    """Cover the OTX module: per-type path mapping, hits, misses, scoring."""

    @responses.activate
    def test_otx_ip_high_pulse_count(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An IP with many pulses returns the full payload (including count)."""
        monkeypatch.setenv("OTX_API_KEY", "fake-key-for-test")
        responses.add(
            responses.GET,
            "https://otx.alienvault.com/api/v1/indicators/IPv4/1.2.3.4/general",
            json={
                "pulse_info": {
                    "count": 15,
                    "pulses": [
                        {
                            "id": "abc",
                            "name": "Emotet C2 May 2024",
                            "tags": ["emotet", "c2"],
                            "adversary": "TA542",
                            "created": "2024-05-01",
                        }
                    ],
                },
                "reputation": -3,
                "country_name": "United States",
                "asn": "AS15169 Google LLC",
            },
            status=200,
        )
        result = otx.enrich("1.2.3.4", "ip")
        assert result is not None
        assert result["pulse_info"]["count"] == 15
        assert result["pulse_info"]["pulses"][0]["adversary"] == "TA542"

    @responses.activate
    def test_otx_domain_few_pulses(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A domain with a small number of pulses still returns the dict."""
        monkeypatch.setenv("OTX_API_KEY", "fake-key-for-test")
        responses.add(
            responses.GET,
            "https://otx.alienvault.com/api/v1/indicators/domain/evil.example/general",
            json={
                "pulse_info": {
                    "count": 2,
                    "pulses": [
                        {"id": "1", "name": "Phishing wave Q1", "tags": ["phishing"]},
                        {"id": "2", "name": "Lookalike domain set", "tags": []},
                    ],
                },
                "reputation": 0,
            },
            status=200,
        )
        result = otx.enrich("evil.example", "domain")
        assert result is not None
        assert result["pulse_info"]["count"] == 2

    @responses.activate
    def test_otx_no_pulses(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``pulse_info.count == 0`` is still a valid 200 → dict, not None.

        A negative (no-known-pulse) result is its own signal versus a
        network-error miss.
        """
        monkeypatch.setenv("OTX_API_KEY", "fake-key-for-test")
        responses.add(
            responses.GET,
            "https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general",
            json={
                "pulse_info": {"count": 0, "pulses": []},
                "reputation": 0,
            },
            status=200,
        )
        result = otx.enrich("8.8.8.8", "ip")
        assert result is not None
        assert result["pulse_info"]["count"] == 0

    @responses.activate
    def test_otx_url_path_mapping(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A URL IOC must hit the ``/indicators/url/<value>/general`` path."""
        monkeypatch.setenv("OTX_API_KEY", "fake-key-for-test")
        responses.add(
            responses.GET,
            "https://otx.alienvault.com/api/v1/indicators/url/"
            "http://malicious.example/payload.exe/general",
            json={"pulse_info": {"count": 1, "pulses": [{"name": "drop"}]}},
            status=200,
        )
        result = otx.enrich("http://malicious.example/payload.exe", "url")
        assert result is not None
        assert result["pulse_info"]["count"] == 1

    @responses.activate
    def test_otx_hash_path_mapping(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A hash IOC routes through the ``/indicators/file/<hash>/general`` path."""
        monkeypatch.setenv("OTX_API_KEY", "fake-key-for-test")
        sha = "d3486ae9136e7856bc42212385ea797094475802bcc9b2a8b6f23f5a1f5f4b6c"
        responses.add(
            responses.GET,
            f"https://otx.alienvault.com/api/v1/indicators/file/{sha}/general",
            json={
                "pulse_info": {
                    "count": 4,
                    "pulses": [{"name": "TrickBot sample set", "adversary": ""}],
                },
                "reputation": 0,
            },
            status=200,
        )
        result = otx.enrich(sha, "hash")
        assert result is not None
        assert result["pulse_info"]["count"] == 4

    def test_otx_no_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Missing ``OTX_API_KEY`` → returns None without an HTTP call."""
        monkeypatch.delenv("OTX_API_KEY", raising=False)
        # No responses.add() needed — short-circuits before requests.get fires.
        assert otx.enrich("1.2.3.4", "ip") is None

    @responses.activate
    def test_otx_unauthorized(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A 401 from a bad/expired key returns None."""
        monkeypatch.setenv("OTX_API_KEY", "bad-key")
        responses.add(
            responses.GET,
            "https://otx.alienvault.com/api/v1/indicators/IPv4/1.2.3.4/general",
            json={"detail": "Authentication credentials were not provided."},
            status=401,
        )
        assert otx.enrich("1.2.3.4", "ip") is None

    @responses.activate
    def test_otx_request_exception(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Network / connection errors return None without crashing."""
        monkeypatch.setenv("OTX_API_KEY", "fake-key-for-test")
        responses.add(
            responses.GET,
            "https://otx.alienvault.com/api/v1/indicators/IPv4/1.2.3.4/general",
            body=requests.exceptions.ConnectionError("kaboom"),
        )
        assert otx.enrich("1.2.3.4", "ip") is None

    def test_otx_score_zero_pulses(self) -> None:
        """No pulses + non-negative reputation → 0."""
        assert (
            score_mod.calculate_otx_score(
                {"pulse_info": {"count": 0, "pulses": []}, "reputation": 0}
            )
            == 0
        )

    def test_otx_score_few_pulses(self) -> None:
        """1–2 pulses → 50."""
        assert (
            score_mod.calculate_otx_score(
                {"pulse_info": {"count": 2, "pulses": []}, "reputation": 0}
            )
            == 50
        )

    def test_otx_score_many_pulses(self) -> None:
        """3–9 pulses → 75."""
        assert (
            score_mod.calculate_otx_score(
                {"pulse_info": {"count": 5, "pulses": []}, "reputation": 0}
            )
            == 75
        )

    def test_otx_score_widespread(self) -> None:
        """≥10 pulses → 90."""
        assert (
            score_mod.calculate_otx_score(
                {"pulse_info": {"count": 12, "pulses": []}, "reputation": 0}
            )
            == 90
        )

    def test_otx_score_negative_rep_bumps(self) -> None:
        """pulse_count=10 + reputation=-5 → 90 + 10 = 100 (capped)."""
        assert (
            score_mod.calculate_otx_score(
                {"pulse_info": {"count": 10, "pulses": []}, "reputation": -5}
            )
            == 100
        )

    def test_otx_score_none(self) -> None:
        """None / empty payload → 0."""
        assert score_mod.calculate_otx_score(None) == 0
        assert score_mod.calculate_otx_score({}) == 0


# ---------------------------------------------------------------------------
# URLscan.io — historical scan-archive search (IP / domain / URL)
# ---------------------------------------------------------------------------


class TestURLscan:
    """Cover the URLscan.io module: hits (malicious + clean), misses, scoring."""

    @responses.activate
    def test_urlscan_url_hit_with_malicious(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A URL with a malicious-verdict result returns the full search dict."""
        monkeypatch.setenv("URLSCAN_API_KEY", "fake-key-for-test")
        responses.add(
            responses.GET,
            "https://urlscan.io/api/v1/search/",
            json={
                "total": 5,
                "results": [
                    {
                        "task": {
                            "uuid": "abc-123",
                            "url": "http://malicious.example/payload",
                            "time": "2024-01-15T12:00:00Z",
                            "method": "manual",
                            "visibility": "public",
                        },
                        "page": {
                            "url": "http://malicious.example/payload",
                            "domain": "malicious.example",
                            "ip": "1.2.3.4",
                            "country": "US",
                            "asn": "AS15169",
                        },
                        "verdicts": {
                            "overall": {
                                "malicious": True,
                                "score": 75,
                                "tags": ["phishing"],
                            }
                        },
                        "result": "https://urlscan.io/result/abc-123/",
                    },
                    {
                        "task": {"uuid": "def-456"},
                        "verdicts": {"overall": {"malicious": False}},
                        "result": "https://urlscan.io/result/def-456/",
                    },
                ],
            },
            status=200,
        )
        result = urlscan.enrich("http://malicious.example/payload", "url")
        assert result is not None
        assert result["total"] == 5
        assert result["results"][0]["verdicts"]["overall"]["malicious"] is True
        assert (
            result["results"][0]["result"]
            == "https://urlscan.io/result/abc-123/"
        )

    @responses.activate
    def test_urlscan_domain_hit_no_malicious(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A domain with history but no malicious verdict still returns a dict."""
        monkeypatch.setenv("URLSCAN_API_KEY", "fake-key-for-test")
        responses.add(
            responses.GET,
            "https://urlscan.io/api/v1/search/",
            json={
                "total": 2,
                "results": [
                    {
                        "task": {"uuid": "x1"},
                        "page": {"domain": "example.com"},
                        "verdicts": {"overall": {"malicious": False, "score": 0}},
                        "result": "https://urlscan.io/result/x1/",
                    },
                    {
                        "task": {"uuid": "x2"},
                        "verdicts": {"overall": {"malicious": False}},
                        "result": "https://urlscan.io/result/x2/",
                    },
                ],
            },
            status=200,
        )
        result = urlscan.enrich("example.com", "domain")
        assert result is not None
        assert result["total"] == 2
        # Confirm no malicious verdict present
        assert not any(
            (r.get("verdicts") or {}).get("overall", {}).get("malicious")
            for r in result["results"]
        )

    @responses.activate
    def test_urlscan_ip_lookup_query_format(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """IP lookups must use the ``page.ip:"<value>"`` Lucene query."""
        monkeypatch.setenv("URLSCAN_API_KEY", "fake-key-for-test")
        responses.add(
            responses.GET,
            "https://urlscan.io/api/v1/search/",
            json={"total": 0, "results": []},
            status=200,
        )
        result = urlscan.enrich("1.2.3.4", "ip")
        assert result is not None
        # Confirm the request was built with the expected page.ip:"..." query.
        assert len(responses.calls) == 1
        request_url = responses.calls[0].request.url
        assert 'page.ip%3A%221.2.3.4%22' in request_url or 'page.ip:"1.2.3.4"' in request_url

    @responses.activate
    def test_urlscan_no_history(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``total == 0`` is a successful 200 → dict returned, NOT None."""
        monkeypatch.setenv("URLSCAN_API_KEY", "fake-key-for-test")
        responses.add(
            responses.GET,
            "https://urlscan.io/api/v1/search/",
            json={"total": 0, "results": []},
            status=200,
        )
        result = urlscan.enrich("clean.example", "domain")
        assert result is not None
        assert result["total"] == 0
        assert result["results"] == []

    def test_urlscan_hash_unsupported(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``ioc_type='hash'`` short-circuits to None — no HTTP call made."""
        monkeypatch.setenv("URLSCAN_API_KEY", "fake-key-for-test")
        # No responses.add() — a request here would explode under @responses.activate.
        assert (
            urlscan.enrich(
                "d3486ae9136e7856bc42212385ea797094475802bcc9b2a8b6f23f5a1f5f4b6c",
                "hash",
            )
            is None
        )

    @responses.activate
    def test_urlscan_no_api_key_still_works(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Missing URLSCAN_API_KEY → request still made, no auth header sent."""
        monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
        responses.add(
            responses.GET,
            "https://urlscan.io/api/v1/search/",
            json={"total": 1, "results": [{"task": {"uuid": "anon"}}]},
            status=200,
        )
        result = urlscan.enrich("1.2.3.4", "ip")
        assert result is not None
        assert result["total"] == 1
        # The request must have gone out without the API-Key header.
        assert len(responses.calls) == 1
        assert "API-Key" not in responses.calls[0].request.headers

    @responses.activate
    def test_urlscan_request_exception(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Network / connection errors return None without crashing."""
        monkeypatch.setenv("URLSCAN_API_KEY", "fake-key-for-test")
        responses.add(
            responses.GET,
            "https://urlscan.io/api/v1/search/",
            body=requests.exceptions.ConnectionError("kaboom"),
        )
        assert urlscan.enrich("1.2.3.4", "ip") is None

    def test_urlscan_score_malicious(self) -> None:
        """Any malicious-verdict result → 90."""
        data = {
            "total": 3,
            "results": [
                {"verdicts": {"overall": {"malicious": False}}},
                {"verdicts": {"overall": {"malicious": True, "tags": ["phishing"]}}},
            ],
        }
        assert score_mod.calculate_urlscan_score(data) == 90

    def test_urlscan_score_history_only(self) -> None:
        """History exists but no malicious verdict → 30 (mild signal)."""
        data = {
            "total": 2,
            "results": [
                {"verdicts": {"overall": {"malicious": False}}},
                {"verdicts": {"overall": {"malicious": False}}},
            ],
        }
        assert score_mod.calculate_urlscan_score(data) == 30

    def test_urlscan_score_zero_total(self) -> None:
        """total == 0 → 0 (we looked, nothing was there)."""
        assert (
            score_mod.calculate_urlscan_score({"total": 0, "results": []}) == 0
        )

    def test_urlscan_score_none(self) -> None:
        """None / empty payload → 0."""
        assert score_mod.calculate_urlscan_score(None) == 0
        assert score_mod.calculate_urlscan_score({}) == 0


# ---------------------------------------------------------------------------
# NVD — NIST National Vulnerability Database (CVE → CVSS v3.1)
# ---------------------------------------------------------------------------


class TestNVD:
    """Cover the NVD module: hit, miss, network error, and scoring."""

    @responses.activate
    def test_nvd_cve_hit_critical(self) -> None:
        """A CVE with a CVSS v3.1 baseScore of 9.8 returns the `cve` dict."""
        responses.add(
            responses.GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            json={
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2024-1234",
                            "descriptions": [
                                {"lang": "en", "value": "Critical RCE in Foo."}
                            ],
                            "metrics": {
                                "cvssMetricV31": [
                                    {
                                        "cvssData": {
                                            "baseScore": 9.8,
                                            "baseSeverity": "CRITICAL",
                                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                        }
                                    }
                                ]
                            },
                        }
                    }
                ]
            },
            status=200,
        )
        result = nvd.enrich_cve("CVE-2024-1234")
        assert result is not None
        assert result["id"] == "CVE-2024-1234"
        assert (
            result["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"] == 9.8
        )

    @responses.activate
    def test_nvd_no_match(self) -> None:
        """Empty ``vulnerabilities`` array is a clean miss → None."""
        responses.add(
            responses.GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            json={"vulnerabilities": []},
            status=200,
        )
        assert nvd.enrich_cve("CVE-9999-0000") is None

    @responses.activate
    def test_nvd_request_exception(self) -> None:
        """Network errors return None without crashing."""
        responses.add(
            responses.GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            body=requests.exceptions.ConnectionError("kaboom"),
        )
        assert nvd.enrich_cve("CVE-2024-1234") is None

    @responses.activate
    def test_nvd_non_200(self) -> None:
        """Non-200 status → None (e.g. 503 during NVD maintenance windows)."""
        responses.add(
            responses.GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            json={"message": "Service Unavailable"},
            status=503,
        )
        assert nvd.enrich_cve("CVE-2024-1234") is None

    def test_calculate_nvd_score_critical(self) -> None:
        """baseScore 9.8 → 98 (CVSS * 10, rounded)."""
        data = {
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                ]
            }
        }
        assert score_mod.calculate_nvd_score(data) == 98

    def test_calculate_nvd_score_missing_metric(self) -> None:
        """No cvssMetricV31 block → 0 (we don't fall back to v2)."""
        assert score_mod.calculate_nvd_score({"metrics": {}}) == 0
        assert score_mod.calculate_nvd_score({}) == 0

    def test_calculate_nvd_score_none(self) -> None:
        """None payload → 0."""
        assert score_mod.calculate_nvd_score(None) == 0


# ---------------------------------------------------------------------------
# EPSS — FIRST.org Exploit Prediction Scoring System
# ---------------------------------------------------------------------------


class TestEPSS:
    """Cover the EPSS module: hit, miss, network error, and scoring."""

    @responses.activate
    def test_epss_high_score(self) -> None:
        """A CVE with a high EPSS returns the first ``data[]`` entry."""
        responses.add(
            responses.GET,
            "https://api.first.org/data/v1/epss",
            json={
                "status": "OK",
                "data": [
                    {
                        "cve": "CVE-2024-1234",
                        "epss": "0.97412",
                        "percentile": "0.99876",
                        "date": "2024-05-01",
                    }
                ],
            },
            status=200,
        )
        result = epss.enrich_cve("CVE-2024-1234")
        assert result is not None
        assert result["cve"] == "CVE-2024-1234"
        assert result["epss"] == "0.97412"
        assert result["percentile"] == "0.99876"

    @responses.activate
    def test_epss_no_match(self) -> None:
        """Empty ``data`` array is a clean miss → None."""
        responses.add(
            responses.GET,
            "https://api.first.org/data/v1/epss",
            json={"status": "OK", "data": []},
            status=200,
        )
        assert epss.enrich_cve("CVE-9999-0000") is None

    @responses.activate
    def test_epss_request_exception(self) -> None:
        """Network errors return None without crashing."""
        responses.add(
            responses.GET,
            "https://api.first.org/data/v1/epss",
            body=requests.exceptions.ConnectionError("kaboom"),
        )
        assert epss.enrich_cve("CVE-2024-1234") is None

    def test_calculate_epss_high(self) -> None:
        """epss=0.97 → 97 (probability * 100, rounded)."""
        data = {"epss": "0.97", "percentile": "0.95"}
        assert score_mod.calculate_epss_score(data) == 97

    def test_calculate_epss_top_percentile_floor(self) -> None:
        """epss=0.30 percentile=0.995 → 70 (top-1% floor kicks in)."""
        data = {"epss": "0.30", "percentile": "0.995"}
        assert score_mod.calculate_epss_score(data) == 70

    def test_calculate_epss_score_none(self) -> None:
        """None / empty payload → 0."""
        assert score_mod.calculate_epss_score(None) == 0
        assert score_mod.calculate_epss_score({}) == 0


# ---------------------------------------------------------------------------
# CISA KEV — Known Exploited Vulnerabilities catalog
# ---------------------------------------------------------------------------


class TestKEV:
    """Cover the KEV module: hit/miss, catalog refresh, fallback, scoring."""

    _SAMPLE_CATALOG = {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-1234",
                "vendorProject": "Acme",
                "product": "WidgetServer",
                "vulnerabilityName": "Acme WidgetServer RCE",
                "dateAdded": "2024-02-01",
                "shortDescription": "Pre-auth RCE in Acme WidgetServer.",
                "requiredAction": "Apply vendor patch.",
                "dueDate": "2024-02-22",
                "knownRansomwareCampaignUse": "Known",
            },
            {
                "cveID": "CVE-2023-5678",
                "vendorProject": "Beta",
                "product": "Gizmo",
                "vulnerabilityName": "Beta Gizmo auth bypass",
                "dateAdded": "2023-12-15",
                "requiredAction": "Apply patch.",
                "dueDate": "2024-01-05",
                "knownRansomwareCampaignUse": "Unknown",
            },
        ],
    }

    def test_kev_hit(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        """A CVE present in the catalog returns its full entry dict."""
        cache_file = tmp_path / "cisa_kev.json"
        cache_file.write_text(__import__("json").dumps(self._SAMPLE_CATALOG))
        monkeypatch.setattr(kev, "CACHE_FILE", str(cache_file))
        entry = kev.get_kev_entry("CVE-2024-1234")
        assert entry is not None
        assert entry["vendorProject"] == "Acme"
        assert entry["product"] == "WidgetServer"
        assert entry["knownRansomwareCampaignUse"] == "Known"

    def test_kev_miss(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        """A CVE not in the catalog returns None."""
        cache_file = tmp_path / "cisa_kev.json"
        cache_file.write_text(__import__("json").dumps(self._SAMPLE_CATALOG))
        monkeypatch.setattr(kev, "CACHE_FILE", str(cache_file))
        assert kev.get_kev_entry("CVE-9999-0000") is None

    @responses.activate
    def test_kev_catalog_refresh_on_stale_cache(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        """A cache file >24 h old triggers a redownload."""
        import json as _json
        import os as _os
        import time as _time

        cache_file = tmp_path / "cisa_kev.json"
        # Write a stale cache (old content) then age the file.
        cache_file.write_text(_json.dumps({"vulnerabilities": []}))
        old_time = _time.time() - 25 * 3600
        _os.utime(str(cache_file), (old_time, old_time))

        monkeypatch.setattr(kev, "CACHE_FILE", str(cache_file))

        responses.add(
            responses.GET,
            kev.CATALOG_URL,
            json=self._SAMPLE_CATALOG,
            status=200,
        )
        entry = kev.get_kev_entry("CVE-2024-1234")
        assert entry is not None
        assert entry["vendorProject"] == "Acme"
        # Cache file should have been rewritten with the fresh catalog.
        reread = _json.loads(cache_file.read_text())
        assert any(
            v.get("cveID") == "CVE-2024-1234"
            for v in reread.get("vulnerabilities", [])
        )

    @responses.activate
    def test_kev_catalog_falls_back_to_local_on_network_error(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        """RequestException during refresh + cache present → use cached copy."""
        import json as _json
        import os as _os
        import time as _time

        cache_file = tmp_path / "cisa_kev.json"
        cache_file.write_text(_json.dumps(self._SAMPLE_CATALOG))
        # Make it stale to force the refresh path.
        old_time = _time.time() - 25 * 3600
        _os.utime(str(cache_file), (old_time, old_time))
        monkeypatch.setattr(kev, "CACHE_FILE", str(cache_file))

        responses.add(
            responses.GET,
            kev.CATALOG_URL,
            body=requests.exceptions.ConnectionError("kaboom"),
        )

        entry = kev.get_kev_entry("CVE-2024-1234")
        assert entry is not None
        assert entry["vendorProject"] == "Acme"

    def test_kev_load_catalog_returns_set(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        """load_catalog returns a set of CVE IDs."""
        import json as _json

        cache_file = tmp_path / "cisa_kev.json"
        cache_file.write_text(_json.dumps(self._SAMPLE_CATALOG))
        monkeypatch.setattr(kev, "CACHE_FILE", str(cache_file))

        catalog = kev.load_catalog()
        assert isinstance(catalog, set)
        assert "CVE-2024-1234" in catalog
        assert "CVE-2023-5678" in catalog
        assert "CVE-9999-9999" not in catalog

    def test_calculate_kev_score_hit(self) -> None:
        """Any KEV entry → 100 (known-exploited is the strongest signal)."""
        assert score_mod.calculate_kev_score({"cveID": "CVE-2024-1234"}) == 100

    def test_calculate_kev_score_none(self) -> None:
        """None / empty payload → 0."""
        assert score_mod.calculate_kev_score(None) == 0
        assert score_mod.calculate_kev_score({}) == 0

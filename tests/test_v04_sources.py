"""Tests for v0.4 batch-A sources: Feodo Tracker, SSLBL, crt.sh."""

import json
import time
from typing import Any

import responses

from ioc_tool.core import score
from ioc_tool.modules import crtsh, feodo, sslbl

# ---------------------------------------------------------------------------
# Feodo Tracker
# ---------------------------------------------------------------------------


_FEODO_SAMPLE = [
    {
        "ip_address": "1.2.3.4",
        "port": 443,
        "status": "online",
        "malware": "Emotet",
        "first_seen": "2026-01-15",
        "last_online": "2026-05-14",
        "as_number": 12345,
        "as_name": "EXAMPLE-AS",
        "country": "RU",
    },
    {
        "ip_address": "9.9.9.9",
        "port": 80,
        "status": "offline_24h",
        "malware": "TrickBot",
    },
]


def test_feodo_returns_none_for_unlisted_ip(monkeypatch, tmp_path):
    cache = tmp_path / "feodo.json"
    cache.write_text(json.dumps(_FEODO_SAMPLE))
    monkeypatch.setattr(feodo, "CACHE_FILE", str(cache))
    assert feodo.enrich_ip("8.8.8.8") is None


def test_feodo_returns_entry_for_listed_ip(monkeypatch, tmp_path):
    cache = tmp_path / "feodo.json"
    cache.write_text(json.dumps(_FEODO_SAMPLE))
    monkeypatch.setattr(feodo, "CACHE_FILE", str(cache))
    result = feodo.enrich_ip("1.2.3.4")
    assert result is not None
    assert result["malware"] == "Emotet"
    assert result["status"] == "online"
    assert result["country"] == "RU"


def test_feodo_cache_stale_when_old(monkeypatch, tmp_path):
    cache = tmp_path / "feodo.json"
    cache.write_text(json.dumps(_FEODO_SAMPLE))
    old_mtime = time.time() - (48 * 3600)
    import os
    os.utime(cache, (old_mtime, old_mtime))
    monkeypatch.setattr(feodo, "CACHE_FILE", str(cache))
    monkeypatch.setenv("FEODO_LIST_TTL_HOURS", "24")
    assert feodo._cache_is_stale() is True


@responses.activate
def test_feodo_refresh_blocklist_writes_cache(monkeypatch, tmp_path):
    cache = tmp_path / "feodo.json"
    monkeypatch.setattr(feodo, "CACHE_FILE", str(cache))
    responses.add(
        responses.GET, feodo.FEED_URL, json=_FEODO_SAMPLE, status=200,
    )
    assert feodo.refresh_blocklist() is True
    saved = json.loads(cache.read_text())
    assert saved[0]["ip_address"] == "1.2.3.4"


@responses.activate
def test_feodo_refresh_handles_500(monkeypatch, tmp_path):
    monkeypatch.setattr(feodo, "CACHE_FILE", str(tmp_path / "feodo.json"))
    responses.add(responses.GET, feodo.FEED_URL, status=500)
    assert feodo.refresh_blocklist() is False


def test_feodo_score_online_vs_offline():
    assert score.calculate_feodo_score(None) == 0
    assert score.calculate_feodo_score({"status": "online"}) == 95
    assert score.calculate_feodo_score({"status": "offline_24h"}) == 70


# ---------------------------------------------------------------------------
# SSLBL
# ---------------------------------------------------------------------------


_SSLBL_SAMPLE = [
    {
        "SHA1": "AABB" + "0" * 36,  # 40-char placeholder
        "Listingdate": "2026-04-01",
        "Listingreason": "CobaltStrike",
        "DstIP": "5.6.7.8",
        "DstPort": 443,
    },
]


def test_sslbl_short_hash_short_circuits():
    """MD5 (32) and SHA-256 (64) inputs never make a network call."""
    assert sslbl.enrich_hash("d41d8cd98f00b204e9800998ecf8427e") is None  # MD5
    assert sslbl.enrich_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") is None  # SHA-256


def test_sslbl_hits_known_sha1(monkeypatch, tmp_path):
    cache = tmp_path / "sslbl.json"
    cache.write_text(json.dumps(_SSLBL_SAMPLE))
    monkeypatch.setattr(sslbl, "CACHE_FILE", str(cache))
    result = sslbl.enrich_hash("AABB" + "0" * 36)
    assert result is not None
    assert result["malware"] == "CobaltStrike"
    assert result["dst_ip"] == "5.6.7.8"


def test_sslbl_misses_unlisted_sha1(monkeypatch, tmp_path):
    cache = tmp_path / "sslbl.json"
    cache.write_text(json.dumps(_SSLBL_SAMPLE))
    monkeypatch.setattr(sslbl, "CACHE_FILE", str(cache))
    assert sslbl.enrich_hash("CCDD" + "0" * 36) is None


def test_sslbl_score_hit_is_95():
    assert score.calculate_sslbl_score(None) == 0
    assert score.calculate_sslbl_score({"sha1": "x"}) == 95


# ---------------------------------------------------------------------------
# crt.sh
# ---------------------------------------------------------------------------


def _crtsh_payload(count: int = 3) -> list[dict[str, Any]]:
    return [
        {
            "name_value": f"a{i}.example.com\nb{i}.example.com",
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "not_before": f"2026-04-{(i % 28) + 1:02d}T00:00:00",
            "common_name": f"a{i}.example.com",
        }
        for i in range(count)
    ]


@responses.activate
def test_crtsh_returns_none_on_empty():
    responses.add(responses.GET, crtsh.BASE_URL, json=[], status=200)
    assert crtsh.enrich_domain("example.com") is None


@responses.activate
def test_crtsh_returns_summary_on_hit():
    responses.add(responses.GET, crtsh.BASE_URL, json=_crtsh_payload(5), status=200)
    result = crtsh.enrich_domain("example.com")
    assert result is not None
    assert result["total"] == 5
    # Each entry contributes 2 subdomains, so we have up to 10 unique values.
    assert result["subdomain_count"] > 0
    assert any("a0.example.com" in s for s in result["unique_subdomains"])


@responses.activate
def test_crtsh_handles_500():
    responses.add(responses.GET, crtsh.BASE_URL, status=500)
    assert crtsh.enrich_domain("example.com") is None


@responses.activate
def test_crtsh_handles_malformed_json():
    responses.add(responses.GET, crtsh.BASE_URL, body="not json", status=200)
    assert crtsh.enrich_domain("example.com") is None


def test_crtsh_score_thresholds():
    assert score.calculate_crtsh_score(None) == 0
    assert score.calculate_crtsh_score({"total": 50}) == 0
    assert score.calculate_crtsh_score({"total": 200}) == 15
    assert score.calculate_crtsh_score({"total": 2000}) == 30

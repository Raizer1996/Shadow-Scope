"""Tests for the bulk enrichment fan-out (enrich_many) and Tor cache TTL."""

import os
import time

import pytest

from ioc_tool.core import enrich
from ioc_tool.modules import tor as tor_mod

# ---------------------------------------------------------------------------
# Bulk fan-out
# ---------------------------------------------------------------------------


@pytest.fixture
def _isolated_db(monkeypatch, tmp_path):
    """Repoint the SQLite cache at a per-test file."""
    from ioc_tool.core import database as _db
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "ioc.db"))
    _db.init_db()
    return _db


def _stub_all_network(monkeypatch):
    """Force every source to return None — same stub used in test_smoke."""
    from ioc_tool.modules import (
        abuseipdb,
        crtsh,
        feodo,
        greynoise,
        ip_quality_score,
        ipinfo_mod,
        malwarebazaar,
        otx,
        pulsedive,
        shodan_mod,
        sslbl,
        threatfox,
        urlhaus,
        urlscan,
        vt,
        whois_mod,
    )
    monkeypatch.setattr(abuseipdb, "enrich_ip", lambda v: None)
    monkeypatch.setattr(crtsh, "enrich_domain", lambda v: None)
    monkeypatch.setattr(feodo, "enrich_ip", lambda v: None)
    monkeypatch.setattr(greynoise, "enrich_ip", lambda v: None)
    monkeypatch.setattr(ipinfo_mod, "enrich_ip", lambda v: None)
    monkeypatch.setattr(ip_quality_score, "enrich_ip", lambda v: None)
    monkeypatch.setattr(malwarebazaar, "enrich_hash", lambda v: None)
    monkeypatch.setattr(otx, "enrich", lambda v, t: None)
    monkeypatch.setattr(pulsedive, "enrich", lambda v, t: None)
    monkeypatch.setattr(shodan_mod, "host_search", lambda v: {"error": "stub"})
    monkeypatch.setattr(sslbl, "enrich_hash", lambda v: None)
    monkeypatch.setattr(threatfox, "enrich", lambda v: None)
    monkeypatch.setattr(urlhaus, "enrich_url", lambda v: None)
    monkeypatch.setattr(urlhaus, "enrich_host", lambda v: None)
    monkeypatch.setattr(urlscan, "enrich", lambda v, t: None)
    monkeypatch.setattr(vt, "enrich_ip", lambda v: None)
    monkeypatch.setattr(vt, "enrich_domain", lambda v: None)
    monkeypatch.setattr(vt, "enrich_url", lambda v: None)
    monkeypatch.setattr(vt, "enrich_hash", lambda v: None)
    monkeypatch.setattr(whois_mod, "get_whois_data", lambda v: None)
    monkeypatch.setattr(tor_mod, "is_tor_node", lambda v: False)


def test_enrich_many_returns_one_dict_per_ioc(monkeypatch, _isolated_db):
    _stub_all_network(monkeypatch)

    iocs = [("8.8.8.8", "ip"), ("1.1.1.1", "ip"), ("9.9.9.9", "ip")]
    results = enrich.enrich_many(iocs)

    assert len(results) == 3
    assert {r["ioc"] for r in results} == {"8.8.8.8", "1.1.1.1", "9.9.9.9"}
    for r in results:
        assert r["type"] == "ip"
        assert r["final_score"] == 0


def test_enrich_many_empty_input_returns_empty():
    assert enrich.enrich_many([]) == []


def test_enrich_many_drops_crashing_iocs(monkeypatch, _isolated_db):
    """A single IOC blowing up shouldn't take down the batch."""
    _stub_all_network(monkeypatch)

    # Make every parser call for the bad IOC type explode.
    original_normalize = enrich.parser.normalize_value
    def _normalize(value, ioc_type):
        if value == "BAD":
            raise RuntimeError("boom")
        return original_normalize(value, ioc_type)
    monkeypatch.setattr(enrich.parser, "normalize_value", _normalize)

    iocs = [("8.8.8.8", "ip"), ("BAD", "ip"), ("1.1.1.1", "ip")]
    results = enrich.enrich_many(iocs)
    assert {r["ioc"] for r in results} == {"8.8.8.8", "1.1.1.1"}


def test_enrich_many_async_is_awaitable(monkeypatch, _isolated_db):
    """The async function exists and returns the same shape as the sync wrapper."""
    import asyncio
    _stub_all_network(monkeypatch)

    iocs = [("8.8.8.8", "ip")]
    results = asyncio.run(enrich.enrich_many_async(iocs))
    assert len(results) == 1


def test_enrich_many_honours_no_cache(monkeypatch, _isolated_db):
    """no_cache propagates through to every IOC in the batch."""
    _stub_all_network(monkeypatch)

    fetcher_calls = []

    def _vt_stub(value):
        fetcher_calls.append(value)
        return None

    from ioc_tool.modules import vt
    monkeypatch.setattr(vt, "enrich_ip", _vt_stub)

    # Run twice — the second pass should still hit the stub if no_cache=True.
    enrich.enrich_many([("8.8.8.8", "ip")])
    enrich.enrich_many([("8.8.8.8", "ip")], no_cache=True)
    assert fetcher_calls.count("8.8.8.8") >= 2


# ---------------------------------------------------------------------------
# Tor list TTL
# ---------------------------------------------------------------------------


def test_tor_ttl_defaults_to_24h(monkeypatch):
    monkeypatch.delenv("TOR_LIST_TTL_HOURS", raising=False)
    assert tor_mod._ttl_seconds() == 24 * 3600


def test_tor_ttl_reads_env(monkeypatch):
    monkeypatch.setenv("TOR_LIST_TTL_HOURS", "168")
    assert tor_mod._ttl_seconds() == 168 * 3600


def test_tor_ttl_unparseable_falls_back(monkeypatch):
    monkeypatch.setenv("TOR_LIST_TTL_HOURS", "garbage")
    assert tor_mod._ttl_seconds() == 24 * 3600


def test_tor_cache_stale_when_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(tor_mod, "CACHE_FILE", str(tmp_path / "tor.txt"))
    assert tor_mod._cache_is_stale() is True


def test_tor_cache_fresh_when_recent(monkeypatch, tmp_path):
    cache = tmp_path / "tor.txt"
    cache.write_text("1.2.3.4\n")
    monkeypatch.setattr(tor_mod, "CACHE_FILE", str(cache))
    monkeypatch.setenv("TOR_LIST_TTL_HOURS", "24")
    assert tor_mod._cache_is_stale() is False


def test_tor_cache_stale_when_old(monkeypatch, tmp_path):
    cache = tmp_path / "tor.txt"
    cache.write_text("1.2.3.4\n")
    old_mtime = time.time() - (48 * 3600)  # 48 h old
    os.utime(cache, (old_mtime, old_mtime))
    monkeypatch.setattr(tor_mod, "CACHE_FILE", str(cache))
    monkeypatch.setenv("TOR_LIST_TTL_HOURS", "24")
    assert tor_mod._cache_is_stale() is True


def test_tor_is_tor_node_uses_cache(monkeypatch, tmp_path):
    """A populated cache + fresh mtime → no network call."""
    cache = tmp_path / "tor.txt"
    cache.write_text("9.9.9.9\n8.8.8.8\n")
    monkeypatch.setattr(tor_mod, "CACHE_FILE", str(cache))
    monkeypatch.setenv("TOR_LIST_TTL_HOURS", "168")

    calls = []
    monkeypatch.setattr(tor_mod, "update_tor_list", lambda: calls.append(1) or True)

    assert tor_mod.is_tor_node("9.9.9.9") is True
    assert tor_mod.is_tor_node("1.1.1.1") is False
    assert calls == []  # no refresh — cache is fresh

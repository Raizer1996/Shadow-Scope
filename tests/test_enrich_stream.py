"""Tests for :func:`ioc_tool.core.enrich.enrich_ioc_stream`.

The streaming variant yields the same total work as ``enrich_ioc_async``
but emits per-source ``module`` events as each task completes (instead of
returning one big dict after the slowest one). These tests confirm:

* The event sequence is ``meta`` → one ``module`` per non-None source →
  ``final``.
* The ``final`` event carries the same shape ``enrich_ioc_async`` does
  (so the dashboard reshape path is identical).
* Allowlisted IOCs short-circuit with ``meta`` + ``final`` only — no
  per-source tasks should run.

Every test monkeypatches the per-module enrichers so no real APIs are
hit, and uses an isolated SQLite cache via the ``_isolated_db`` fixture.
"""

from __future__ import annotations

import pytest

from ioc_tool.core import enrich
from ioc_tool.modules import (
    abstract_api,
    abuseipdb,
    censys,
    epss,
    feodo,
    greynoise,
    ip_quality_score,
    ipinfo_mod,
    kev,
    malwarebazaar,
    nvd,
    otx,
    pdns,
    pulsedive,
    rdns,
    shodan_mod,
    threatfox,
    urlhaus,
    urlscan,
    vt,
)
from ioc_tool.modules import tor as tor_mod


@pytest.fixture
def _isolated_db(monkeypatch, tmp_path):
    """Repoint the SQLite cache at a per-test file so tests don't share state."""
    from ioc_tool.core import database as _db
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "ioc.db"))
    _db.init_db()
    return _db


def _all_sources_quiet(monkeypatch):
    """Return None / safe stubs from every source the IP fan-out touches.

    Per-test overrides patch back over the specific sources we care about.
    """
    monkeypatch.setattr(abstract_api, "enrich_ip", lambda v: None)
    monkeypatch.setattr(abuseipdb, "enrich_ip", lambda v: None)
    monkeypatch.setattr(censys, "host_lookup", lambda v: {"error": "stub"})
    monkeypatch.setattr(epss, "enrich_cve", lambda v: None)
    monkeypatch.setattr(feodo, "enrich_ip", lambda v: None)
    monkeypatch.setattr(greynoise, "enrich_ip", lambda v: None)
    monkeypatch.setattr(ipinfo_mod, "enrich_ip", lambda v: None)
    monkeypatch.setattr(ip_quality_score, "enrich_ip", lambda v: None)
    monkeypatch.setattr(kev, "get_kev_entry", lambda v: None)
    monkeypatch.setattr(malwarebazaar, "enrich_hash", lambda v: None)
    monkeypatch.setattr(nvd, "enrich_cve", lambda v: None)
    monkeypatch.setattr(otx, "enrich", lambda v, t: None)
    monkeypatch.setattr(pdns, "enrich_ip", lambda v: {})
    monkeypatch.setattr(pulsedive, "enrich", lambda v, t: None)
    monkeypatch.setattr(rdns, "enrich_ip", lambda v: None)
    monkeypatch.setattr(shodan_mod, "host_search", lambda v: {"error": "stub"})
    monkeypatch.setattr(threatfox, "enrich", lambda v: None)
    monkeypatch.setattr(urlhaus, "enrich_url", lambda v: None)
    monkeypatch.setattr(urlhaus, "enrich_host", lambda v: None)
    monkeypatch.setattr(urlscan, "enrich", lambda v, t: None)
    monkeypatch.setattr(tor_mod, "is_tor_node", lambda v: False)
    monkeypatch.setattr(vt, "enrich_ip", lambda v: None)


async def _collect(agen):
    """Drain an async generator into a list. Helper for asyncio.run-style tests."""
    out = []
    async for ev in agen:
        out.append(ev)
    return out


def test_stream_emits_meta_then_modules_then_final(monkeypatch, _isolated_db):
    """Happy path: one source returns data, others quiet → meta, one module, final."""
    import asyncio

    _all_sources_quiet(monkeypatch)
    # Wire VT to return a real-looking payload so it surfaces as a `module` event
    # and contributes a score to the composite.
    monkeypatch.setattr(vt, "enrich_ip", lambda v: {
        "last_analysis_stats": {
            "malicious": 5, "harmless": 70, "suspicious": 0, "undetected": 25,
        },
    })

    events = asyncio.run(_collect(enrich.enrich_ioc_stream("9.9.9.9", "ip")))

    kinds = [e["event"] for e in events]
    assert kinds[0] == "meta"
    assert kinds[-1] == "final"
    # At least one module event (VT) and the rest are also `module` events.
    assert "module" in kinds
    module_names = [e["name"] for e in events if e["event"] == "module"]
    assert "VirusTotal" in module_names

    final = events[-1]
    assert final["result"]["ioc"] == "9.9.9.9"
    assert final["result"]["type"] == "ip"
    assert "VirusTotal" in final["result"]["modules"]
    # Composite score is computed from the per-source scores — at minimum,
    # the final shape must carry the field the dashboard reads.
    assert isinstance(final["result"]["final_score"], int)


def test_stream_short_circuits_on_allowlist(monkeypatch, _isolated_db):
    """Allowlisted IOC must not run any per-source task — just meta + final."""
    import asyncio

    from ioc_tool.core import allowlist
    monkeypatch.setattr(
        allowlist, "is_allowlisted",
        lambda v, t: {"source": "test", "rule": "rfc1918"},
    )
    # If the short-circuit fails, this would blow up because nothing else is
    # stubbed — that's the point: the absence of source calls proves the
    # allowlist path bypassed the fan-out entirely.

    events = asyncio.run(_collect(enrich.enrich_ioc_stream("10.0.0.1", "ip")))

    kinds = [e["event"] for e in events]
    assert kinds == ["meta", "final"]
    assert events[0]["allowlisted"] is True
    final = events[-1]
    assert final["result"]["allowlisted"] is True
    assert "Allowlist" in final["result"]["modules"]
    assert final["result"]["final_score"] == 0


def test_stream_meta_carries_pending_count(monkeypatch, _isolated_db):
    """The first `meta` event tells the UI how many tasks were scheduled.

    The dashboard uses this for the "landed/total" progress label — a
    missing or zero count would degrade the skeleton to an unbounded
    spinner instead of a bounded progress bar.
    """
    import asyncio

    _all_sources_quiet(monkeypatch)

    events = asyncio.run(_collect(enrich.enrich_ioc_stream("8.8.8.8", "ip")))
    meta = events[0]
    assert meta["event"] == "meta"
    assert meta["allowlisted"] is False
    assert isinstance(meta["pending"], int)
    assert meta["pending"] > 0

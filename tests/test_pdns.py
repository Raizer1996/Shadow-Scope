"""Passive DNS (PDNS) module tests.

Covers the Mnemonic-flavoured parsing path, the soft-fail empty-dict
convention, the IP-only type gate (the orchestrator decides this, but
we assert the public entry point gracefully refuses an empty IOC), and
a smoke test on the CLI block renderer.

Every test monkeypatches ``ioc_tool.core.http.get`` — we never hit the
real network. ``http.get`` returns a ``requests.Response``-ish object,
so the fakes here mirror that surface (``status_code``, ``json()``).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from ioc_tool.modules import pdns
from ioc_tool.ui import cli as cli_mod


class _FakeResp:
    """Minimal stand-in for ``requests.Response`` — only what the module reads."""

    def __init__(self, payload: Any, status_code: int = 200, raise_on_json: bool = False):
        self._payload = payload
        self.status_code = status_code
        self._raise_on_json = raise_on_json

    def json(self) -> Any:
        if self._raise_on_json:
            raise ValueError("not json")
        return self._payload


def _ms(year: int, month: int, day: int) -> int:
    return int(
        datetime(year, month, day, tzinfo=timezone.utc).timestamp() * 1000
    )


# ---------------------------------------------------------------------------
# Success path — full Mnemonic envelope parses cleanly
# ---------------------------------------------------------------------------


def test_pdns_parses_mnemonic_envelope(monkeypatch):
    """Two records → first/last span across both, record_count summed,
    top_rrnames ordered by frequency, source = 'mnemonic'."""
    payload = {
        "data": [
            {
                "query": "alpha.example.com",
                "answer": "203.0.113.5",
                "firstSeenTimestamp": _ms(2024, 3, 14),
                "lastSeenTimestamp":  _ms(2026, 5, 1),
                "count": 4,
            },
            {
                "query": "beta.example.com",
                "answer": "203.0.113.5",
                "firstSeenTimestamp": _ms(2024, 6, 1),
                "lastSeenTimestamp":  _ms(2026, 5, 15),
                "count": 8,
            },
        ],
    }
    monkeypatch.setattr(pdns.http, "get", lambda *a, **k: _FakeResp(payload))

    out = pdns.enrich_ip("203.0.113.5")
    assert out["source"] == "mnemonic"
    assert out["record_count"] == 12
    assert out["first_seen"].startswith("2024-03-14")
    assert out["last_seen"].startswith("2026-05-15")
    # beta has more counts → ordered first.
    assert out["top_rrnames"][0] == "beta.example.com"
    assert "alpha.example.com" in out["top_rrnames"]
    # age_days is a non-negative int (real elapsed time depends on today).
    assert isinstance(out["age_days"], int)
    assert out["age_days"] >= 0


def test_pdns_caps_top_rrnames_at_five(monkeypatch):
    payload = {
        "data": [
            {
                "query": f"name-{i}.example.com",
                "firstSeenTimestamp": _ms(2024, 3, 14) + i,
                "lastSeenTimestamp":  _ms(2026, 5, 1),
                "count": 10 - i,  # descending so order is deterministic
            }
            for i in range(8)
        ],
    }
    monkeypatch.setattr(pdns.http, "get", lambda *a, **k: _FakeResp(payload))
    out = pdns.enrich_ip("198.51.100.10")
    assert len(out["top_rrnames"]) == 5
    assert out["top_rrnames"][0] == "name-0.example.com"


def test_pdns_accepts_circl_legacy_field_names(monkeypatch):
    """``time_first`` / ``time_last`` (CIRCL-style epoch seconds → ms)
    fall through the same parser. We feed epoch-ms shaped as ints so the
    Mnemonic→CIRCL shim doesn't need to know the difference."""
    payload = {
        "data": [
            {
                "rrname": "host.example.com",
                "time_first": _ms(2025, 1, 1),
                "time_last":  _ms(2025, 12, 31),
                "count": 3,
            },
        ],
    }
    monkeypatch.setattr(pdns.http, "get", lambda *a, **k: _FakeResp(payload))
    out = pdns.enrich_ip("203.0.113.99")
    assert out["first_seen"].startswith("2025-01-01")
    assert out["last_seen"].startswith("2025-12-31")
    assert out["top_rrnames"] == ["host.example.com"]


# ---------------------------------------------------------------------------
# Soft-fail paths — every error mode collapses to {}
# ---------------------------------------------------------------------------


def test_pdns_soft_fail_when_http_get_returns_none(monkeypatch):
    """Rate-limit refusal / network error → ``{}``."""
    calls: list[tuple] = []

    def fake_get(*args, **kwargs):
        calls.append((args, kwargs))
        return None

    monkeypatch.setattr(pdns.http, "get", fake_get)
    assert pdns.enrich_ip("203.0.113.5") == {}
    assert len(calls) == 1  # we did try once


def test_pdns_soft_fail_on_non_200(monkeypatch):
    monkeypatch.setattr(pdns.http, "get", lambda *a, **k: _FakeResp({}, status_code=503))
    assert pdns.enrich_ip("203.0.113.5") == {}


def test_pdns_soft_fail_on_invalid_json(monkeypatch):
    monkeypatch.setattr(
        pdns.http, "get",
        lambda *a, **k: _FakeResp(None, status_code=200, raise_on_json=True),
    )
    assert pdns.enrich_ip("203.0.113.5") == {}


def test_pdns_soft_fail_on_empty_data_array(monkeypatch):
    monkeypatch.setattr(pdns.http, "get", lambda *a, **k: _FakeResp({"data": []}))
    assert pdns.enrich_ip("203.0.113.5") == {}


# ---------------------------------------------------------------------------
# IOC type gate — the orchestrator only calls enrich_ip on IP IOCs, but
# the module itself defends an empty input (analogous to rdns.enrich_ip).
# ---------------------------------------------------------------------------


def test_pdns_empty_ip_short_circuits_without_http_call(monkeypatch):
    """Empty IOC: never touch the network."""
    calls: list[Any] = []

    def fake_get(*args, **kwargs):
        calls.append((args, kwargs))
        return _FakeResp({"data": []})

    monkeypatch.setattr(pdns.http, "get", fake_get)
    assert pdns.enrich_ip("") == {}
    assert calls == []


def test_pdns_orchestrator_type_gate_for_domain():
    """Confirm enrich.enrich_ioc never wires PDNS for non-IP types.

    We scan the orchestrator source for the PDNS task definition and
    assert it is guarded by an ``ioc_type == 'ip'`` check — the test is
    a guard-rail against an accidental future de-restriction.
    """
    import inspect

    from ioc_tool.core import enrich as enrich_mod
    src = inspect.getsource(enrich_mod)
    # The PDNS section must live inside an 'ip'-typed block.
    pdns_idx = src.find("'pdns'")
    assert pdns_idx > 0, "pdns task not found in enrich.py"
    # The closest preceding `if ioc_type ==` must select 'ip'.
    prefix = src[:pdns_idx]
    last_guard = prefix.rfind("if ioc_type ==")
    assert last_guard > 0, "no type-gate before PDNS task"
    guard_line = src[last_guard:src.find("\n", last_guard)]
    assert "'ip'" in guard_line


# ---------------------------------------------------------------------------
# age_days — bounds + freshness
# ---------------------------------------------------------------------------


def test_pdns_age_days_is_zero_or_positive(monkeypatch):
    """A first-seen 5 days ago should yield age_days >= 4 (rounding-safe)."""
    five_days_ago = datetime.now(tz=timezone.utc) - timedelta(days=5)
    fs_ms = int(five_days_ago.timestamp() * 1000)
    payload = {
        "data": [
            {
                "query": "fresh.example.com",
                "firstSeenTimestamp": fs_ms,
                "lastSeenTimestamp":  fs_ms + 1000,
                "count": 1,
            },
        ],
    }
    monkeypatch.setattr(pdns.http, "get", lambda *a, **k: _FakeResp(payload))
    out = pdns.enrich_ip("203.0.113.5")
    assert 4 <= out["age_days"] <= 6


# ---------------------------------------------------------------------------
# CLI block renderer smoke test — string contents are load-bearing
# (the user contract is "first <date> last <date> (Nd, M records)").
# ---------------------------------------------------------------------------


def test_cli_pdns_renderer_contains_key_fields():
    rendered = cli_mod._format_pdns_details({
        "first_seen": "2024-03-14T12:00:00Z",
        "last_seen":  "2026-05-15T08:42:00Z",
        "age_days":   794,
        "record_count": 12,
        "top_rrnames": ["example.com", "other.example.com"],
        "source": "mnemonic",
    })
    assert "first 2024-03-14" in rendered
    assert "last 2026-05-15" in rendered
    assert "794 d" in rendered
    assert "12 records" in rendered
    assert "rrnames:" in rendered
    assert "example.com" in rendered


def test_cli_pdns_renderer_empty_dict_returns_empty_string():
    assert cli_mod._format_pdns_details({}) == ""


# ---------------------------------------------------------------------------
# Rate-limit bucket registration — defends against the entry being lost
# in a rebase against the parallel HTTP-migration / webhook agents.
# ---------------------------------------------------------------------------


def test_pdns_rate_limit_bucket_registered():
    from ioc_tool.core import ratelimit

    assert "pdns" in ratelimit._DEFAULT_BUCKETS
    capacity, period = ratelimit._DEFAULT_BUCKETS["pdns"]
    assert capacity == 5
    assert period == 60


# ---------------------------------------------------------------------------
# Soft-fail cache persistence — the empty ``{}`` MUST land in the cache
# so a quiet IP doesn't refetch on every enrichment.
# ---------------------------------------------------------------------------


def test_pdns_empty_result_is_persisted_to_cache(monkeypatch, tmp_path):
    """When PDNS returns ``{}`` (its documented soft-fail), the orchestrator
    must persist a cache row anyway — otherwise a low-signal IP refetches
    on every call and burns the tight Mnemonic free-tier quota.

    Previously PDNS shared :func:`_shodan_filter`, which discards falsy
    dicts. The dedicated :func:`_pdns_filter` keeps ``{}`` while still
    rejecting ``{"error": ...}`` payloads.
    """
    from ioc_tool.core import database, enrich

    # Repoint cache at a per-test SQLite file.
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "ioc.db"))
    database.init_db()

    # Stub all other sources to None so we can isolate the PDNS row.
    from tests.test_smoke import _stub_all_network
    _stub_all_network(monkeypatch)

    # PDNS returns its documented soft-fail.
    monkeypatch.setattr(pdns, "enrich_ip", lambda v: {})

    result = enrich.enrich_ioc("203.0.113.99", "ip")

    # The orchestrator surfaces the empty PDNS row (info-only).
    assert "PDNS" in result["modules"]
    assert result["modules"]["PDNS"]["data"] == {}

    # And — the critical assertion — the row IS in the cache.
    ioc_id = database.add_or_update_ioc("203.0.113.99", "ip")
    cached = database.get_latest_enrichment(ioc_id, "pdns")
    assert cached is not None, "PDNS soft-fail must be cached, not refetched"


def test_pdns_error_dict_not_persisted(monkeypatch, tmp_path):
    """An explicit ``{"error": ...}`` from the upstream is NOT cached —
    we don't want to pin a transient outage into the cache for hours.
    """
    from ioc_tool.core import database, enrich

    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "ioc.db"))
    database.init_db()

    from tests.test_smoke import _stub_all_network
    _stub_all_network(monkeypatch)

    monkeypatch.setattr(pdns, "enrich_ip", lambda v: {"error": "upstream 503"})

    enrich.enrich_ioc("203.0.113.99", "ip")

    ioc_id = database.add_or_update_ioc("203.0.113.99", "ip")
    cached = database.get_latest_enrichment(ioc_id, "pdns")
    assert cached is None, "error-dict payloads must not pollute the cache"


def test_pdns_filter_unit():
    """Direct unit on the filter: empty dict kept, error rejected, None rejected."""
    from ioc_tool.core.enrich import _pdns_filter

    assert _pdns_filter({}) == {}
    assert _pdns_filter({"first_seen": "2024-01-01T00:00:00Z"}) == {
        "first_seen": "2024-01-01T00:00:00Z"
    }
    assert _pdns_filter({"error": "boom"}) is None
    assert _pdns_filter(None) is None
    # Non-dicts (defensive) collapse to None.
    assert _pdns_filter("not a dict") is None  # type: ignore[arg-type]

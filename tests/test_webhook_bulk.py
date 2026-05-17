"""Tests for the parallel webhook fan-out and handler-time env resolution.

Targets the contract established by PR ``fix-cli-webhook-docs``:

* stdout (JSON / CSV / STIX / table) is emitted BEFORE any webhook POST
  begins — receivers under back-pressure can't stall downstream readers.
* webhook POSTs run in parallel via ``ThreadPoolExecutor``; the shared
  per-source ``webhook`` token bucket is the only governor.
* an individual POST failure must NOT abort the loop or affect exit code.
* ``SHADOWSCOPE_WEBHOOK_URL`` is resolved at handler time (NOT parser-
  construction time), so wrapping scripts can set it after import.
* ``--webhook-concurrent=1`` falls back to a deterministic serial path.

Network is fully stubbed via ``_stub_all_network`` from ``test_bulk``;
no real HTTP traffic is ever issued.
"""

from __future__ import annotations

import argparse
import threading
import time

import pytest

from ioc_tool.core import http as core_http
from ioc_tool.ui import cli
from tests.test_bulk import _stub_all_network as _stub_legacy_network


def _stub_all_network(monkeypatch):
    """Stub every enrichment source — superset of ``test_bulk._stub_all_network``.

    The bulk-webhook tests need enrichment to finish in milliseconds so
    the wall-clock concurrency check is meaningful. The base helper from
    ``test_bulk`` only stubs the original 17 modules; later additions
    (rDNS, NVD/EPSS/KEV, PDNS, ASN, Censys, sandbox SDKs) still issue
    real network or DNS calls, blowing the test budget by orders of
    magnitude. We re-stub them all here.
    """
    _stub_legacy_network(monkeypatch)
    from ioc_tool.modules import (
        asn,
        censys,
        epss,
        kev,
        nvd,
        pdns,
        rdns,
    )
    monkeypatch.setattr(asn, "enrich", lambda v: None, raising=False)
    monkeypatch.setattr(censys, "host_lookup", lambda v: {}, raising=False)
    monkeypatch.setattr(epss, "enrich_cve", lambda v: None, raising=False)
    monkeypatch.setattr(kev, "get_kev_entry", lambda v: None, raising=False)
    monkeypatch.setattr(nvd, "enrich_cve", lambda v: None, raising=False)
    monkeypatch.setattr(pdns, "enrich_ip", lambda v: {}, raising=False)
    monkeypatch.setattr(rdns, "enrich_ip", lambda v: None, raising=False)

    # Belt + braces: any unstubbed module would still hit the network
    # via core/http. Force every GET to return None so latency is bounded.
    monkeypatch.setattr(core_http, "get", lambda *a, **k: None, raising=False)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def _isolated_db(monkeypatch, tmp_path):
    """Point the SQLite cache at a per-test file so tests stay independent."""
    from ioc_tool.core import database as _db
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "ioc.db"))
    _db.init_db()
    return _db


def _make_enrich_ns(**overrides) -> argparse.Namespace:
    """Build the argparse Namespace ``handle_enrich`` expects."""
    base = dict(
        ioc=None,
        file=None,
        text=None,
        json=True,
        csv=False,
        stix=False,
        md=False,
        webhook=None,
        webhook_concurrent=8,
        defang=False,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def _write_ioc_file(tmp_path, values: list[str]) -> str:
    path = tmp_path / "iocs.txt"
    path.write_text("\n".join(values) + "\n")
    return str(path)


# ---------------------------------------------------------------------------
# Concurrency — 10 POSTs should overlap, not serialize end-to-end
# ---------------------------------------------------------------------------


def test_webhook_bulk_parallel_faster_than_serial(
    monkeypatch, _isolated_db, tmp_path, capsys
):
    """Concurrent POSTs must finish faster than a strict serial dispatch.

    We measure both modes back-to-back with the same per-call sleep and
    require concurrent < serial / 2 (so an off-by-one or accidental
    serialisation regression shows up cleanly).
    """
    _stub_all_network(monkeypatch)

    per_call_delay = 0.05  # 50ms

    def _slow_post_webhook(url, payload, **_):
        time.sleep(per_call_delay)
        return True

    monkeypatch.setattr(core_http, "post_webhook", _slow_post_webhook)

    ioc_values = [f"8.8.8.{i}" for i in range(10)]
    ioc_file = _write_ioc_file(tmp_path, ioc_values)

    # Serial baseline.
    ns_serial = _make_enrich_ns(
        file=ioc_file,
        webhook="https://siem.test/hook",
        webhook_concurrent=1,
    )
    start = time.perf_counter()
    cli.handle_enrich(ns_serial)
    serial_elapsed = time.perf_counter() - start

    # Concurrent run (default pool = 8).
    ns_par = _make_enrich_ns(
        file=ioc_file,
        webhook="https://siem.test/hook",
        webhook_concurrent=8,
    )
    start = time.perf_counter()
    cli.handle_enrich(ns_par)
    par_elapsed = time.perf_counter() - start

    # Both should have posted all 10 IOCs.
    captured = capsys.readouterr()
    assert "webhook: 10 posted, 0 failed" in captured.err

    # Concurrent must be at most half of serial — a generous bound that
    # still catches accidental serialisation.
    assert par_elapsed < serial_elapsed / 2, (
        f"webhook fan-out wasn't parallel: serial={serial_elapsed:.3f}s "
        f"concurrent={par_elapsed:.3f}s"
    )


# ---------------------------------------------------------------------------
# Ordering — stdout MUST land before POSTs complete
# ---------------------------------------------------------------------------


def test_webhook_bulk_stdout_emitted_before_posts(
    monkeypatch, _isolated_db, tmp_path
):
    """Receiver back-pressure must NOT stall the JSON payload.

    Strategy: replace ``sys.stdout`` with a wrapper that timestamps its
    first write, then stamp the first webhook POST with another
    timestamp. The stdout timestamp must precede the POST timestamp.
    """
    import io
    import sys as _sys

    _stub_all_network(monkeypatch)

    # Use a wall-clock-friendly per-POST delay so the difference is
    # measurable even on slow CI.
    per_call_delay = 0.05

    timeline: dict[str, float | None] = {
        "stdout_first_write": None,
        "post_first_call": None,
    }
    timeline_lock = threading.Lock()
    real_stdout = _sys.stdout

    class _TimestampedStdout(io.TextIOBase):
        def write(self, s: str) -> int:
            with timeline_lock:
                if timeline["stdout_first_write"] is None and s.strip():
                    timeline["stdout_first_write"] = time.perf_counter()
            return real_stdout.write(s)

        def flush(self) -> None:
            real_stdout.flush()

    monkeypatch.setattr(_sys, "stdout", _TimestampedStdout())

    def _timed_post_webhook(url, payload, **_):
        with timeline_lock:
            if timeline["post_first_call"] is None:
                timeline["post_first_call"] = time.perf_counter()
        time.sleep(per_call_delay)
        return True

    monkeypatch.setattr(core_http, "post_webhook", _timed_post_webhook)

    ioc_file = _write_ioc_file(tmp_path, ["8.8.8.8", "1.1.1.1", "9.9.9.9"])
    ns = _make_enrich_ns(file=ioc_file, webhook="https://siem.test/hook")

    cli.handle_enrich(ns)

    assert timeline["stdout_first_write"] is not None, "stdout never written"
    assert timeline["post_first_call"] is not None, "webhook never called"
    assert timeline["stdout_first_write"] < timeline["post_first_call"], (
        "First webhook POST began before stdout was written — "
        "ordering invariant violated."
    )


# ---------------------------------------------------------------------------
# Soft-fail — one POST failing must NOT drop the others or exit non-zero
# ---------------------------------------------------------------------------


def test_webhook_bulk_one_failure_does_not_drop_others(
    monkeypatch, _isolated_db, tmp_path, capsys
):
    _stub_all_network(monkeypatch)

    calls: list[tuple[str, str]] = []
    calls_lock = threading.Lock()

    def _flaky_post_webhook(url, payload, **_):
        ioc_value = payload.get("ioc")
        with calls_lock:
            calls.append((url, ioc_value))
        # Fail exactly one IOC; everyone else succeeds.
        return ioc_value != "1.1.1.1"

    monkeypatch.setattr(core_http, "post_webhook", _flaky_post_webhook)

    ioc_values = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "4.4.4.4"]
    ioc_file = _write_ioc_file(tmp_path, ioc_values)
    ns = _make_enrich_ns(file=ioc_file, webhook="https://siem.test/hook")

    # Must not raise — soft-fail semantics.
    cli.handle_enrich(ns)

    # All 4 attempts happened despite the one failure.
    assert sorted(v for _, v in calls) == sorted(ioc_values)

    err = capsys.readouterr().err
    # Per-failure warning for the dropped one only.
    assert "webhook post failed for 1.1.1.1" in err
    # Summary tally reflects 3 posted / 1 failed.
    assert "webhook: 3 posted, 1 failed" in err


# ---------------------------------------------------------------------------
# Env-only path — flag absent + env set → POST happens
# ---------------------------------------------------------------------------


def test_webhook_bulk_env_url_resolved_at_handler_time(
    monkeypatch, _isolated_db, capsys
):
    """No ``--webhook`` flag, but ``SHADOWSCOPE_WEBHOOK_URL`` is set.

    Critically, the env mutation happens AFTER ``cli`` was imported, so
    the legacy ``default=os.getenv(...)`` snapshot pattern would miss it.
    The handler-time resolution must catch this case.
    """
    _stub_all_network(monkeypatch)
    monkeypatch.setenv("SHADOWSCOPE_WEBHOOK_URL", "https://env.test/hook")

    seen: list[str] = []

    def _capture(url, payload, **_):
        seen.append(url)
        return True

    monkeypatch.setattr(core_http, "post_webhook", _capture)

    # webhook=None on the namespace mirrors "flag not passed".
    ns = _make_enrich_ns(ioc="8.8.8.8", webhook=None)
    cli.handle_enrich(ns)

    assert seen == ["https://env.test/hook"], (
        "Env var was set but no POST happened — handler-time resolution "
        "regression."
    )


# ---------------------------------------------------------------------------
# Flag wins over env when both are present
# ---------------------------------------------------------------------------


def test_webhook_bulk_flag_overrides_env(monkeypatch, _isolated_db, capsys):
    _stub_all_network(monkeypatch)
    monkeypatch.setenv("SHADOWSCOPE_WEBHOOK_URL", "https://env.test/hook")

    seen: list[str] = []

    def _capture(url, payload, **_):
        seen.append(url)
        return True

    monkeypatch.setattr(core_http, "post_webhook", _capture)

    ns = _make_enrich_ns(ioc="8.8.8.8", webhook="https://flag.test/hook")
    cli.handle_enrich(ns)

    # Explicit flag wins, env is ignored.
    assert seen == ["https://flag.test/hook"]


# ---------------------------------------------------------------------------
# --webhook-concurrent=1 → no parallelism
# ---------------------------------------------------------------------------


def test_webhook_bulk_concurrent_one_runs_serial(
    monkeypatch, _isolated_db, tmp_path, capsys
):
    """``--webhook-concurrent=1`` forces serial dispatch — no overlap.

    We detect "no overlap" by counting how many calls were in flight at
    the same time. With concurrency=1, that count must never exceed 1.
    """
    _stub_all_network(monkeypatch)

    in_flight = 0
    max_in_flight = 0
    lock = threading.Lock()

    def _tracking_post_webhook(url, payload, **_):
        nonlocal in_flight, max_in_flight
        with lock:
            in_flight += 1
            if in_flight > max_in_flight:
                max_in_flight = in_flight
        time.sleep(0.02)
        with lock:
            in_flight -= 1
        return True

    monkeypatch.setattr(core_http, "post_webhook", _tracking_post_webhook)

    ioc_values = [f"10.0.0.{i}" for i in range(5)]
    ioc_file = _write_ioc_file(tmp_path, ioc_values)
    ns = _make_enrich_ns(
        file=ioc_file,
        webhook="https://siem.test/hook",
        webhook_concurrent=1,
    )
    cli.handle_enrich(ns)

    assert max_in_flight == 1, (
        f"webhook_concurrent=1 produced {max_in_flight} overlapping calls — "
        "serial fallback is broken."
    )


# ---------------------------------------------------------------------------
# --webhook-concurrent out-of-range clamping
# ---------------------------------------------------------------------------


def test_webhook_bulk_concurrent_out_of_range_clamped(
    monkeypatch, _isolated_db, tmp_path
):
    """Negative / huge values are clamped to [1, min(32, n_results)]."""
    _stub_all_network(monkeypatch)
    monkeypatch.setattr(core_http, "post_webhook", lambda *a, **k: True)

    # Negative → clamped to 1 (we just want to assert the call doesn't
    # raise and the helper resolves a sane workforce size).
    ioc_file = _write_ioc_file(tmp_path, ["8.8.8.8", "1.1.1.1"])
    ns = _make_enrich_ns(
        file=ioc_file,
        webhook="https://siem.test/hook",
        webhook_concurrent=-5,
    )
    cli.handle_enrich(ns)  # must not raise

    ns = _make_enrich_ns(
        file=ioc_file,
        webhook="https://siem.test/hook",
        webhook_concurrent=9999,
    )
    cli.handle_enrich(ns)  # must not raise

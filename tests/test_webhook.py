"""Tests for the ``--webhook=URL`` flag on ``shadowscope enrich``.

The flag POSTs each enrichment dict as JSON to an external receiver
(SIEM / ticketing / IR pager). It must:

* be wired into the argparse parser (with an env-var fallback)
* call the shared ``ioc_tool.core.http.post_webhook`` helper once per IOC
* soft-fail — receiver errors must NOT crash the CLI or affect IOC output
* keep stdout pristine so JSON / CSV pipelines stay parse-clean

The tests stub the network layer (via ``_stub_all_network`` from
``tests/test_bulk.py``) and monkeypatch ``http.post_webhook`` to capture
the payloads. They never hit a real HTTP endpoint.
"""

from __future__ import annotations

import argparse

import pytest

from ioc_tool.core import http as core_http
from ioc_tool.ui import cli
from tests.test_bulk import _stub_all_network


@pytest.fixture
def _isolated_db(monkeypatch, tmp_path):
    """Point the SQLite cache at a per-test file so tests stay independent."""
    from ioc_tool.core import database as _db
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "ioc.db"))
    _db.init_db()
    return _db


# ---------------------------------------------------------------------------
# Argparse wiring
# ---------------------------------------------------------------------------


def test_cli_parser_accepts_enrich_webhook_flag():
    parser = cli.build_parser()
    args = parser.parse_args(['enrich', '8.8.8.8', '--webhook', 'https://example.test/hook'])
    assert args.command == 'enrich'
    assert args.webhook == 'https://example.test/hook'


def test_cli_parser_enrich_webhook_defaults_to_env(monkeypatch):
    monkeypatch.setenv('SHADOWSCOPE_WEBHOOK_URL', 'https://from-env.test/hook')
    # The default is evaluated at parser-construction time, so build a
    # fresh parser after the env mutation.
    parser = cli.build_parser()
    args = parser.parse_args(['enrich', '8.8.8.8'])
    assert args.webhook == 'https://from-env.test/hook'


def test_cli_parser_enrich_webhook_none_when_unset(monkeypatch):
    monkeypatch.delenv('SHADOWSCOPE_WEBHOOK_URL', raising=False)
    parser = cli.build_parser()
    args = parser.parse_args(['enrich', '8.8.8.8'])
    assert args.webhook is None


# ---------------------------------------------------------------------------
# Single-IOC POST path
# ---------------------------------------------------------------------------


def _make_enrich_ns(**overrides) -> argparse.Namespace:
    """Build the argparse Namespace handle_enrich expects."""
    base = dict(
        ioc=None,
        file=None,
        text=None,
        json=True,           # machine-readable → keeps stdout clean
        csv=False,
        stix=False,
        md=False,
        webhook=None,
        defang=False,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def test_enrich_webhook_posts_full_enrichment_dict(monkeypatch, _isolated_db, capsys):
    """Happy path: enrichment completes → post_webhook called with the dict."""
    _stub_all_network(monkeypatch)

    calls: list[tuple[str, dict]] = []

    def _fake_post_webhook(url, payload, **kwargs):
        calls.append((url, payload))
        return True

    monkeypatch.setattr(core_http, "post_webhook", _fake_post_webhook)

    ns = _make_enrich_ns(ioc="8.8.8.8", webhook="https://siem.test/hook")
    cli.handle_enrich(ns)

    assert len(calls) == 1
    url, payload = calls[0]
    assert url == "https://siem.test/hook"
    # Payload must be the same dict we'd emit to stdout / JSON / STIX.
    assert payload["ioc"] == "8.8.8.8"
    assert payload["type"] == "ip"
    assert "final_score" in payload


def test_enrich_webhook_failure_does_not_crash_cli(monkeypatch, _isolated_db, capsys):
    """post_webhook returns False (e.g. 5xx) → stderr warning, exit 0."""
    _stub_all_network(monkeypatch)

    monkeypatch.setattr(core_http, "post_webhook", lambda url, payload, **_: False)

    ns = _make_enrich_ns(ioc="8.8.8.8", webhook="https://broken.test/hook")
    # Must not raise — the CLI is fire-and-forget on webhook errors.
    cli.handle_enrich(ns)

    captured = capsys.readouterr()
    # stdout still contains the JSON payload (unaffected by webhook failure).
    assert '"8.8.8.8"' in captured.out
    # Stderr carries the warning so analysts see what broke.
    assert "webhook post failed" in captured.err
    assert "8.8.8.8" in captured.err


def test_enrich_webhook_post_exception_is_swallowed(monkeypatch, _isolated_db, capsys):
    """A raising post_webhook (programmer error / library bug) must NOT crash."""
    _stub_all_network(monkeypatch)

    # Verify the helper itself swallows exceptions from the underlying post.
    def _raising_post(*args, **kwargs):
        raise RuntimeError("transport blew up")

    monkeypatch.setattr(core_http, "post", _raising_post)

    ns = _make_enrich_ns(ioc="8.8.8.8", webhook="https://broken.test/hook")
    cli.handle_enrich(ns)  # must not raise

    captured = capsys.readouterr()
    assert "webhook post failed" in captured.err
    assert '"8.8.8.8"' in captured.out


def test_enrich_without_webhook_does_not_post(monkeypatch, _isolated_db):
    """No --webhook / no env var → post_webhook is never called."""
    _stub_all_network(monkeypatch)

    calls: list[tuple[str, dict]] = []

    def _fake(url, payload, **kwargs):
        calls.append((url, payload))
        return True

    monkeypatch.setattr(core_http, "post_webhook", _fake)

    ns = _make_enrich_ns(ioc="8.8.8.8", webhook=None)
    cli.handle_enrich(ns)
    assert calls == []


# ---------------------------------------------------------------------------
# Bulk mode — one POST per IOC
# ---------------------------------------------------------------------------


def test_enrich_webhook_bulk_mode_one_post_per_ioc(monkeypatch, _isolated_db, tmp_path):
    """3 IOCs in via -f → 3 webhook POSTs, one payload each."""
    _stub_all_network(monkeypatch)

    calls: list[tuple[str, dict]] = []

    def _fake(url, payload, **kwargs):
        calls.append((url, payload))
        return True

    monkeypatch.setattr(core_http, "post_webhook", _fake)

    ioc_file = tmp_path / "iocs.txt"
    ioc_file.write_text("8.8.8.8\n1.1.1.1\n9.9.9.9\n")

    ns = _make_enrich_ns(file=str(ioc_file), webhook="https://siem.test/hook")
    cli.handle_enrich(ns)

    assert len(calls) == 3
    posted_iocs = {payload["ioc"] for _, payload in calls}
    assert posted_iocs == {"8.8.8.8", "1.1.1.1", "9.9.9.9"}
    # Every call hits the same URL.
    assert {url for url, _ in calls} == {"https://siem.test/hook"}


# ---------------------------------------------------------------------------
# Helper-level coverage — post_webhook contract
# ---------------------------------------------------------------------------


def test_post_webhook_returns_true_on_2xx(monkeypatch):
    class _Resp:
        status_code = 204

    monkeypatch.setattr(core_http, "post", lambda *a, **k: _Resp())
    assert core_http.post_webhook("https://x.test", {"hello": "world"}) is True


def test_post_webhook_returns_false_on_5xx(monkeypatch):
    class _Resp:
        status_code = 503

    monkeypatch.setattr(core_http, "post", lambda *a, **k: _Resp())
    assert core_http.post_webhook("https://x.test", {"k": "v"}) is False


def test_post_webhook_returns_false_when_underlying_returns_none(monkeypatch):
    """Rate-limiter starvation / transport failure → ``post`` returns None."""
    monkeypatch.setattr(core_http, "post", lambda *a, **k: None)
    assert core_http.post_webhook("https://x.test", {"k": "v"}) is False


def test_post_webhook_uses_webhook_source_key(monkeypatch):
    """The helper must gate on the dedicated ``webhook`` bucket, not borrow another."""
    seen_keys: list[str] = []

    class _Resp:
        status_code = 200

    def _capture(source_key, url, **kwargs):
        seen_keys.append(source_key)
        return _Resp()

    monkeypatch.setattr(core_http, "post", _capture)
    core_http.post_webhook("https://x.test", {"k": "v"})
    assert seen_keys == ["webhook"]


def test_webhook_bucket_registered_in_defaults():
    """Sanity: the ratelimit defaults expose a ``webhook`` bucket."""
    from ioc_tool.core import ratelimit
    assert "webhook" in ratelimit._DEFAULT_BUCKETS
    capacity, period = ratelimit._DEFAULT_BUCKETS["webhook"]
    assert capacity > 0 and period > 0

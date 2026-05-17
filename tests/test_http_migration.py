"""Soft-fail tests for modules migrated onto :mod:`ioc_tool.core.http`.

When the rate-limiter bucket refuses to hand out a token (or the request
raises) the helper returns ``None``. Each migrated module must collapse
that into its existing failure shape — ``None`` for the modules that
already returned ``None`` on miss, ``{"error": ...}`` for the modules
that surface an error envelope (Shodan, Censys).

Three representative modules are covered here — one per response shape:

* ``abuseipdb`` — returns a parsed ``data`` dict / ``None`` on miss.
* ``shodan_mod`` — surfaces an ``{"error": ...}`` envelope.
* ``censys`` — info-only source returning ``{}`` / ``{"error": ...}``.

Together they cover the three failure-path conventions used across the
nine migrated modules.
"""

from __future__ import annotations

import pytest

from ioc_tool.core import http
from ioc_tool.modules import abuseipdb, censys, shodan_mod


def test_abuseipdb_soft_fails_when_http_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bucket refusal / network failure → ``None`` (matches existing miss path)."""
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fake-key-for-test")
    monkeypatch.setattr(http, "get", lambda *a, **kw: None)
    assert abuseipdb.enrich_ip("1.2.3.4") is None


def test_shodan_soft_fails_with_error_dict(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bucket refusal → ``{"error": ...}`` envelope (matches existing failure shape)."""
    monkeypatch.setenv("SHODAN_API_KEY", "fake-key-for-test")
    monkeypatch.setattr(http, "get", lambda *a, **kw: None)
    result = shodan_mod.host_search("1.2.3.4")
    assert isinstance(result, dict)
    assert "error" in result


def test_censys_soft_fails_with_error_dict(monkeypatch: pytest.MonkeyPatch) -> None:
    """Censys is info-only — bucket refusal collapses to ``{"error": ...}`` envelope."""
    monkeypatch.setenv("CENSYS_API_KEY", "fake-pat-for-test")
    monkeypatch.setattr(http, "get", lambda *a, **kw: None)
    result = censys.host_lookup("1.2.3.4")
    assert isinstance(result, dict)
    assert "error" in result

"""Rate-limited HTTP helper tests.

Verifies the three documented behaviours:

* Bucket gating refuses to issue a request when no token can be acquired.
* 429 responses trigger a single retry honouring ``Retry-After``.
* Network exceptions collapse to ``None`` rather than propagating.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
import requests
import responses

from ioc_tool.core import http, ratelimit


@pytest.fixture(autouse=True)
def _reset():
    ratelimit.reset()
    yield
    ratelimit.reset()


@responses.activate
def test_get_success_returns_response(monkeypatch):
    responses.add(responses.GET, "https://example.test/x", json={"ok": True}, status=200)
    resp = http.get("virustotal", "https://example.test/x")
    assert resp is not None
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_get_returns_none_when_bucket_refuses(monkeypatch):
    # Patch ratelimit.acquire to refuse — simulates a real-world dry bucket.
    with patch.object(ratelimit, "acquire", return_value=False):
        resp = http.get("virustotal", "https://example.test/x", rate_timeout=0.01)
    assert resp is None


@responses.activate
def test_get_retries_after_429(monkeypatch):
    """A 429 with Retry-After triggers exactly one retry."""
    responses.add(
        responses.GET, "https://example.test/x",
        json={"err": "limit"}, status=429,
        headers={"Retry-After": "0"},  # immediate retry, keeps test fast
    )
    responses.add(
        responses.GET, "https://example.test/x",
        json={"ok": True}, status=200,
    )
    resp = http.get("virustotal", "https://example.test/x")
    assert resp is not None
    assert resp.status_code == 200
    assert len(responses.calls) == 2


@responses.activate
def test_get_returns_429_when_retry_also_fails(monkeypatch):
    """If the retry also 429s, return the 429 response (caller will reject it)."""
    for _ in range(2):
        responses.add(
            responses.GET, "https://example.test/x",
            json={"err": "limit"}, status=429,
            headers={"Retry-After": "0"},
        )
    resp = http.get("virustotal", "https://example.test/x")
    assert resp is not None
    assert resp.status_code == 429


@responses.activate
def test_network_exception_returns_none(monkeypatch):
    responses.add(
        responses.GET, "https://example.test/x",
        body=requests.ConnectionError("boom"),
    )
    resp = http.get("virustotal", "https://example.test/x")
    assert resp is None


@responses.activate
def test_request_passes_kwargs(monkeypatch):
    """Ensure headers + params reach the underlying requests call."""
    responses.add(responses.GET, "https://example.test/x", json={"ok": True}, status=200)
    resp = http.get(
        "virustotal", "https://example.test/x",
        headers={"x-apikey": "abc"},
        params={"limit": 5},
    )
    assert resp is not None
    call = responses.calls[0]
    assert call.request.headers.get("x-apikey") == "abc"
    assert "limit=5" in call.request.url


def test_parse_retry_after_handles_bad_input():
    """Internal helper — bad values fall back to ``None`` (caller uses 1s default)."""
    assert http._parse_retry_after(None) is None
    assert http._parse_retry_after("") is None
    assert http._parse_retry_after("not-a-number") is None
    assert http._parse_retry_after("-3") is None
    assert http._parse_retry_after("5") == 5.0
    # Cap at MAX_RETRY_AFTER so a hostile server can't pin the worker.
    assert http._parse_retry_after("9999") == http._MAX_RETRY_AFTER_S

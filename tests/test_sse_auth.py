"""Auth gating for the ``/api/ui/events`` SSE stream.

The stream is consumed by ``EventSource`` in the dashboard, which can't
attach an ``Authorization`` header — so the bearer token is accepted
via the ``?token=`` query param instead. This module pins the four
states:

* token configured + no query token → ``401``
* token configured + wrong query token → ``401``
* token configured + matching query token → ``200`` (the StreamingResponse
  is returned and starts emitting frames)
* token NOT configured → ``200`` (open mode, matches every other
  endpoint that delegates auth to :func:`require_token`)

The 401 paths are tested via ``TestClient`` because they short-circuit
before any streaming starts. The 200 paths can't go through the
TestClient end-to-end — httpx's ASGI transport buffers streaming
bodies, so any attempt to read or even tear down a still-open SSE
response would hang. Instead we invoke the route coroutine directly
and inspect the returned ``StreamingResponse`` object's metadata. The
actual streamed bytes are covered by ``tests/test_sse_heartbeat.py``
which drives the extracted ``_events_stream`` generator directly.
"""

from __future__ import annotations

import asyncio
import os

import pytest
from fastapi import HTTPException
from fastapi.responses import StreamingResponse
from fastapi.testclient import TestClient

from ioc_tool.web import api as api_mod
from ioc_tool.web.api import app


@pytest.fixture(autouse=True)
def _clear_token_env():
    """Make sure no stale token leaks in from the developer shell."""
    os.environ.pop("SHADOWSCOPE_API_TOKEN", None)
    yield
    os.environ.pop("SHADOWSCOPE_API_TOKEN", None)


def _invoke_events(token):
    """Call the route handler directly and discard the streaming body.

    Returns either the ``StreamingResponse`` (success path) or the
    ``HTTPException`` raised by the auth gate (401 path).
    """
    try:
        return asyncio.run(api_mod.ui_events(token=token))
    except HTTPException as exc:
        return exc


def test_events_requires_token_when_configured(monkeypatch):
    """No ?token= → 401 when SHADOWSCOPE_API_TOKEN is set."""
    monkeypatch.setenv("SHADOWSCOPE_API_TOKEN", "supersecret")
    # Via TestClient — the auth gate short-circuits before any streaming
    # starts, so no buffering risk.
    with TestClient(app) as c:
        r = c.get("/api/ui/events")
    assert r.status_code == 401


def test_events_rejects_wrong_token(monkeypatch):
    """?token=wrong → 401."""
    monkeypatch.setenv("SHADOWSCOPE_API_TOKEN", "supersecret")
    with TestClient(app) as c:
        r = c.get("/api/ui/events", params={"token": "nope"})
    assert r.status_code == 401


def test_events_accepts_correct_token(monkeypatch):
    """?token=correct → returns a ``StreamingResponse`` with SSE headers.

    We invoke the coroutine directly so we never block on the streaming
    body (the TestClient would hang trying to drain an SSE response).
    """
    monkeypatch.setenv("SHADOWSCOPE_API_TOKEN", "supersecret")
    result = _invoke_events("supersecret")
    assert isinstance(result, StreamingResponse), result
    assert result.media_type == "text/event-stream"
    assert result.headers.get("cache-control") == "no-cache, no-transform"
    assert result.headers.get("x-accel-buffering") == "no"


def test_events_open_when_token_not_configured():
    """No SHADOWSCOPE_API_TOKEN → endpoint is open (returns the stream).

    Confirms the "homelab localhost convenience" mode survives: no
    token configured means the route accepts any (or no) ?token=
    value.
    """
    os.environ.pop("SHADOWSCOPE_API_TOKEN", None)
    result = _invoke_events(None)
    assert isinstance(result, StreamingResponse), result
    assert result.media_type == "text/event-stream"
    # Even a bogus ?token= sails through when the env var is unset.
    result = _invoke_events("anything-goes")
    assert isinstance(result, StreamingResponse), result


# ---------------------------------------------------------------------------
# CORS tightening — when a token is configured, default to loopback only
# ---------------------------------------------------------------------------


def test_cors_origins_tightens_when_token_set(monkeypatch):
    """Auth-on + no explicit origins → CORS defaults to loopback (no '*')."""
    monkeypatch.setenv("SHADOWSCOPE_API_TOKEN", "x")
    monkeypatch.delenv("SHADOWSCOPE_CORS_ORIGINS", raising=False)
    from ioc_tool.web.api import _cors_origins

    origins = _cors_origins()
    assert "*" not in origins
    assert "http://localhost:8765" in origins
    assert "http://127.0.0.1:8765" in origins


def test_cors_origins_open_when_no_token(monkeypatch):
    """Auth-off + no explicit origins → keep legacy permissive default."""
    monkeypatch.delenv("SHADOWSCOPE_API_TOKEN", raising=False)
    monkeypatch.delenv("SHADOWSCOPE_CORS_ORIGINS", raising=False)
    from ioc_tool.web.api import _cors_origins

    assert _cors_origins() == ["*"]


def test_cors_origins_env_override_wins(monkeypatch):
    """Explicit SHADOWSCOPE_CORS_ORIGINS always wins, token or not."""
    monkeypatch.setenv("SHADOWSCOPE_API_TOKEN", "x")
    monkeypatch.setenv(
        "SHADOWSCOPE_CORS_ORIGINS",
        "https://secops.lan, https://dashboard.lan",
    )
    from ioc_tool.web.api import _cors_origins

    assert _cors_origins() == ["https://secops.lan", "https://dashboard.lan"]


# ---------------------------------------------------------------------------
# JS subscriber appends ?token= when a session-storage token is present
# ---------------------------------------------------------------------------


def test_data_js_subscribe_helper_appends_token():
    """``shadowscopeSubscribeEvents`` must read ``ss_api_token`` and pass it as ?token=."""
    os.environ.pop("SHADOWSCOPE_API_TOKEN", None)
    with TestClient(app) as c:
        r = c.get("/static/shared/data.js")
    assert r.status_code == 200
    body = r.text
    # Token is read from sessionStorage (matches every other helper in the file).
    assert "ss_api_token" in body
    # And appended as ?token= to the SSE URL.
    assert "/api/ui/events?token=" in body

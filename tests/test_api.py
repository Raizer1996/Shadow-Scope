"""Tests for the FastAPI REST API surface (``ioc_tool.web.api``).

All tests use ``fastapi.testclient.TestClient`` — sync, no async test
machinery needed. The enrichment pipeline is mocked via ``monkeypatch``
so we never hit live APIs (matches the "never call external APIs in
tests" rule from ``CLAUDE.md``).

The async ``enrich.enrich_ioc_async`` is patched with an ``async def``
stub so ``await`` semantics on the server side stay realistic.
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from ioc_tool.core import enrich as enrich_mod
from ioc_tool.web import api as api_mod
from ioc_tool.web.api import app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def client() -> TestClient:
    """Plain TestClient — no auth token in environment by default."""
    # Make sure no stale token leaks in from the developer's shell.
    os.environ.pop("SHADOWSCOPE_API_TOKEN", None)
    return TestClient(app)


def _stub_async_enrich(monkeypatch, *, stub=None):
    """Replace ``enrich.enrich_ioc_async`` with an awaitable stub.

    The stub returns a small fixed dict per call so tests can assert on
    structure without exercising any real network.
    """
    async def _default_stub(value, ioc_type):
        return {
            "ioc": value,
            "type": ioc_type,
            "modules": {
                "VirusTotal": {
                    "score": 0,
                    "data": {
                        "last_analysis_stats": {
                            "malicious": 0,
                            "harmless": 90,
                            "suspicious": 0,
                            "undetected": 0,
                        }
                    },
                }
            },
            "final_score": 0,
        }

    # Patch BOTH the module-level original AND the imported reference
    # used by ``ioc_tool.web.api`` — they're separate name bindings.
    monkeypatch.setattr(enrich_mod, "enrich_ioc_async", stub or _default_stub)
    monkeypatch.setattr(api_mod.enrich, "enrich_ioc_async", stub or _default_stub)


# ---------------------------------------------------------------------------
# Basic / metadata endpoints
# ---------------------------------------------------------------------------


def test_root_returns_service_info(client):
    """GET / returns a dict with version and endpoints keys."""
    response = client.get("/")
    assert response.status_code == 200
    payload = response.json()
    assert "version" in payload
    assert "endpoints" in payload
    assert isinstance(payload["endpoints"], list)
    assert any("/enrich" in ep for ep in payload["endpoints"])


def test_root_includes_ui_link(client):
    """GET / response carries a ``ui`` key pointing at /ui."""
    response = client.get("/")
    assert response.status_code == 200
    payload = response.json()
    assert payload.get("ui") == "/ui"
    # And the endpoints list mentions the UI route explicitly.
    assert any("/ui" in ep for ep in payload["endpoints"])


def test_health_returns_ok(client):
    """GET /health returns {'status': 'ok'}."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# /enrich
# ---------------------------------------------------------------------------


def test_enrich_ip_returns_result_dict(client, monkeypatch):
    """GET /enrich?ioc=1.2.3.4 returns the stubbed enrichment dict."""
    _stub_async_enrich(monkeypatch)
    response = client.get("/enrich", params={"ioc": "1.2.3.4"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["ioc"] == "1.2.3.4"
    assert payload["type"] == "ip"
    assert "modules" in payload
    assert payload["final_score"] == 0


def test_enrich_unknown_type_returns_400(client, monkeypatch):
    """An unparseable IOC returns 400 with a helpful message."""
    _stub_async_enrich(monkeypatch)
    response = client.get("/enrich", params={"ioc": "garbage-input-no-tld"})
    assert response.status_code == 400
    body = response.json()
    assert "detail" in body
    assert "ioc type" in body["detail"].lower() or "unable" in body["detail"].lower()


def test_enrich_refangs_defanged_input(client, monkeypatch):
    """Defanged ``1[.]2[.]3[.]4`` should be refanged before parsing."""
    captured: dict = {}

    async def _capturing(value, ioc_type):
        captured["value"] = value
        captured["type"] = ioc_type
        return {"ioc": value, "type": ioc_type, "modules": {}, "final_score": 0}

    _stub_async_enrich(monkeypatch, stub=_capturing)
    response = client.get("/enrich", params={"ioc": "1[.]2[.]3[.]4"})
    assert response.status_code == 200
    # The enrichment function received the LIVE form (refanged on entry).
    assert captured["value"] == "1.2.3.4"
    assert captured["type"] == "ip"


def test_enrich_defang_query_param(client, monkeypatch):
    """defang=true defangs the ioc field in the response."""
    _stub_async_enrich(monkeypatch)
    response = client.get(
        "/enrich",
        params={"ioc": "1.2.3.4", "defang": "true"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["ioc"] == "1[.]2[.]3[.]4"


# ---------------------------------------------------------------------------
# /enrich/bulk
# ---------------------------------------------------------------------------


def test_bulk_enrich_runs_concurrent(client, monkeypatch):
    """POST /enrich/bulk with 3 IOCs returns 3 results."""
    _stub_async_enrich(monkeypatch)
    response = client.post(
        "/enrich/bulk",
        json={"iocs": ["1.2.3.4", "8.8.8.8", "evil.com"]},
    )
    assert response.status_code == 200
    payload = response.json()
    assert isinstance(payload, list)
    assert len(payload) == 3
    iocs = {item["ioc"] for item in payload}
    assert iocs == {"1.2.3.4", "8.8.8.8", "evil.com"}


# ---------------------------------------------------------------------------
# /extract
# ---------------------------------------------------------------------------


def test_extract_endpoint_pulls_iocs(client, monkeypatch):
    """POST /extract pulls IOCs from a text blob and enriches each."""
    _stub_async_enrich(monkeypatch)
    response = client.post(
        "/extract",
        json={"text": "see 1.2.3.4 in the firewall logs"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert "extracted" in payload
    assert "results" in payload
    # The extractor must have surfaced the IP under the 'ip' bucket
    assert "ip" in payload["extracted"]
    assert "1.2.3.4" in payload["extracted"]["ip"]
    # And the enrichment ran for that IP
    assert any(r["ioc"] == "1.2.3.4" for r in payload["results"])


# ---------------------------------------------------------------------------
# /show
# ---------------------------------------------------------------------------


def test_show_returns_404_for_unknown(client, monkeypatch):
    """GET /show?ioc=<never-seen> returns 404."""
    # Ensure the DB lookup returns nothing — patch get_ioc_id to return None
    from ioc_tool.core import database as db_mod

    monkeypatch.setattr(db_mod, "get_ioc_id", lambda v: None)
    monkeypatch.setattr(api_mod.database, "get_ioc_id", lambda v: None)

    response = client.get("/show", params={"ioc": "never-seen-1.2.3.4"})
    assert response.status_code == 404
    body = response.json()
    assert "detail" in body


# ---------------------------------------------------------------------------
# /sources
# ---------------------------------------------------------------------------


def test_sources_endpoint_lists_keys_present(client, monkeypatch):
    """GET /sources returns a {source_name: bool} dict and never reveals key values."""
    # Set one key, leave others absent — bool flip should be observable.
    monkeypatch.setenv("VT_API_KEY", "totally-fake-key")
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    response = client.get("/sources")
    assert response.status_code == 200
    payload = response.json()
    assert isinstance(payload, dict)
    # Every value must be a bool — never a string key, never a leaked secret.
    for source, value in payload.items():
        assert isinstance(value, bool), (
            f"source {source!r} returned {value!r} ({type(value).__name__}) "
            "— should be bool"
        )
    # And the response body must not contain the actual key value
    assert "totally-fake-key" not in response.text
    assert payload["virustotal"] is True
    assert payload["abuseipdb"] is False
    # No-key-required sources are always true
    assert payload["urlhaus"] is True
    assert payload["threatfox"] is True


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


def test_auth_required_when_token_set(monkeypatch):
    """With SHADOWSCOPE_API_TOKEN set, /enrich without header → 401."""
    monkeypatch.setenv("SHADOWSCOPE_API_TOKEN", "supersecret")
    _stub_async_enrich(monkeypatch)
    with TestClient(app) as c:
        response = c.get("/enrich", params={"ioc": "1.2.3.4"})
    assert response.status_code == 401


def test_auth_passes_with_correct_token(monkeypatch):
    """With the correct Bearer token, /enrich succeeds."""
    monkeypatch.setenv("SHADOWSCOPE_API_TOKEN", "supersecret")
    _stub_async_enrich(monkeypatch)
    with TestClient(app) as c:
        response = c.get(
            "/enrich",
            params={"ioc": "1.2.3.4"},
            headers={"Authorization": "Bearer supersecret"},
        )
    assert response.status_code == 200
    assert response.json()["ioc"] == "1.2.3.4"


def test_auth_wrong_token_returns_403(monkeypatch):
    """Wrong bearer token must return 403, not 401."""
    monkeypatch.setenv("SHADOWSCOPE_API_TOKEN", "supersecret")
    _stub_async_enrich(monkeypatch)
    with TestClient(app) as c:
        response = c.get(
            "/enrich",
            params={"ioc": "1.2.3.4"},
            headers={"Authorization": "Bearer wrong-one"},
        )
    assert response.status_code == 403


def test_health_skips_auth_even_when_token_set(monkeypatch):
    """/health is always public so container healthchecks don't need a token."""
    monkeypatch.setenv("SHADOWSCOPE_API_TOKEN", "supersecret")
    with TestClient(app) as c:
        response = c.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# Dashboard UI (/ui + /static/*)
# ---------------------------------------------------------------------------


def test_ui_route_returns_html(client):
    """GET /ui returns 200 HTML containing the ShadowScope title."""
    response = client.get("/ui")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "ShadowScope" in response.text


def test_ui_route_skips_auth(monkeypatch):
    """Even with SHADOWSCOPE_API_TOKEN set, /ui loads without an Authorization header.

    Rationale: the HTML shell is harmless; the JSON endpoints behind it are
    what's gated. The browser needs to be able to load the page in order to
    prompt for a token in the first place.
    """
    monkeypatch.setenv("SHADOWSCOPE_API_TOKEN", "supersecret")
    with TestClient(app) as c:
        response = c.get("/ui")
    assert response.status_code == 200
    assert "ShadowScope" in response.text


def test_static_files_served(client):
    """GET /static/app.js returns 200 with a JS content type."""
    response = client.get("/static/app.js")
    assert response.status_code == 200
    ctype = response.headers.get("content-type", "")
    assert ("javascript" in ctype) or ctype.startswith("application/javascript"), (
        f"unexpected content-type for /static/app.js: {ctype!r}"
    )
    # And it must really be the app code — sanity-check a known marker.
    assert "ShadowScope dashboard" in response.text

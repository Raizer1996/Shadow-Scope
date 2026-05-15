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
# /enrich — LLM summary integration (summary=true)
# ---------------------------------------------------------------------------


def test_api_enrich_with_summary_query(client, monkeypatch):
    """``?summary=true`` injects ``llm_summary`` populated from llm.summarize."""
    _stub_async_enrich(monkeypatch)
    # Patch llm.summarize where it's *used* (the api module's binding) so the
    # async to_thread wrapper picks it up.
    monkeypatch.setattr(api_mod.llm_mod, "summarize", lambda r: "verdict text")
    response = client.get(
        "/enrich",
        params={"ioc": "8.8.8.8", "summary": "true"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload.get("llm_summary") == "verdict text"


def test_api_enrich_summary_false_omits_field(client, monkeypatch):
    """Without ``?summary=true`` the ``llm_summary`` key is absent."""
    _stub_async_enrich(monkeypatch)
    # Even if summarize would return text, it must never run when the flag's off.
    monkeypatch.setattr(
        api_mod.llm_mod,
        "summarize",
        lambda r: (_ for _ in ()).throw(AssertionError("must not be called")),
    )
    response = client.get("/enrich", params={"ioc": "8.8.8.8"})
    assert response.status_code == 200
    payload = response.json()
    assert "llm_summary" not in payload


def test_api_enrich_summary_none_omits_field(client, monkeypatch):
    """When llm.summarize returns ``None`` (Ollama down), no key is injected."""
    _stub_async_enrich(monkeypatch)
    monkeypatch.setattr(api_mod.llm_mod, "summarize", lambda r: None)
    response = client.get(
        "/enrich",
        params={"ioc": "8.8.8.8", "summary": "true"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert "llm_summary" not in payload


def test_api_bulk_enrich_with_summary(client, monkeypatch):
    """Bulk endpoint attaches per-result summaries when ``?summary=true`` is set."""
    _stub_async_enrich(monkeypatch)
    monkeypatch.setattr(
        api_mod.llm_mod, "summarize", lambda r: "verdict for " + r["ioc"]
    )
    response = client.post(
        "/enrich/bulk",
        params={"summary": "true"},
        json={"iocs": ["1.2.3.4", "8.8.8.8"]},
    )
    assert response.status_code == 200
    payload = response.json()
    assert isinstance(payload, list)
    assert all("llm_summary" in r for r in payload)
    assert any(r["llm_summary"].endswith("1.2.3.4") for r in payload)


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
    """GET /static/shared/data.js returns 200 with a JS content type.

    The brutalist UI pulls its mock data from ``/static/shared/data.js``;
    this exercises the same StaticFiles mount the dashboard relies on.
    """
    response = client.get("/static/shared/data.js")
    assert response.status_code == 200
    ctype = response.headers.get("content-type", "")
    assert ("javascript" in ctype) or ctype.startswith("application/javascript"), (
        f"unexpected content-type for /static/shared/data.js: {ctype!r}"
    )
    # Known marker — sanity-check it's really the data module.
    assert "IOC_DB" in response.text


def test_classic_ui_still_reachable(client):
    """Legacy vanilla dashboard remains at /ui-classic until full API wiring lands."""
    response = client.get("/ui-classic")
    assert response.status_code == 200
    # Markers from the classic HTML
    assert "ShadowScope" in response.text
    assert "/static/classic/styles.css" in response.text


# ---------------------------------------------------------------------------
# /api/ui/enrich — brutalist dashboard adapter
# ---------------------------------------------------------------------------


def _stub_async_enrich_with_kwargs(monkeypatch, payload):
    """Async stub that accepts the no_cache kwarg /api/ui/enrich passes."""
    async def _stub(value, ioc_type, *, no_cache=False):
        return {**payload, "ioc": value, "type": ioc_type}
    monkeypatch.setattr(api_mod.enrich, "enrich_ioc_async", _stub)


def test_ui_enrich_returns_shaped_payload(client, monkeypatch):
    _stub_async_enrich_with_kwargs(monkeypatch, {
        "ioc": "evil.example.com",
        "type": "domain",
        "final_score": 85,
        "modules": {
            "VirusTotal": {"score": 75, "data": {
                "last_analysis_stats": {"malicious": 7, "harmless": 60, "suspicious": 0, "undetected": 35},
            }},
            "URLhaus": {"score": 95, "data": {"threat": "malware_download", "tags": ["emotet"]}},
            "Heuristics": {"score": 75, "data": {
                "nrd": {"bucket": "nrd", "age_days": 12, "score": 75},
                "dga": {"score": 30},
            }},
        },
    })
    r = client.get("/api/ui/enrich?ioc=evil.example.com")
    assert r.status_code == 200
    body = r.json()
    # UI-only shape additions
    assert body["id"].startswith("ioc_")
    assert "agreement" in body and body["agreement"]["sources_total"] > 0
    assert "enriched_at" in body
    # Per-module detail summaries populated
    assert body["modules"]["VirusTotal"]["detail"] == "7 / 102 engines malicious"
    assert "threat=malware_download" in body["modules"]["URLhaus"]["detail"]
    assert "NRD(12d)" in body["modules"]["Heuristics"]["detail"]


def test_ui_enrich_rejects_unknown_type(client, monkeypatch):
    _stub_async_enrich_with_kwargs(monkeypatch, {"modules": {}, "final_score": 0})
    r = client.get("/api/ui/enrich?ioc=not-an-ioc!")
    assert r.status_code == 400


def test_ui_enrich_record_id_stable(client, monkeypatch):
    """Same IOC + type → same id (idempotent dashboard rows)."""
    _stub_async_enrich_with_kwargs(monkeypatch, {"modules": {}, "final_score": 0})
    a = client.get("/api/ui/enrich?ioc=8.8.8.8").json()
    b = client.get("/api/ui/enrich?ioc=8.8.8.8").json()
    assert a["id"] == b["id"]


def test_ui_enrich_carries_no_cache_param(client, monkeypatch):
    seen: dict = {}
    async def _stub(value, ioc_type, *, no_cache=False):
        seen["no_cache"] = no_cache
        return {"ioc": value, "type": ioc_type, "modules": {}, "final_score": 0}
    monkeypatch.setattr(api_mod.enrich, "enrich_ioc_async", _stub)
    client.get("/api/ui/enrich?ioc=8.8.8.8&no_cache=true")
    assert seen["no_cache"] is True

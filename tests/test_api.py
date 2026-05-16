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


# /ui-classic was retired by PR #37 (22d564f) — brutalist v2 is now the
# sole canonical dashboard at /ui. The old "legacy still reachable" test
# was orphaned by that refactor; it stays removed.


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


# ---------------------------------------------------------------------------
# /api/cache/{stats,prune,clear} — cache maintenance endpoints
# ---------------------------------------------------------------------------


@pytest.fixture
def cache_db(monkeypatch, tmp_path):
    """Tmp-path SQLite for the cache endpoints. Each test starts empty."""
    from ioc_tool.core import database as _db
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "ioc.db"))
    _db.init_db()
    return _db


def _seed_cache_row(db, ioc_value, source, age_days, score=0):
    """Insert one enrichment row aged ``now - age_days``. Returns ioc_id."""
    from datetime import datetime, timedelta
    ioc_id = db.add_or_update_ioc(ioc_value, "ip")
    ts = (datetime.now() - timedelta(days=age_days)).strftime("%Y-%m-%d %H:%M:%S")
    conn = db.get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO enrichments (ioc_id, source, data, timestamp, score) VALUES (?,?,?,?,?)",
        (ioc_id, source, "{}", ts, score),
    )
    conn.commit()
    conn.close()
    return ioc_id


def test_cache_stats_empty(client, cache_db):
    r = client.get("/api/cache/stats")
    assert r.status_code == 200
    body = r.json()
    assert body["ioc_count"] == 0
    assert body["enrichment_count"] == 0
    assert body["oldest_timestamp"] is None
    assert body["per_source"] == []


def test_cache_stats_populated(client, cache_db):
    _seed_cache_row(cache_db, "1.1.1.1", "vt", age_days=10)
    _seed_cache_row(cache_db, "1.1.1.1", "vt", age_days=1)
    _seed_cache_row(cache_db, "1.1.1.1", "abuseipdb", age_days=5)
    r = client.get("/api/cache/stats")
    assert r.status_code == 200
    body = r.json()
    assert body["ioc_count"] == 1
    assert body["enrichment_count"] == 3
    by_src = {row["source"]: row["rows"] for row in body["per_source"]}
    assert by_src == {"vt": 2, "abuseipdb": 1}


def test_cache_prune_uses_request_window(client, cache_db):
    _seed_cache_row(cache_db, "1.1.1.1", "vt", age_days=30)
    _seed_cache_row(cache_db, "1.1.1.1", "vt", age_days=2)
    r = client.post("/api/cache/prune", json={"older_than_days": 10})
    assert r.status_code == 200
    body = r.json()
    assert body["used_older_than_days"] == 10
    assert body["removed_by_age"] == 1


def test_cache_prune_defaults_to_retention_env(client, cache_db, monkeypatch):
    monkeypatch.setenv("RETENTION_DAYS", "5")
    _seed_cache_row(cache_db, "1.1.1.1", "vt", age_days=30)
    _seed_cache_row(cache_db, "1.1.1.1", "vt", age_days=1)
    r = client.post("/api/cache/prune", json={})
    assert r.status_code == 200
    body = r.json()
    assert body["used_older_than_days"] == 5
    assert body["removed_by_age"] == 1


def test_cache_prune_keep_last_caps_history(client, cache_db):
    for hours in range(5):
        _seed_cache_row(cache_db, "1.1.1.1", "vt", age_days=hours / 24)
    r = client.post(
        "/api/cache/prune",
        json={"older_than_days": 365, "keep_last": 2},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["removed_by_age"] == 0
    assert body["removed_by_keep_last"] == 3


def test_cache_clear_by_source(client, cache_db):
    _seed_cache_row(cache_db, "1.1.1.1", "vt", age_days=1)
    _seed_cache_row(cache_db, "1.1.1.1", "abuseipdb", age_days=1)
    r = client.post("/api/cache/clear", json={"source": "vt"})
    assert r.status_code == 200
    body = r.json()
    assert body["scope"] == "source=vt"
    assert body["removed"] == 1


def test_cache_clear_by_ioc(client, cache_db):
    _seed_cache_row(cache_db, "1.1.1.1", "vt", age_days=1)
    _seed_cache_row(cache_db, "2.2.2.2", "vt", age_days=1)
    r = client.post("/api/cache/clear", json={"ioc": "1.1.1.1"})
    assert r.status_code == 200
    body = r.json()
    assert body["scope"] == "ioc=1.1.1.1"
    assert body["removed"] == 1


def test_cache_clear_all_requires_all_true(client, cache_db):
    _seed_cache_row(cache_db, "1.1.1.1", "vt", age_days=1)
    r = client.post("/api/cache/clear", json={"all": True})
    assert r.status_code == 200
    assert r.json() == {"scope": "all", "removed": 1}


def test_cache_clear_rejects_empty_filter(client, cache_db):
    """No filter at all → 400, not an accidental wipe."""
    r = client.post("/api/cache/clear", json={})
    assert r.status_code == 400


def test_cache_clear_rejects_multiple_filters(client, cache_db):
    r = client.post(
        "/api/cache/clear",
        json={"source": "vt", "ioc": "1.1.1.1"},
    )
    assert r.status_code == 400


def test_cache_endpoints_require_token(client, cache_db, monkeypatch):
    """When SHADOWSCOPE_API_TOKEN is set, the endpoints reject unauth'd calls."""
    monkeypatch.setenv("SHADOWSCOPE_API_TOKEN", "secret")
    assert client.get("/api/cache/stats").status_code == 401
    assert client.post("/api/cache/prune", json={}).status_code == 401
    assert client.post("/api/cache/clear", json={"all": True}).status_code == 401
    # With the right token, they pass through.
    h = {"Authorization": "Bearer secret"}
    assert client.get("/api/cache/stats", headers=h).status_code == 200


# ---------------------------------------------------------------------------
# /api/ui/recent — dashboard recent strip seed
# ---------------------------------------------------------------------------


def test_ui_recent_empty_workspace_returns_empty_list(client, cache_db):
    """Fresh workspace → []. Dashboard renders the empty-state prompt."""
    r = client.get("/api/ui/recent")
    assert r.status_code == 200
    assert r.json() == []


def test_ui_recent_returns_newest_first(client, cache_db):
    """Two IPs, second seeded with newer last_seen → comes first."""
    _seed_cache_row(cache_db, "1.1.1.1", "virustotal", age_days=5, score=10)
    _seed_cache_row(cache_db, "2.2.2.2", "virustotal", age_days=1, score=20)
    # add_or_update_ioc bumps last_seen on touch — re-touch the second
    # IOC so it definitively ranks newest.
    cache_db.add_or_update_ioc("2.2.2.2", "ip")
    r = client.get("/api/ui/recent")
    assert r.status_code == 200
    rows = r.json()
    assert [row["ioc"] for row in rows] == ["2.2.2.2", "1.1.1.1"]
    # Each row carries the brutalist-UI shape contract.
    for row in rows:
        assert {"id", "ioc", "type", "final_score", "modules", "enriched_at"} <= row.keys()


def test_ui_recent_respects_limit(client, cache_db):
    for i in range(5):
        _seed_cache_row(cache_db, f"10.0.0.{i}", "virustotal", age_days=i, score=0)
    r = client.get("/api/ui/recent", params={"limit": 2})
    assert r.status_code == 200
    assert len(r.json()) == 2


def test_ui_recent_skips_iocs_with_no_enrichments(client, cache_db):
    """An ``iocs`` row without any enrichment rows isn't useful — omit it."""
    cache_db.add_or_update_ioc("9.9.9.9", "ip")  # row exists, no enrichments
    _seed_cache_row(cache_db, "1.1.1.1", "virustotal", age_days=1, score=50)
    r = client.get("/api/ui/recent")
    assert r.status_code == 200
    iocs = [row["ioc"] for row in r.json()]
    assert iocs == ["1.1.1.1"]


def test_ui_recent_normalises_timestamp_to_iso(client, cache_db):
    """`enriched_at` must end in `Z` so the JS Relative component parses it."""
    _seed_cache_row(cache_db, "1.1.1.1", "virustotal", age_days=1, score=0)
    r = client.get("/api/ui/recent")
    rows = r.json()
    assert rows[0]["enriched_at"].endswith("Z")
    assert "T" in rows[0]["enriched_at"]


def test_ui_recent_requires_token(client, cache_db, monkeypatch):
    monkeypatch.setenv("SHADOWSCOPE_API_TOKEN", "secret")
    assert client.get("/api/ui/recent").status_code == 401
    h = {"Authorization": "Bearer secret"}
    assert client.get("/api/ui/recent", headers=h).status_code == 200


def test_ui_recent_rejects_out_of_range_limit(client, cache_db):
    """limit must be 1..50 — FastAPI enforces this at the route layer."""
    assert client.get("/api/ui/recent", params={"limit": 0}).status_code == 422
    assert client.get("/api/ui/recent", params={"limit": 999}).status_code == 422


# ---------------------------------------------------------------------------
# /api/ui/pivot — cache-wide related-IOC lookup
# ---------------------------------------------------------------------------


def _seed_with_json(db, ioc_value, source, payload, age_days=1, score=0):
    """Insert a row with arbitrary JSON payload. Returns ioc_id."""
    import json as _json
    from datetime import datetime, timedelta
    ioc_id = db.add_or_update_ioc(ioc_value, "domain")
    ts = (datetime.now() - timedelta(days=age_days)).strftime("%Y-%m-%d %H:%M:%S")
    conn = db.get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO enrichments (ioc_id, source, data, timestamp, score) VALUES (?,?,?,?,?)",
        (ioc_id, source, _json.dumps(payload), ts, score),
    )
    conn.commit()
    conn.close()
    return ioc_id


def test_ui_pivot_rejects_bad_kind(client, cache_db):
    r = client.get("/api/ui/pivot", params={"kind": "garbage", "value": "x"})
    assert r.status_code == 400
    assert "Allowed" in r.json()["detail"]


def test_ui_pivot_missing_value_returns_422(client, cache_db):
    """FastAPI validates ``value`` is required."""
    assert client.get("/api/ui/pivot", params={"kind": "tag"}).status_code == 422


def test_ui_pivot_finds_iocs_sharing_a_malware_family(client, cache_db):
    _seed_with_json(cache_db, "evil.com", "threatfox",
                    {"malware": "Cobalt Strike"}, score=80)
    _seed_with_json(cache_db, "other.com", "threatfox",
                    {"malware": "Cobalt Strike"}, score=70)
    _seed_with_json(cache_db, "harmless.com", "threatfox",
                    {"malware": "Emotet"}, score=50)
    r = client.get("/api/ui/pivot",
                   params={"kind": "malware", "value": "Cobalt Strike"})
    assert r.status_code == 200
    iocs = sorted([row["ioc"] for row in r.json()])
    assert iocs == ["evil.com", "other.com"]


def test_ui_pivot_quoted_match_avoids_substring_false_positive(client, cache_db):
    """`emotet` shouldn't match `emotetable` because the JSON literal
    is wrapped in quotes during the LIKE search."""
    _seed_with_json(cache_db, "real.com", "threatfox",
                    {"malware": "emotet"}, score=80)
    _seed_with_json(cache_db, "fake.com", "threatfox",
                    {"description": "this is emotetable text"}, score=10)
    r = client.get("/api/ui/pivot",
                   params={"kind": "malware", "value": "emotet"})
    iocs = [row["ioc"] for row in r.json()]
    assert iocs == ["real.com"]


def test_ui_pivot_exclude_omits_the_active_ioc(client, cache_db):
    """The active IOC shouldn't appear in its own RELATED list."""
    _seed_with_json(cache_db, "active.com", "threatfox",
                    {"malware": "Lockbit"}, score=85)
    _seed_with_json(cache_db, "related.com", "threatfox",
                    {"malware": "Lockbit"}, score=80)
    r = client.get(
        "/api/ui/pivot",
        params={"kind": "malware", "value": "Lockbit", "exclude": "active.com"},
    )
    iocs = [row["ioc"] for row in r.json()]
    assert iocs == ["related.com"]


def test_ui_pivot_registrar_match(client, cache_db):
    _seed_with_json(cache_db, "a.com", "whois",
                    {"registrar": "Namecheap, Inc."}, score=0)
    _seed_with_json(cache_db, "b.com", "whois",
                    {"registrar": "Namecheap, Inc."}, score=0)
    _seed_with_json(cache_db, "c.com", "whois",
                    {"registrar": "GoDaddy.com, LLC"}, score=0)
    r = client.get(
        "/api/ui/pivot",
        params={"kind": "registrar", "value": "Namecheap, Inc."},
    )
    iocs = sorted([row["ioc"] for row in r.json()])
    assert iocs == ["a.com", "b.com"]


def test_ui_pivot_ioc_kind_searches_value_column(client, cache_db):
    """`kind=ioc` matches against ``iocs.value`` directly — useful for
    partial domain pivots like clicking a base name to find subdomains.

    Uses the canonical ``virustotal`` source key so the module-shape
    reconstruction in the API layer surfaces the record (records with
    no recognised sources are dropped because the UI panels need at
    least one module to render)."""
    _seed_with_json(cache_db, "evil.example.com", "virustotal",
                    {"last_analysis_stats": {"malicious": 1}}, score=10)
    _seed_with_json(cache_db, "ftp.example.com", "virustotal",
                    {"last_analysis_stats": {"malicious": 0}}, score=0)
    _seed_with_json(cache_db, "unrelated.org", "virustotal",
                    {"last_analysis_stats": {"malicious": 0}}, score=0)
    r = client.get("/api/ui/pivot", params={"kind": "ioc", "value": "example.com"})
    iocs = sorted([row["ioc"] for row in r.json()])
    assert iocs == ["evil.example.com", "ftp.example.com"]


def test_ui_pivot_returns_empty_when_no_match(client, cache_db):
    _seed_with_json(cache_db, "evil.com", "threatfox",
                    {"malware": "Cobalt Strike"}, score=80)
    r = client.get("/api/ui/pivot",
                   params={"kind": "malware", "value": "NonExistent"})
    assert r.status_code == 200
    assert r.json() == []


def test_ui_pivot_requires_token(client, cache_db, monkeypatch):
    monkeypatch.setenv("SHADOWSCOPE_API_TOKEN", "secret")
    r = client.get("/api/ui/pivot", params={"kind": "any", "value": "x"})
    assert r.status_code == 401
    h = {"Authorization": "Bearer secret"}
    r = client.get(
        "/api/ui/pivot",
        params={"kind": "any", "value": "x"},
        headers=h,
    )
    assert r.status_code == 200


def test_ui_pivot_respects_limit(client, cache_db):
    for i in range(5):
        _seed_with_json(cache_db, f"d{i}.com", "threatfox",
                        {"malware": "Lockbit"}, score=80)
    r = client.get(
        "/api/ui/pivot",
        params={"kind": "malware", "value": "Lockbit", "limit": 2},
    )
    assert len(r.json()) == 2


# ---------------------------------------------------------------------------
# /api/ui/cases — backend-backed case views + mutations
# ---------------------------------------------------------------------------


def test_ui_cases_empty_workspace(client, cache_db):
    """No cases tagged → []. The UI shows an empty-state prompt."""
    r = client.get("/api/ui/cases")
    assert r.status_code == 200
    assert r.json() == []


def test_ui_cases_returns_distinct_cases(client, cache_db):
    """Cases group by case_name with member counts + derived severity."""
    ioc_a = cache_db.add_or_update_ioc("a.com", "domain")
    ioc_b = cache_db.add_or_update_ioc("b.com", "domain")
    ioc_c = cache_db.add_or_update_ioc("c.com", "domain")
    cache_db.update_last_score(ioc_a, 80)
    cache_db.update_last_score(ioc_b, 30)
    cache_db.update_last_score(ioc_c, 90)
    cache_db.tag_ioc(ioc_a, case="campaign-x")
    cache_db.tag_ioc(ioc_b, case="campaign-x")
    cache_db.tag_ioc(ioc_c, case="campaign-y")
    r = client.get("/api/ui/cases")
    assert r.status_code == 200
    body = r.json()
    # Severity descending → campaign-y (90) before campaign-x (80).
    assert [c["label"] for c in body] == ["campaign-y", "campaign-x"]
    by_id = {c["id"]: c for c in body}
    assert by_id["campaign-x"]["ioc_count"] == 2
    assert by_id["campaign-x"]["severity"] == 80
    assert sorted(by_id["campaign-x"]["iocs"]) == ["a.com", "b.com"]
    assert by_id["campaign-y"]["severity"] == 90


def test_ui_cases_omits_tag_only_rows(client, cache_db):
    """An ``ioc_tags`` row with tag=foo but no case_name shouldn't appear."""
    ioc_id = cache_db.add_or_update_ioc("a.com", "domain")
    cache_db.tag_ioc(ioc_id, tag="phishing")
    assert client.get("/api/ui/cases").json() == []


def test_ui_set_case_assigns_and_detaches(client, cache_db):
    cache_db.add_or_update_ioc("a.com", "domain")
    # Assign.
    r = client.patch("/api/ui/iocs/a.com/case", json={"case": "campaign-x"})
    assert r.status_code == 200
    assert r.json() == {"ioc": "a.com", "case": "campaign-x"}
    assert client.get("/api/ui/cases").json()[0]["label"] == "campaign-x"
    # Detach.
    r = client.patch("/api/ui/iocs/a.com/case", json={"case": None})
    assert r.status_code == 200
    assert r.json() == {"ioc": "a.com", "case": None}
    assert client.get("/api/ui/cases").json() == []


def test_ui_set_case_404_for_unknown_ioc(client, cache_db):
    """Cannot tag what isn't in the cache yet — caller must enrich first."""
    r = client.patch("/api/ui/iocs/ghost.com/case", json={"case": "x"})
    assert r.status_code == 404


def test_ui_set_case_refangs_path_value(client, cache_db):
    cache_db.add_or_update_ioc("evil.com", "domain")
    r = client.patch("/api/ui/iocs/evil[.]com/case", json={"case": "campaign-x"})
    assert r.status_code == 200
    assert r.json()["ioc"] == "evil.com"


def test_ui_set_case_replaces_prior_assignment(client, cache_db):
    """An IOC can only belong to one case at a time in the UI."""
    cache_db.add_or_update_ioc("a.com", "domain")
    client.patch("/api/ui/iocs/a.com/case", json={"case": "campaign-x"})
    client.patch("/api/ui/iocs/a.com/case", json={"case": "campaign-y"})
    cases = client.get("/api/ui/cases").json()
    labels = [c["label"] for c in cases]
    assert labels == ["campaign-y"]
    assert cases[0]["ioc_count"] == 1


def test_ui_delete_case_removes_every_assignment(client, cache_db):
    ioc_a = cache_db.add_or_update_ioc("a.com", "domain")
    ioc_b = cache_db.add_or_update_ioc("b.com", "domain")
    cache_db.tag_ioc(ioc_a, case="campaign-x")
    cache_db.tag_ioc(ioc_b, case="campaign-x")
    r = client.delete("/api/ui/cases/campaign-x")
    assert r.status_code == 200
    assert r.json()["removed"] == 2
    assert client.get("/api/ui/cases").json() == []


def test_ui_delete_case_unknown_returns_zero(client, cache_db):
    """Unknown case is a silent no-op — keeps the UI's delete path simple."""
    r = client.delete("/api/ui/cases/no-such-case")
    assert r.status_code == 200
    assert r.json() == {"case": "no-such-case", "removed": 0}


def test_ui_cases_requires_token(client, cache_db, monkeypatch):
    monkeypatch.setenv("SHADOWSCOPE_API_TOKEN", "secret")
    assert client.get("/api/ui/cases").status_code == 401
    assert client.patch("/api/ui/iocs/x/case", json={"case": "y"}).status_code == 401
    assert client.delete("/api/ui/cases/x").status_code == 401
    h = {"Authorization": "Bearer secret"}
    assert client.get("/api/ui/cases", headers=h).status_code == 200

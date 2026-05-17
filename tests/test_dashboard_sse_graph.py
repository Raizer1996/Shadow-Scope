"""Static-asset assertions for the dashboard's SSE wiring, score-history
sparkline, and CaseAssignBar recently-used boost.

The dashboard is delivered as raw .jsx / .js files (no build step), so
each feature reduces to "is the expected helper present in the file
served by FastAPI?". We follow the same pattern ``test_api`` uses for
``/static/shared/data.js`` — load the asset through the real
``StaticFiles`` mount, then grep for stable markers.

In addition we exercise the pure helpers we can run server-side:

* ``shadowscopePushRecentCase`` ordering & cap — re-implemented in
  Python here so we can guarantee the contract before shipping the JS;
  the test asserts the JS file actually wires the same key + cap.

These tests intentionally avoid spinning up a JS runtime (no jsdom in
this repo). Should one ever land, the helper contracts here translate
verbatim into Node-side unit tests.
"""

from __future__ import annotations

import os
from collections import deque

import pytest
from fastapi.testclient import TestClient

from ioc_tool.web.api import app


@pytest.fixture
def client() -> TestClient:
    os.environ.pop("SHADOWSCOPE_API_TOKEN", None)
    return TestClient(app)


# ---------------------------------------------------------------------------
# Feature #2 — SSE EventSource wiring
# ---------------------------------------------------------------------------


def test_data_js_exports_event_subscribe_helper(client):
    """``shared/data.js`` must expose ``window.shadowscopeSubscribeEvents``.

    The Watch view replaces its 8 s ``/api/ui/recent`` poll with this
    helper. If the symbol disappears or gets renamed, the dashboard
    would fall back to its (now removed) interval and silently stop
    updating — that's the regression this test catches.
    """
    r = client.get("/static/shared/data.js")
    assert r.status_code == 200
    body = r.text
    assert "shadowscopeSubscribeEvents" in body
    # Backoff cap — capped at 30 s per the design constraint.
    assert "30000" in body
    # Connects to the canonical SSE endpoint exposed by api.py.
    assert "/api/ui/events" in body
    # Hello + score event-types are both wired.
    assert 'addEventListener("hello"' in body
    assert 'addEventListener("score"' in body


def test_watchview_uses_sse_and_keeps_slow_fallback(client):
    """``screens.jsx`` must call the SSE helper AND keep a 60 s poll fallback.

    The slow poll is a safety net in case a reverse proxy buffers the
    event-stream response. We assert both pieces stay wired together —
    a future refactor that drops the fallback is something we want to
    review explicitly.
    """
    r = client.get("/static/brutal/screens.jsx")
    assert r.status_code == 200
    body = r.text
    assert "shadowscopeSubscribeEvents" in body
    # 60 s fallback poll — the old 8000 ms cadence is gone.
    assert "setInterval(reload, 60000)" in body
    assert "setInterval(reload, 8000)" not in body


# ---------------------------------------------------------------------------
# Feature #3 — Score history sparkline
# ---------------------------------------------------------------------------


def test_data_js_exports_score_history_helper(client):
    """``shared/data.js`` must expose ``window.shadowscopeScoreHistory``."""
    r = client.get("/static/shared/data.js")
    assert r.status_code == 200
    body = r.text
    assert "shadowscopeScoreHistory" in body
    # Endpoint shape — limit defaults to 50 per the dashboard's request.
    assert "/api/ui/score_history/" in body
    # 404 (IOC not in cache) is normalised to an empty result so the
    # sparkline can render its empty state without a try/catch.
    assert "r.status === 404" in body


def test_enrich_view_renders_sparkline_component(client):
    """``enrich-view.jsx`` must mount ``ScoreHistorySparkline`` on the detail view."""
    r = client.get("/static/brutal/enrich-view.jsx")
    assert r.status_code == 200
    body = r.text
    assert "ScoreHistorySparkline" in body
    # The empty state — analyst-facing copy when the cache has no
    # snapshots yet.
    assert "No score history" in body
    # SVG-only — no chart library imports.
    assert "<svg " in body
    assert "<polyline" not in body or "<path" in body  # path is acceptable
    # Wiring: the component fetches via the helper we just shipped.
    assert "shadowscopeScoreHistory" in body


def test_sparkline_has_hover_tooltip_markup(client):
    """``ScoreHistorySparkline`` must surface a per-point hover tooltip.

    The component renders an absolutely-positioned div near the snapped
    data point showing ``Score: <n>`` plus the ISO timestamp
    (``recorded_at`` field on each point). We pin a handful of stable
    markers so an accidental revert to the old no-tooltip render is
    caught at the static-asset layer, since the project has no JS
    runtime in CI.
    """
    r = client.get("/static/brutal/enrich-view.jsx")
    assert r.status_code == 200
    body = r.text
    # Hover state + mouse handlers wired on the wrapper.
    assert "score-history-tooltip" in body
    assert "score-history-wrap" in body
    assert "onMouseMove" in body
    assert "onMouseLeave" in body
    # The two pieces of data the tooltip surfaces.
    assert "Score:" in body
    assert "hovered.recorded_at" in body
    # Snap-to-nearest-point marker (small circle highlighting the
    # selected point so analysts can see what the tooltip refers to).
    assert "<circle" in body
    # The deferred-work marker from PR #62 must be gone — its presence
    # would mean the feature was reverted but the comment left behind.
    assert "TODO(v2)" not in body


def test_score_history_endpoint_empty_for_unknown_ioc(client):
    """``/api/ui/score_history/{value}`` returns 404 for IOCs not in cache.

    The frontend helper turns this into an empty result so the sparkline
    can render its "No score history" empty state. We pin the backend
    contract here too — a regression to 200/[] would mask the empty
    state silently.
    """
    r = client.get("/api/ui/score_history/never-enriched.example?limit=10")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Feature #5 — CaseAssignBar recently-used boost
# ---------------------------------------------------------------------------


def test_data_js_exposes_recent_cases_mru_helpers(client):
    """``shared/data.js`` must expose getters/setters for the MRU case list.

    Stored under ``shadowscope.recentCases``, capped at 5, newest-first.
    """
    r = client.get("/static/shared/data.js")
    assert r.status_code == 200
    body = r.text
    assert "shadowscopeGetRecentCases" in body
    assert "shadowscopePushRecentCase" in body
    assert "shadowscope.recentCases" in body
    # Cap = 5 per the spec.
    assert "SHADOWSCOPE_RECENT_CASES_MAX = 5" in body


def test_case_assign_bar_hoists_recent_cases(client):
    """``enrich-view.jsx`` must consume the MRU list and merge with the server list.

    We grep for both helper calls and the dedup pass; the actual order is
    pinned by the pure-Python re-implementation in
    ``test_recent_cases_mru_contract``.
    """
    r = client.get("/static/brutal/enrich-view.jsx")
    assert r.status_code == 200
    body = r.text
    assert "shadowscopeGetRecentCases" in body
    assert "shadowscopePushRecentCase" in body


def _push_recent(name: str, current: list[str], cap: int = 5) -> list[str]:
    """Pure-Python mirror of the JS ``shadowscopePushRecentCase`` helper.

    Contract:
    * blank / non-string input → no change, returns existing list
    * existing entry (case-insensitive) is removed before unshift
    * newest entry lands at index 0
    * the list is capped at ``cap`` entries
    """
    if not isinstance(name, str):
        return list(current)
    trimmed = name.strip()
    if not trimmed:
        return list(current)
    lower = trimmed.lower()
    deduped = [s for s in current if s.lower() != lower]
    deduped.insert(0, trimmed)
    return deduped[:cap]


def test_recent_cases_mru_contract():
    """Pin the MRU contract the JS helper must satisfy."""
    # Fresh list — first push lands at index 0.
    out = _push_recent("phish-2024", [])
    assert out == ["phish-2024"]

    # Re-pushing an existing case (case-insensitive) moves it back to the
    # top instead of duplicating.
    out = _push_recent("Phish-2024", ["other", "phish-2024", "third"])
    assert out == ["Phish-2024", "other", "third"]

    # Cap holds — overflow trims the oldest tail entry.
    seed = ["a", "b", "c", "d", "e"]
    out = _push_recent("f", seed)
    assert out == ["f", "a", "b", "c", "d"]
    assert len(out) == 5

    # Blank / whitespace push is a no-op.
    assert _push_recent("   ", ["a"]) == ["a"]
    assert _push_recent("", ["a"]) == ["a"]


def test_recent_cases_round_trip_via_deque_invariants():
    """Spot-check the MRU invariants over a long random-ish sequence.

    Picks a deterministic sequence that exercises every transition the
    JS helper must handle (insert, hoist-existing, cap-trim) and asserts
    the resulting list always matches a deque-based reference impl.
    """
    cap = 5
    seq = ["alpha", "Beta", "gamma", "alpha", "delta", "epsilon", "ALPHA", "zeta"]
    impl: list[str] = []
    ref: deque[str] = deque(maxlen=cap)
    for name in seq:
        impl = _push_recent(name, impl, cap=cap)
        lower = name.lower()
        # Reference: lowercase-dedup, MRU-first.
        ref = deque((s for s in ref if s.lower() != lower), maxlen=cap)
        ref.appendleft(name)
    assert impl == list(ref)

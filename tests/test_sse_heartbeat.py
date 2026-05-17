"""Heartbeat keepalive on the ``/api/ui/events`` SSE stream.

The previous implementation only emitted a ``: heartbeat`` comment line
*after* receiving a real event from the bus — so a fully silent bus
produced zero heartbeats and reverse proxies / browsers eventually
timed out the connection.

The fix extracts the streaming generator (``_events_stream``) so it can
wrap ``queue.get()`` in ``asyncio.wait_for(..., timeout=…)`` and yield
the heartbeat on ``TimeoutError``. We exercise it directly here rather
than through ``TestClient`` because httpx's ASGI transport buffers
streaming bodies — going end-to-end would hang waiting for EOF.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from ioc_tool.web import eventbus
from ioc_tool.web.api import _events_stream


@pytest.fixture(autouse=True)
def _isolate_bus():
    os.environ.pop("SHADOWSCOPE_API_TOKEN", None)
    eventbus.detach()
    yield
    eventbus.detach()


def _pull_n_frames(n: int, heartbeat_s: float = 0.05) -> list[str]:
    """Drive ``_events_stream`` for ``n`` frames then close it cleanly."""

    async def scenario() -> list[str]:
        eventbus.attach(asyncio.get_running_loop())
        agen = _events_stream(heartbeat_s=heartbeat_s)
        collected: list[str] = []
        try:
            for _ in range(n):
                frame = await asyncio.wait_for(agen.__anext__(), timeout=2.0)
                collected.append(frame)
        finally:
            await agen.aclose()
        return collected

    return asyncio.run(scenario())


def test_heartbeat_emitted_when_bus_is_silent():
    """With no events published, a ``: heartbeat`` comment must arrive.

    We pull three frames: the greeting + (at least) two heartbeat
    comments. The second comment proves the keepalive fires repeatedly,
    not just once.
    """
    frames = _pull_n_frames(3, heartbeat_s=0.05)
    assert len(frames) == 3
    # Greeting frame survives.
    assert "shadowscope-events" in frames[0]
    assert "event: hello" in frames[0]
    # And both subsequent frames are heartbeats — no events were
    # published, so the timeout branch must have produced them.
    assert frames[1] == ": heartbeat\n\n"
    assert frames[2] == ": heartbeat\n\n"


def test_real_event_preempts_heartbeat():
    """A published event arrives ahead of the next heartbeat tick.

    ``publish`` hops through ``call_soon_threadsafe`` even when called
    from the loop's own thread, so we yield once with ``asyncio.sleep(0)``
    after publishing to let the scheduled ``_put`` callback land in the
    subscriber queue before we ``__anext__`` for the second frame.
    """

    async def scenario() -> list[str]:
        eventbus.attach(asyncio.get_running_loop())
        agen = _events_stream(heartbeat_s=5.0)  # long enough not to fire
        collected: list[str] = []
        try:
            # Greeting first.
            collected.append(
                await asyncio.wait_for(agen.__anext__(), timeout=2.0)
            )
            # Publish, then yield so call_soon_threadsafe drains.
            eventbus.publish("score", {"ioc": "evil.example", "score": 80})
            await asyncio.sleep(0.01)
            collected.append(
                await asyncio.wait_for(agen.__anext__(), timeout=2.0)
            )
        finally:
            await agen.aclose()
        return collected

    frames = asyncio.run(scenario())
    assert "shadowscope-events" in frames[0]
    # Real event landed as the second frame, not a heartbeat.
    assert frames[1].startswith("event: score\n")
    assert "evil.example" in frames[1]
    assert "heartbeat" not in frames[1]


def test_heartbeat_constant_overridable_via_env(monkeypatch):
    """``SHADOWSCOPE_SSE_HEARTBEAT_S`` controls the keepalive cadence.

    The module reads the env var at import time with a default of
    25.0. A drift here would silently change proxy-keepalive behaviour
    in production.
    """
    import importlib

    from ioc_tool.web import api as api_mod

    monkeypatch.delenv("SHADOWSCOPE_SSE_HEARTBEAT_S", raising=False)
    reloaded = importlib.reload(api_mod)
    assert reloaded._SSE_HEARTBEAT_S == 25.0

    monkeypatch.setenv("SHADOWSCOPE_SSE_HEARTBEAT_S", "1.5")
    reloaded = importlib.reload(api_mod)
    assert reloaded._SSE_HEARTBEAT_S == 1.5

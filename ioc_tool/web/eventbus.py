"""In-process event bus for the SSE stream at ``/api/ui/events``.

The dashboard's Watch tab and AlertTicker previously polled
``/api/ui/recent`` on an 8 s timer. With this bus, enrichment writes
can fan out to connected dashboards in near-real-time without changing
the underlying SQLite-cache contract.

Design:

* **publish(event_type, payload)** is a *sync* function so it can be
  called from the existing enrichment hot path (``update_last_score``,
  ``add_enrichment``) without forcing those callers to be async. It
  routes the event to every async subscriber via
  ``asyncio.run_coroutine_threadsafe`` against the running event loop
  captured by ``attach(loop)`` at app startup.

* **subscribe()** is an async generator yielding events in order. Each
  subscriber gets its own bounded ``asyncio.Queue`` (drops oldest on
  overflow rather than blocking the publisher — keeping the enrichment
  pipeline fast is more important than perfect delivery to a stalled
  dashboard).

* When no loop is attached (e.g. ShadowScope CLI, no web server
  running), ``publish`` is a quiet no-op so the enrichment path
  never blocks or raises.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator
from typing import Any

# Queue depth per subscriber. 64 events is enough for a slow client to
# survive a short stall without losing the last enrichment burst, but
# small enough that a totally dead client can't grow an unbounded
# backlog.
_QUEUE_MAX = 64

_loop: asyncio.AbstractEventLoop | None = None
_subscribers: set[asyncio.Queue] = set()


def attach(loop: asyncio.AbstractEventLoop) -> None:
    """Bind the bus to the FastAPI event loop. Called once at startup."""
    global _loop
    _loop = loop


def detach() -> None:
    """Reset bus state. Useful in tests."""
    global _loop
    _loop = None
    _subscribers.clear()


def _put(queue: asyncio.Queue, event: dict[str, Any]) -> None:
    """Drop-oldest enqueue. Keeps publishers fast, prefers liveness over delivery."""
    if queue.full():
        with contextlib.suppress(asyncio.QueueEmpty):
            queue.get_nowait()
    queue.put_nowait(event)


def publish(event_type: str, payload: dict[str, Any]) -> None:
    """Broadcast an event to every active subscriber. Safe from any thread.

    Returns immediately. If no loop is attached or there are no
    subscribers, this is a no-op.
    """
    if _loop is None or not _subscribers:
        return
    event = {
        "type": event_type,
        "ts": int(time.time() * 1000),
        "data": payload,
    }
    for queue in list(_subscribers):
        # Hop into the loop's thread so the bounded queue operations
        # happen on the same thread that owns the queue.
        try:
            _loop.call_soon_threadsafe(_put, queue, event)
        except RuntimeError:
            # Loop closed mid-broadcast — drop the event silently.
            continue


async def subscribe() -> AsyncIterator[dict[str, Any]]:
    """Stream events to one client. Yields until the consumer disconnects."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=_QUEUE_MAX)
    _subscribers.add(queue)
    try:
        while True:
            event = await queue.get()
            yield event
    finally:
        _subscribers.discard(queue)


def subscriber_count() -> int:
    """Expose the live subscriber count for debugging / health checks."""
    return len(_subscribers)

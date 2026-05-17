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
import threading
import time
from collections.abc import AsyncIterator, Callable
from typing import Any

# Queue depth per subscriber. 64 events is enough for a slow client to
# survive a short stall without losing the last enrichment burst, but
# small enough that a totally dead client can't grow an unbounded
# backlog.
_QUEUE_MAX = 64

_loop: asyncio.AbstractEventLoop | None = None
_subscribers: set[asyncio.Queue] = set()
# ``publish`` runs from worker threads (enrichment hot path) while
# ``subscribe``/``unsubscribe`` mutate ``_subscribers`` from the event-loop
# thread. CPython protects individual set ops, but iterating ``list(set)``
# during a concurrent ``add``/``discard`` can drop or double-yield items.
# This lock guards mutation + snapshot copy. We intentionally do NOT hold
# it while issuing ``call_soon_threadsafe`` / ``put_nowait`` to avoid
# extending the critical section across an event-loop hop.
_subscribers_lock = threading.Lock()


def attach(loop: asyncio.AbstractEventLoop) -> None:
    """Bind the bus to the FastAPI event loop. Called once at startup."""
    global _loop
    _loop = loop


def detach() -> None:
    """Reset bus state. Useful in tests."""
    global _loop
    _loop = None
    with _subscribers_lock:
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
    if _loop is None:
        return
    # Snapshot subscribers under the lock so we don't iterate a set that
    # subscribe()/unsubscribe() are mutating from the event-loop thread.
    # We release the lock before issuing call_soon_threadsafe — holding
    # it across an event-loop hop would serialize publishers.
    with _subscribers_lock:
        if not _subscribers:
            return
        snapshot = list(_subscribers)
    event = {
        "type": event_type,
        "ts": int(time.time() * 1000),
        "data": payload,
    }
    for queue in snapshot:
        # Hop into the loop's thread so the bounded queue operations
        # happen on the same thread that owns the queue.
        try:
            _loop.call_soon_threadsafe(_put, queue, event)
        except RuntimeError:
            # Loop closed mid-broadcast — drop the event silently.
            continue


async def subscribe() -> AsyncIterator[dict[str, Any]]:
    """Stream events to one client. Yields until the consumer disconnects.

    Note: this generator blocks on ``queue.get()`` with no timeout, which
    means a silent bus would leave the consumer waiting forever. SSE
    consumers that need periodic keepalive frames should use
    :func:`open_subscription` and drive the queue.get/timeout loop
    themselves.
    """
    queue, _release = open_subscription()
    try:
        while True:
            event = await queue.get()
            yield event
    finally:
        _release()


def open_subscription() -> tuple[asyncio.Queue, Callable[[], None]]:
    """Register a new subscriber and return its queue + cleanup callable.

    Lower-level than :func:`subscribe` — exposes the underlying queue so
    callers (e.g. the SSE stream) can wrap ``queue.get()`` in
    ``asyncio.wait_for`` to emit heartbeats between real events.

    The returned cleanup callable is idempotent; call it from a
    ``finally`` (or via :class:`contextlib.closing`) to unregister.
    """
    queue: asyncio.Queue = asyncio.Queue(maxsize=_QUEUE_MAX)
    with _subscribers_lock:
        _subscribers.add(queue)

    released = False

    def _release() -> None:
        nonlocal released
        if released:
            return
        released = True
        with _subscribers_lock:
            _subscribers.discard(queue)

    return queue, _release


def subscriber_count() -> int:
    """Expose the live subscriber count for debugging / health checks."""
    with _subscribers_lock:
        return len(_subscribers)

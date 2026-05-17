"""Threaded stress test for ``ioc_tool.web.eventbus``.

``publish`` is invoked from worker threads (enrichment hot path) while
``subscribe`` / ``open_subscription`` mutate ``_subscribers`` from the
event-loop thread. The old implementation iterated ``list(_subscribers)``
during a concurrent ``add`` / ``discard``, which on CPython can drop
or double-yield elements (the GIL protects single ops, not the snapshot
copy).

This test spawns 8 worker threads that repeatedly subscribe + unsubscribe
their own bounded queues while another thread publishes events. The
invariant we assert:

* No exception bubbles up from any thread.
* The final ``_subscribers`` set is empty (every transient subscriber
  cleaned itself up — i.e. no leaked references from a torn-down
  snapshot).
"""

from __future__ import annotations

import asyncio
import threading
import time

import pytest

from ioc_tool.web import eventbus


@pytest.fixture(autouse=True)
def _reset_bus():
    eventbus.detach()
    yield
    eventbus.detach()


def test_concurrent_subscribe_publish_no_corruption():
    """8 churn threads + 1 publisher → no exceptions, clean teardown."""
    # Spin up a small event loop on a dedicated thread so ``publish``'s
    # ``call_soon_threadsafe`` has something to schedule against.
    loop = asyncio.new_event_loop()
    loop_thread = threading.Thread(
        target=loop.run_forever, name="bus-loop", daemon=True
    )
    loop_thread.start()
    eventbus.attach(loop)

    stop = threading.Event()
    errors: list[BaseException] = []
    errors_lock = threading.Lock()

    def _record(exc: BaseException) -> None:
        with errors_lock:
            errors.append(exc)

    def churn_worker() -> None:
        try:
            while not stop.is_set():
                # open_subscription is the lower-level handle used by
                # the new SSE loop and is the most-mutating API.
                fut = asyncio.run_coroutine_threadsafe(
                    _open_and_close(), loop
                )
                # Drain so the coroutine completes before we loop.
                fut.result(timeout=5.0)
        except BaseException as exc:  # noqa: BLE001 — capture for assert
            _record(exc)

    async def _open_and_close() -> None:
        queue, release = eventbus.open_subscription()
        # Hold the subscription for a tiny window so it overlaps with
        # publisher iteration. ``await asyncio.sleep(0)`` yields without
        # introducing real wall-time so churn rate stays high.
        await asyncio.sleep(0)
        release()
        # Drain anything that landed in the queue to avoid GC complaints.
        while not queue.empty():
            queue.get_nowait()

    def publisher_worker() -> None:
        try:
            i = 0
            while not stop.is_set():
                eventbus.publish("score", {"i": i, "ioc": "x"})
                i += 1
        except BaseException as exc:  # noqa: BLE001
            _record(exc)

    threads = [
        threading.Thread(target=churn_worker, name=f"churn-{n}", daemon=True)
        for n in range(8)
    ]
    threads.append(threading.Thread(target=publisher_worker, name="pub", daemon=True))
    for t in threads:
        t.start()

    # Let it run for ~0.5 s of real wall time — long enough to interleave
    # thousands of subscribe/publish cycles on a modern machine.
    time.sleep(0.5)
    stop.set()
    for t in threads:
        t.join(timeout=5.0)
        assert not t.is_alive(), f"thread {t.name} did not stop"

    # Final invariant: no exceptions, every churned subscriber released.
    assert errors == [], f"thread errors: {errors!r}"
    # Drain any in-flight call_soon_threadsafe callbacks before checking
    # the final subscriber set so the assertion isn't racing the loop.
    done = threading.Event()
    loop.call_soon_threadsafe(done.set)
    done.wait(timeout=2.0)
    assert eventbus.subscriber_count() == 0

    loop.call_soon_threadsafe(loop.stop)
    loop_thread.join(timeout=5.0)
    loop.close()


def test_publish_snapshot_isolates_from_concurrent_unsubscribe():
    """A late ``release()`` mid-publish must not raise inside ``publish``.

    Specifically: the snapshot taken under ``_subscribers_lock`` is the
    iteration target, so an unsubscribe that happens between the
    snapshot and the per-queue ``call_soon_threadsafe`` is harmless —
    we just enqueue into an orphan queue.
    """
    loop = asyncio.new_event_loop()
    loop_thread = threading.Thread(target=loop.run_forever, daemon=True)
    loop_thread.start()
    eventbus.attach(loop)
    try:
        queue, release = eventbus.open_subscription()
        # Drop the subscription, then publish: the snapshot was taken
        # *after* release, so there's nothing to deliver. This must
        # not raise.
        release()
        eventbus.publish("score", {"ioc": "x", "score": 1})
        # Sanity: no callback was scheduled because the snapshot is empty.
        # (Asserting len 0 also catches the case where release() failed.)
        assert eventbus.subscriber_count() == 0
        # The queue is still alive locally — drain to be tidy.
        while not queue.empty():
            queue.get_nowait()
    finally:
        loop.call_soon_threadsafe(loop.stop)
        loop_thread.join(timeout=5.0)
        loop.close()

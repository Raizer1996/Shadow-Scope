"""In-process event bus tests.

Cover three concerns:

1. ``publish`` without an attached loop / without subscribers is a quiet
   no-op (the enrichment hot path must never blow up).
2. With a loop attached and one subscriber, a published event is
   delivered to ``subscribe`` exactly once.
3. Drop-oldest backpressure: a full queue evicts the oldest event
   rather than blocking the publisher.

Note: we drive the async paths via ``asyncio.run`` rather than the
``pytest-asyncio`` plugin to avoid adding a dev dependency for these
handful of tests.
"""

from __future__ import annotations

import asyncio

import pytest

from ioc_tool.web import eventbus


@pytest.fixture(autouse=True)
def _reset_bus():
    """Reset module state between tests so they don't leak loop refs."""
    eventbus.detach()
    yield
    eventbus.detach()


def test_publish_no_loop_is_noop():
    eventbus.publish("score", {"ioc": "evil.example", "score": 80})
    assert eventbus.subscriber_count() == 0


def test_publish_delivers_to_subscriber():
    received: list[dict] = []

    async def scenario():
        eventbus.attach(asyncio.get_running_loop())
        stop = asyncio.Event()

        async def reader():
            async for event in eventbus.subscribe():
                received.append(event)
                stop.set()
                return

        task = asyncio.create_task(reader())
        await asyncio.sleep(0)
        eventbus.publish("score", {"ioc": "evil.example", "score": 80})
        await asyncio.wait_for(stop.wait(), timeout=1.0)
        task.cancel()

    asyncio.run(scenario())
    assert received[0]["type"] == "score"
    assert received[0]["data"] == {"ioc": "evil.example", "score": 80}
    assert isinstance(received[0]["ts"], int)


def test_drop_oldest_when_queue_full():
    async def scenario():
        eventbus.attach(asyncio.get_running_loop())
        queue: asyncio.Queue = asyncio.Queue(maxsize=2)
        eventbus._subscribers.add(queue)
        try:
            for i in range(5):
                eventbus._put(queue, {"type": "score", "ts": i, "data": {"i": i}})
            assert queue.qsize() == 2
            first = await queue.get()
            second = await queue.get()
            # Drop-oldest semantics: only the two most-recent events survive.
            assert first["data"]["i"] == 3
            assert second["data"]["i"] == 4
        finally:
            eventbus._subscribers.discard(queue)

    asyncio.run(scenario())


def test_subscriber_count_tracks_registration():
    async def scenario():
        eventbus.attach(asyncio.get_running_loop())
        assert eventbus.subscriber_count() == 0

        agen = eventbus.subscribe()
        # Pull one tick so the generator actually registers itself with
        # the bus (first ``async for`` iteration runs the head of the
        # body up to the first ``await``).
        peek = asyncio.create_task(agen.__anext__())
        await asyncio.sleep(0)
        assert eventbus.subscriber_count() == 1

        eventbus.publish("score", {"ioc": "x", "score": 0})
        event = await asyncio.wait_for(peek, timeout=1.0)
        assert event["data"]["ioc"] == "x"

        # Explicitly close the generator so the finally block fires
        # deterministically before we check the unregister.
        await agen.aclose()
        assert eventbus.subscriber_count() == 0

    asyncio.run(scenario())

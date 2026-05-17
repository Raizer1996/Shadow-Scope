"""Threaded contention tests for :class:`ioc_tool.core.ratelimit.Bucket`.

The previous bucket implementation released the underlying lock inside a
``with self.lock:`` block (so it could sleep while waiting for refill).
Under contention the context manager would then call ``release()`` a
second time on exit, raising ``RuntimeError: release unlocked lock`` —
not deterministically, but often enough to surface in a 16-thread race.

The refactor uses a :class:`threading.Condition` so the lock lifetime
is managed by the ``with`` block and waits use ``cond.wait()`` (atomic
release + re-acquire on wakeup). These tests fire many threads at a
small-capacity bucket and assert:

* No exception escapes any worker.
* Every thread eventually acquires a token (no deadlocks, no spurious
  refusals before the deadline).
* The total throughput is bounded by the bucket's refill rate (sanity
  check that we didn't turn the limiter into a no-op while fixing the
  lock).
"""

from __future__ import annotations

import threading
import time

from ioc_tool.core import ratelimit


def _isolated_bucket(monkeypatch, *, capacity: float, period: float) -> ratelimit.Bucket:
    """Drop the conftest's session-level disable flag for the duration
    of this test and return a freshly-constructed bucket so test isolation
    is total.
    """
    monkeypatch.delenv("RATELIMIT_VIRUSTOTAL_DISABLE", raising=False)
    ratelimit.reset()
    return ratelimit.Bucket(
        capacity=capacity,
        refill_per_sec=capacity / period,
    )


def test_threaded_acquire_no_runtime_error(monkeypatch):
    """16 threads race for a small bucket: nobody crashes, everyone
    eventually acquires.

    The historical bug — ``RuntimeError: release unlocked lock`` —
    surfaces probabilistically under contention. We over-engineer
    the contention to maximise the chance of hitting it if the
    regression returns: 16 workers and a capacity well below the
    worker count so most of them must block on the wait path.
    """
    bucket = _isolated_bucket(monkeypatch, capacity=2, period=0.2)

    n_threads = 16
    deadline_s = 6.0
    barrier = threading.Barrier(n_threads)
    errors: list[BaseException] = []
    acquired: list[int] = []
    errors_lock = threading.Lock()
    acquired_lock = threading.Lock()

    def worker(idx: int) -> None:
        try:
            barrier.wait(timeout=deadline_s)
            ok = bucket.acquire(timeout=deadline_s)
            assert ok, f"worker {idx} failed to acquire within deadline"
            with acquired_lock:
                acquired.append(idx)
        except BaseException as exc:  # noqa: BLE001 — capture for assert below
            with errors_lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=deadline_s + 2.0)

    # No thread should still be alive after the deadline.
    for t in threads:
        assert not t.is_alive(), "deadlock — at least one worker never returned"

    # Crucially: no RuntimeError (or anything else) escaped a worker.
    assert errors == [], f"workers raised: {[repr(e) for e in errors]}"

    # All threads eventually acquired — that's the contract.
    assert len(acquired) == n_threads


def test_threaded_throughput_bounded_by_refill(monkeypatch):
    """Sanity check: the limiter still limits.

    With a 2 token / 0.2 s bucket and 8 threads each demanding 1 token,
    the wall-clock for all 8 must be at least ``(8 - 2) / 10 = 0.6 s``
    (we already hold the burst capacity; the rest refills at 10 tok/s).
    A loose lower bound — we just need to confirm the limiter isn't
    accidentally a no-op after the Condition refactor.
    """
    bucket = _isolated_bucket(monkeypatch, capacity=2, period=0.2)

    n_threads = 8
    start = threading.Barrier(n_threads + 1)

    def worker() -> None:
        start.wait(timeout=2.0)
        bucket.acquire(timeout=10.0)

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    t0 = time.monotonic()
    start.wait(timeout=2.0)
    for t in threads:
        t.join(timeout=10.0)
    elapsed = time.monotonic() - t0

    # Refill rate = capacity / period = 10/sec. After consuming the 2-token
    # burst, the remaining 6 acquires need >= 0.6 s of refill. Allow a
    # generous floor of 0.3 s to keep CI green on slow runners while still
    # catching a fully-broken limiter (which would finish in <50 ms).
    assert elapsed >= 0.3, f"limiter throughput too high — got {elapsed:.3f}s"


def test_threaded_timeout_still_returns_false(monkeypatch):
    """A bone-dry bucket with a tight timeout must still refuse, not hang."""
    bucket = _isolated_bucket(monkeypatch, capacity=1, period=60.0)

    # Drain the initial token.
    assert bucket.acquire(timeout=0.5) is True

    errors: list[BaseException] = []
    results: list[bool] = []
    lock = threading.Lock()

    def worker() -> None:
        try:
            ok = bucket.acquire(timeout=0.1)
            with lock:
                results.append(ok)
        except BaseException as exc:  # noqa: BLE001
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=2.0)

    assert errors == []
    # Every refusal should be a clean ``False`` — no thread hung past the
    # timeout, none returned ``True`` (would imply the bucket gave out a
    # token we know isn't there yet).
    assert results == [False] * 4

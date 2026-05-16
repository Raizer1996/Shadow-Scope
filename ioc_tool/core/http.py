"""Rate-limited HTTP helper shared by enrichment modules.

Wraps ``requests.get`` (and friends) with three behaviours:

* **Token-bucket gating** via :mod:`ioc_tool.core.ratelimit`. Each call
  acquires a token keyed on ``source_key`` before issuing the request;
  if the bucket is exhausted the helper sleeps until a token regenerates.
* **429 retry-after handling**. If the server still returns 429 (the
  bucket guessed wrong) the helper honours the ``Retry-After`` header
  for a single retry, capped at 30 s to avoid pathological waits.
* **Timeout default**. Every request gets a 15 s timeout unless the
  caller overrides — keeps a stalled upstream from blocking the whole
  enrichment fan-out.

Modules opt in incrementally: replace ``requests.get(...)`` with
``http.get(source_key, ...)``. The helper returns the underlying
``requests.Response`` so existing call-sites need no further changes.
"""

from __future__ import annotations

from typing import Any

import requests

from . import ratelimit

_DEFAULT_TIMEOUT_S = 15.0
_MAX_RETRY_AFTER_S = 30.0


def _parse_retry_after(value: str | None) -> float | None:
    """Best-effort Retry-After parser. Returns seconds-to-wait or ``None``."""
    if not value:
        return None
    try:
        seconds = float(value)
        if seconds < 0:
            return None
        return min(seconds, _MAX_RETRY_AFTER_S)
    except ValueError:
        # HTTP-date variants are rare on the APIs we hit — skip.
        return None


def request(
    source_key: str,
    method: str,
    url: str,
    *,
    timeout: float | None = None,
    rate_timeout: float = 30.0,
    **kwargs: Any,
) -> requests.Response | None:
    """Issue an HTTP request through the per-source bucket.

    Returns the ``Response`` on success, ``None`` when the bucket
    refused to hand out a token within ``rate_timeout`` or the request
    raised. The 429 retry path honours ``Retry-After`` once before
    giving up.
    """
    if not ratelimit.acquire(source_key, timeout=rate_timeout):
        return None
    if timeout is None:
        timeout = _DEFAULT_TIMEOUT_S
    try:
        response = requests.request(method, url, timeout=timeout, **kwargs)
    except requests.RequestException:
        return None
    if response.status_code != 429:
        return response

    # One retry after honouring Retry-After.
    wait = _parse_retry_after(response.headers.get("Retry-After")) or 1.0
    import time as _time
    _time.sleep(wait)
    # Acquire again — we already consumed a token, but the upstream
    # disagrees, so wait for a fresh token before the retry.
    if not ratelimit.acquire(source_key, timeout=rate_timeout):
        return response  # return the 429 so the caller can short-circuit
    try:
        return requests.request(method, url, timeout=timeout, **kwargs)
    except requests.RequestException:
        return None


def get(source_key: str, url: str, **kwargs: Any) -> requests.Response | None:
    return request(source_key, "GET", url, **kwargs)


def post(source_key: str, url: str, **kwargs: Any) -> requests.Response | None:
    return request(source_key, "POST", url, **kwargs)

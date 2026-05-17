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

import ipaddress
import os
import sys
from contextvars import ContextVar
from typing import Any
from urllib.parse import urlparse

import requests

from . import ratelimit

_DEFAULT_TIMEOUT_S = 15.0
_MAX_RETRY_AFTER_S = 30.0
# Re-acquire timeout for the 429 retry path. Kept deliberately short so a
# starved bucket can't pin a worker re-waiting for a token that won't come
# in time — better to soft-fail and let the orchestrator's failover hook
# substitute a sibling provider.
_RETRY_RATE_TIMEOUT_S = 5.0


# Per-task rate-limit ledger. The orchestrator (``core.enrich``) sets a
# fresh dict in this context before fanning out sources; each ``request()``
# call records ``source_key`` into the dict when the upstream rejects it
# with a 429 we couldn't escape via retry, OR when our own token bucket
# refused to hand out a token within ``rate_timeout``.
#
# Why a ContextVar rather than a module-global set: a ContextVar is
# preserved across ``asyncio.to_thread`` boundaries (the orchestrator
# already relies on this for ``no_cache_ctx``) yet is isolated per task,
# so concurrent ``enrich_many_async`` invocations don't cross-contaminate.
#
# Default ``None`` means "no ledger active" — the helper records nothing,
# preserving the historical zero-bookkeeping fast path for callers outside
# the orchestrator (ad-hoc scripts, tests of unrelated modules, etc.).
rate_limited_ctx: ContextVar[set[str] | None] = ContextVar(
    "rate_limited_ctx", default=None
)


def _mark_rate_limited(source_key: str) -> None:
    """Record that ``source_key`` was rate-limited in the active ledger."""
    ledger = rate_limited_ctx.get()
    if ledger is not None:
        ledger.add(source_key)


def was_rate_limited(source_key: str) -> bool:
    """Return ``True`` iff the active ledger has flagged ``source_key``."""
    ledger = rate_limited_ctx.get()
    return ledger is not None and source_key in ledger


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
        # Local bucket said no — observationally equivalent to a 429 from
        # the upstream, so record it in the ledger for the orchestrator's
        # failover hook.
        _mark_rate_limited(source_key)
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
    #
    # The upstream's 429 means our local bucket guessed wrong — the
    # token we already consumed didn't translate into a successful
    # call. Before re-issuing we MUST acquire a fresh token from the
    # local bucket so the retry doesn't double-spend (one upstream
    # attempt per local token, otherwise we burn the analyst's free-
    # tier quota twice per "logical request").
    #
    # Use a deliberately short re-acquire timeout (``_RETRY_RATE_TIMEOUT_S``)
    # so a starved bucket short-circuits the retry instead of busy-
    # waiting — the failover hook in ``core.enrich`` can then substitute
    # a sibling provider transparently.
    wait = _parse_retry_after(response.headers.get("Retry-After")) or 1.0
    import time as _time
    _time.sleep(wait)
    if not ratelimit.acquire(source_key, timeout=_RETRY_RATE_TIMEOUT_S):
        # Bucket refused — give up gracefully. We flag the source for
        # the orchestrator's failover hook and return ``None`` (NOT the
        # 429 response) so the caller treats this as no-data, identical
        # to a regular bucket starvation. Returning the 429 here would
        # leak the upstream's error body downstream and break the
        # "soft-fail to None" contract callers rely on.
        _mark_rate_limited(source_key)
        return None
    try:
        retry_response = requests.request(method, url, timeout=timeout, **kwargs)
    except requests.RequestException:
        return None
    if retry_response.status_code == 429:
        # Even the retry got throttled — flag the source so the
        # orchestrator can transparently fall back to a sibling provider.
        _mark_rate_limited(source_key)
    return retry_response


def get(source_key: str, url: str, **kwargs: Any) -> requests.Response | None:
    return request(source_key, "GET", url, **kwargs)


def post(source_key: str, url: str, **kwargs: Any) -> requests.Response | None:
    return request(source_key, "POST", url, **kwargs)


# ---------------------------------------------------------------------------
# Shared outbound-webhook helper
# ---------------------------------------------------------------------------
#
# Both ``shadowscope enrich --webhook=URL`` and ``shadowscope watch
# --webhook=URL`` POST a JSON payload to an arbitrary external endpoint
# (SIEM intake, ticketing webhook, IR pager, etc.). They share the same
# "fire-and-forget, soft-fail" contract:
#
#   * never raise — the CLI must keep emitting IOC output even when the
#     receiver is down
#   * default to a short timeout (5 s) so a hanging endpoint can't stall
#     the enrichment fan-out
#   * route through the rate-limited :func:`post` so a noisy receiver
#     can't get hammered by a 10k-IOC bulk run
#
# ``post_webhook`` returns ``True`` on a 2xx response, ``False``
# otherwise; callers can use the return value to emit a single stderr
# warning per failure.
#
# SSRF defence — the helper rejects URLs that would let an attacker (or a
# misconfigured config file) pivot off the ShadowScope host into private
# / cloud-metadata / loopback space:
#
#   * scheme must be http or https (no file://, gopher://, etc.)
#   * if the host parses as a literal IPv4/IPv6, it must NOT be in any
#     private, loopback, or link-local range
#
# Hostnames are accepted as-is in v1 — a future TOCTOU-safe revision can
# resolve them at request time and re-check. The env-var escape hatch
# ``SHADOWSCOPE_WEBHOOK_ALLOW_PRIVATE=1`` skips the private-IP gate for
# internal SIEM / on-prem ticketing endpoints that legitimately live in
# RFC1918 space.
_WEBHOOK_TIMEOUT_S = 5.0
_WEBHOOK_ALLOWED_SCHEMES = frozenset({"http", "https"})


def _webhook_allow_private() -> bool:
    """Return True iff the operator opted in to private-IP webhook targets."""
    return os.getenv("SHADOWSCOPE_WEBHOOK_ALLOW_PRIVATE", "").strip() in (
        "1", "true", "yes", "on",
    )


def _validate_webhook_url(url: str) -> str | None:
    """Return a rejection reason, or ``None`` if the URL is acceptable.

    Cheap stdlib-only check: scheme + literal-IP range. Hostnames are
    pass-through in v1 (no DNS resolution); the caller is trusting the
    operator-supplied config for those.
    """
    if not isinstance(url, str) or not url:
        return "empty url"
    try:
        parsed = urlparse(url)
    except ValueError:
        return "unparseable url"
    scheme = (parsed.scheme or "").lower()
    if scheme not in _WEBHOOK_ALLOWED_SCHEMES:
        return f"disallowed scheme {scheme!r}"
    host = parsed.hostname
    if not host:
        return "missing host"
    # Literal IP check. Hostnames return ValueError from ip_address and
    # are accepted as-is (v1 contract — see docstring).
    if _webhook_allow_private():
        return None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_reserved
        or ip.is_multicast
    ):
        return f"private/loopback/link-local IP {host!r}"
    return None


def post_webhook(
    url: str,
    payload: Any,
    *,
    timeout: float = _WEBHOOK_TIMEOUT_S,
    source_key: str = "webhook",
) -> bool:
    """POST ``payload`` as JSON to ``url``. Returns ``True`` on 2xx.

    Soft-fails on any error (timeout, connection refused, non-2xx,
    rate-limiter starvation, SSRF-policy rejection) and returns ``False``
    — never raises. Rejected URLs are surfaced to stderr so operators can
    spot misconfigured webhook targets without changing the soft-fail
    contract.
    """
    reason = _validate_webhook_url(url)
    if reason is not None:
        print(f"webhook URL rejected: {reason}", file=sys.stderr)
        return False
    try:
        response = post(source_key, url, json=payload, timeout=timeout)
    except Exception:
        return False
    if response is None:
        return False
    return 200 <= response.status_code < 300

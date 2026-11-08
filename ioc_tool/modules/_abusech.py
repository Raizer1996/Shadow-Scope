"""Shared auth for the abuse.ch query APIs (URLhaus, ThreatFox, MalwareBazaar).

Since abuse.ch's "Community First" change every query API call must carry
an ``Auth-Key`` header; requests without one answer ``401 Unauthorized``.
One key, generated once at https://auth.abuse.ch/, covers all platforms.
The bulk feeds (Feodo Tracker, SSL Blacklist) stay unauthenticated.

Env: ``ABUSECH_AUTH_KEY``. When it is missing the three modules return
``None`` without issuing a request — same outcome as the 401, minus the
wasted round-trip and the misleading "source queried" impression.
"""

from __future__ import annotations

import os

ENV_VAR = "ABUSECH_AUTH_KEY"


def api_key() -> str:
    return os.getenv(ENV_VAR, "").strip()


def configured() -> bool:
    return bool(api_key())


def auth_headers() -> dict[str, str]:
    """``{"Auth-Key": ...}`` or ``{}`` when no key is set."""
    key = api_key()
    return {"Auth-Key": key} if key else {}

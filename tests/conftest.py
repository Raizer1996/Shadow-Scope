"""Shared pytest fixtures.

The session-level autouse fixture below disables every per-source rate
limit while the suite runs. Bucket gating is correctness-irrelevant for
the existing module tests (which mock the HTTP layer via ``responses``),
and leaving the buckets active makes the suite stall in ratelimit sleeps
when tests fire many enrichments back-to-back.

Tests that specifically exercise the rate-limit logic re-enable it
locally via the ``ioc_tool.core.ratelimit`` API.
"""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True, scope="session")
def _disable_rate_limits():
    """Flag every known source as rate-limit-disabled for the test run."""
    keys = (
        "VIRUSTOTAL", "ABUSEIPDB", "IPQS", "SHODAN", "OTX",
        "URLSCAN", "PULSEDIVE", "GREYNOISE", "ABSTRACT", "CENSYS",
    )
    saved: dict[str, str | None] = {}
    for key in keys:
        env_key = f"RATELIMIT_{key}_DISABLE"
        saved[env_key] = os.environ.get(env_key)
        os.environ[env_key] = "1"
    yield
    for env_key, prev in saved.items():
        if prev is None:
            os.environ.pop(env_key, None)
        else:
            os.environ[env_key] = prev

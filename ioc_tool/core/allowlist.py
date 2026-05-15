"""IOC allowlist — skip enrichment for known-internal / trusted indicators.

Reads ``ALLOWLIST_CIDRS`` and ``ALLOWLIST_DOMAINS`` from the env. When
an incoming IOC matches an allowlist entry the orchestrator emits a
short-circuit result dict with score 0 and skips every external source
— useful for batch enrichment where most of the input is your own
infrastructure (corp CIDRs, internal hostnames) and you don't want to
burn API quota on it.

Match rules:

* ``ALLOWLIST_CIDRS=10.0.0.0/8,192.168.0.0/16,2001:db8::/32`` — IPv4 and
  IPv6 ranges. Matches when the input IP falls inside any range.
* ``ALLOWLIST_DOMAINS=corp.example.com,internal.lan`` — domain
  suffixes. Matches the exact domain or any subdomain
  (``api.corp.example.com`` → match for ``corp.example.com``).

Empty env / no match → ``None`` (no allowlist hit, proceed normally).
"""

from __future__ import annotations

import ipaddress
import os
from typing import Any


def _parse_cidrs() -> list[ipaddress._BaseNetwork]:
    """Parse ``ALLOWLIST_CIDRS`` into a list of network objects.

    Invalid entries are silently dropped so a typo in one CIDR doesn't
    disable the whole allowlist. We accept both IPv4 and IPv6.
    """
    raw = os.getenv("ALLOWLIST_CIDRS", "").strip()
    if not raw:
        return []
    networks: list[ipaddress._BaseNetwork] = []
    for entry in raw.split(","):
        cleaned = entry.strip()
        if not cleaned:
            continue
        try:
            networks.append(ipaddress.ip_network(cleaned, strict=False))
        except ValueError:
            continue
    return networks


def _parse_domains() -> list[str]:
    """Parse ``ALLOWLIST_DOMAINS`` into a list of lowercase domain suffixes."""
    raw = os.getenv("ALLOWLIST_DOMAINS", "").strip()
    if not raw:
        return []
    out: list[str] = []
    for entry in raw.split(","):
        cleaned = entry.strip().lower().rstrip(".")
        if cleaned and cleaned not in out:
            out.append(cleaned)
    return out


def is_allowlisted(value: str, ioc_type: str) -> dict[str, Any] | None:
    """Return a match-context dict when ``value`` is on the allowlist, else ``None``.

    Match contexts surface in the short-circuited result so analysts
    can see exactly which allowlist rule fired:

        {"reason": "cidr", "match": "10.0.0.0/8"}
        {"reason": "domain", "match": "corp.example.com"}
    """
    if ioc_type == "ip":
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return None
        for net in _parse_cidrs():
            if ip.version != net.version:
                continue
            if ip in net:
                return {"reason": "cidr", "match": str(net)}
        return None

    if ioc_type == "domain":
        target = value.strip().lower().rstrip(".")
        for suffix in _parse_domains():
            if target == suffix or target.endswith("." + suffix):
                return {"reason": "domain", "match": suffix}
        return None

    # URL: extract host and re-check against the domain allowlist.
    if ioc_type == "url":
        host = _extract_host(value)
        if host:
            return is_allowlisted(host, "domain")
        return None

    return None


def _extract_host(url: str) -> str | None:
    """Best-effort host extraction from a URL. Returns ``None`` if not parseable."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url if "://" in url else f"http://{url}")
        return parsed.hostname
    except (ValueError, TypeError):
        return None

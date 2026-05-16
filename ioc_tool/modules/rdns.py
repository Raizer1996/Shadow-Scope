"""Reverse DNS (PTR) lookup — info-only enrichment for IP IOCs.

Resolves the PTR record for an IP via stdlib ``socket.gethostbyaddr``.
Returns a small dict with the canonical hostname plus any aliases, or
``None`` when the lookup fails (NXDOMAIN, timeout, network error).

The signal value is contextual rather than scored:

* ``mail.example.com`` PTR on an IP showing as an open SMTP server is
  consistent and unremarkable.
* ``baseline-residential.isp.example.com`` PTR on an IP that's flagged
  by AbuseIPDB / IPQS pins it to a likely-compromised broadband host.
* ``-`` (no PTR) on a host claiming to be a service endpoint is itself
  a weak suspicion signal.

We deliberately keep this info-only — the analyst reads the hostname
and decides. Pushing a score from PTR alone produces too many false
positives (lots of legit servers have generic / no PTR).
"""

from __future__ import annotations

import socket
from typing import Any

# Cap the lookup latency. ``gethostbyaddr`` honors the socket default
# timeout on most platforms; setting it locally keeps a slow DNS server
# from stalling the whole enrichment fan-out.
_RDNS_TIMEOUT_S = 3.0


def enrich_ip(ip: str) -> dict[str, Any] | None:
    """Resolve PTR for ``ip``. Returns ``None`` when no record exists.

    Output schema::

        {
            "ptr": "host.example.com",
            "aliases": ["alias1.example.com", ...],  # may be empty
        }

    Failure modes (NXDOMAIN, socket error, timeout) collapse to ``None``
    so the orchestrator skips the row silently — same convention as the
    rest of the enrichment modules.
    """
    if not ip:
        return None

    # Snapshot + restore the global socket timeout so we don't leak the
    # short timeout into unrelated network calls happening concurrently.
    prev = socket.getdefaulttimeout()
    socket.setdefaulttimeout(_RDNS_TIMEOUT_S)
    try:
        hostname, aliases, _addrs = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(prev)

    if not hostname:
        return None

    return {"ptr": hostname, "aliases": list(aliases or [])}

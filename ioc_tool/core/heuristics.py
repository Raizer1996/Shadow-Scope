"""Local heuristics — score-bumping signals derived without external API calls.

Each heuristic consumes data already gathered by the enrichment pipeline
(WHOIS, the IOC string itself, env-configured watchlists) and returns a
structured ``dict`` plus an integer ``score`` in ``[0, 100]``. The
orchestrator (:func:`ioc_tool.core.enrich.enrich_ioc_async`) bundles the
active heuristics under a single ``Heuristics`` pseudo-module so they
appear alongside real sources in the output.

Heuristics are intentionally cheap (no I/O after the initial enrichment
batch finishes) and deterministic — useful both as risk amplifiers and
as analyst hints. Each function returns ``None`` when it has no signal
(e.g. NRD with no WHOIS creation date) so the orchestrator can skip the
entry silently.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

# ---------------------------------------------------------------------------
# NRD — Newly Registered Domain
# ---------------------------------------------------------------------------
#
# Domains < 30 days old are heavily abused for phishing and C2: most
# malicious infrastructure is registered within hours or days of the
# campaign that uses it. We piggyback on the WHOIS source's already-
# fetched ``creation_date`` rather than making a second lookup.
#
# Score mapping:
#   age < 7   → 95   (extremely fresh — strong signal)
#   age < 30  → 75   (newly registered — classic NRD bucket)
#   age < 90  → 40   (recent — mild signal, often abused but also legit)
#   age >= 90 → 0    (mature — no signal)


def nrd_check(creation_date: Any) -> dict | None:
    """Compute an NRD score from a WHOIS ``creation_date`` value.

    Accepts the same shapes the WHOIS module produces:
    :class:`datetime`, ISO-format ``str``, or a list of either (registrars
    occasionally return multiple). Returns ``None`` when no usable date is
    available — caller should treat that as "no signal" and skip the entry.
    """
    parsed = _coerce_to_datetime(creation_date)
    if parsed is None:
        return None

    age_days = (datetime.now() - parsed).days
    if age_days < 0:
        # Future-dated creation? Treat as unparseable rather than crashing.
        return None

    if age_days < 7:
        score = 95
        bucket = "fresh"
    elif age_days < 30:
        score = 75
        bucket = "nrd"
    elif age_days < 90:
        score = 40
        bucket = "recent"
    else:
        score = 0
        bucket = "mature"

    return {
        "score": score,
        "age_days": age_days,
        "bucket": bucket,
        "created": parsed.date().isoformat(),
    }


def _coerce_to_datetime(value: Any) -> datetime | None:
    """Best-effort conversion of WHOIS creation_date variants → datetime."""
    if value is None:
        return None
    if isinstance(value, list):
        if not value:
            return None
        value = value[0]
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None

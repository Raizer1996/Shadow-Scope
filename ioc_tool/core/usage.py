"""How many requests each source has been sent — the quota meter.

Every call that goes through :mod:`core.http` is counted per source and UTC
day in the local database (``api_usage``). Nothing here talks to a provider:
it is a local tally, so it only knows about requests made by *this* install.

Outcomes:

* ``ok``       — the source answered (any non-error status);
* ``limited``  — the source answered 429;
* ``failed``   — timeout, connection error, 5xx or an auth error;
* ``held``     — our own rate limiter refused to send it. Not counted as
  sent, because it never reached the provider.

Quotas are optional. A few well-known free-tier limits ship as defaults and
are labelled *assumed*; set ``SHADOWSCOPE_QUOTAS`` to state your real plan,
e.g. ``virustotal=500/day,shodan=100/month,abuseipdb=0`` (0 removes one).

Recording must never break an enrichment, so every failure is swallowed.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from . import database

OUTCOMES = ("ok", "limited", "failed", "held")
PERIODS = ("day", "month")
# Free-tier request limits that are stable and widely documented. Anything
# less certain is left out rather than guessed.
_DEFAULT_QUOTAS: dict[str, tuple[int, str]] = {
    "virustotal": (500, "day"),
    "abuseipdb": (1000, "day"),
    "ipinfo": (50000, "month"),
    "censys": (250, "month"),
}


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def enabled() -> bool:
    return os.getenv("SHADOWSCOPE_USAGE", "1").strip().lower() not in ("0", "false", "no", "off")


def record(source: str, outcome: str) -> None:
    """Count one request attempt. Silent on any error."""
    if outcome not in OUTCOMES or not source or not enabled():
        return
    # Never create a database as a side effect of an HTTP call.
    if not os.path.exists(database.DB_PATH):
        return
    try:
        conn = sqlite3.connect(database.DB_PATH, timeout=2.0)
        try:
            conn.execute(
                f"INSERT INTO api_usage (source, day, {outcome}) VALUES (?, ?, 1) "
                f"ON CONFLICT(source, day) DO UPDATE SET {outcome} = {outcome} + 1",
                (source, _today()),
            )
            conn.commit()
        finally:
            conn.close()
    except sqlite3.Error:
        return


def quotas() -> dict[str, dict[str, Any]]:
    """Effective quotas: defaults, overridden by ``SHADOWSCOPE_QUOTAS``."""
    out: dict[str, dict[str, Any]] = {
        src: {"limit": limit, "period": period, "assumed": True} for src, (limit, period) in _DEFAULT_QUOTAS.items()
    }
    for part in os.getenv("SHADOWSCOPE_QUOTAS", "").split(","):
        name, sep, spec = part.strip().partition("=")
        name = name.strip().lower()
        if not sep or not name:
            continue
        number, _, period = spec.strip().lower().partition("/")
        period = period.strip() or "day"
        try:
            limit = int(number)
        except ValueError:
            continue
        if limit <= 0:
            out.pop(name, None)
        elif period in PERIODS:
            out[name] = {"limit": limit, "period": period, "assumed": False}
    return out


def summary() -> dict[str, Any]:
    """Per-source counts for today, the last 7 days and this month (UTC)."""
    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")
    week_start = (now - timedelta(days=6)).strftime("%Y-%m-%d")
    month_start = now.strftime("%Y-%m-01")
    rows: list[Any] = []
    try:
        conn = database.get_db_connection()
        try:
            rows = conn.execute(
                "SELECT source, day, ok, limited, failed, held FROM api_usage WHERE day >= ? ORDER BY source",
                (min(week_start, month_start),),
            ).fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        rows = []

    per: dict[str, dict[str, Any]] = {}
    for r in rows:
        sent = int(r["ok"]) + int(r["limited"]) + int(r["failed"])
        s = per.setdefault(r["source"], {
            "source": r["source"], "today": 0, "week": 0, "month": 0,
            "limited_today": 0, "failed_today": 0, "held_today": 0, "last_limited": None,
        })
        if r["day"] >= week_start:
            s["week"] += sent
        if r["day"] >= month_start:
            s["month"] += sent
        if r["day"] == today:
            s["today"] = sent
            s["limited_today"] = int(r["limited"])
            s["failed_today"] = int(r["failed"])
            s["held_today"] = int(r["held"])
        if int(r["limited"]) and (s["last_limited"] is None or r["day"] > s["last_limited"]):
            s["last_limited"] = r["day"]

    limits = quotas()
    for name in limits:
        per.setdefault(name, {
            "source": name, "today": 0, "week": 0, "month": 0,
            "limited_today": 0, "failed_today": 0, "held_today": 0, "last_limited": None,
        })
    for name, s in per.items():
        q = limits.get(name)
        if q:
            used = s["today"] if q["period"] == "day" else s["month"]
            s["quota"] = {**q, "used": used, "left": max(0, q["limit"] - used),
                          "pct": min(100, round(100 * used / q["limit"]))}
        else:
            s["quota"] = None
    ordered = sorted(per.values(), key=lambda s: (-(s["quota"]["pct"] if s["quota"] else -1), -s["today"], s["source"]))
    return {"day": today, "enabled": enabled(), "sources": ordered}

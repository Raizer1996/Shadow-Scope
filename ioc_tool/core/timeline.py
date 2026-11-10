"""One chronological story per indicator. Cache-only.

Merges two kinds of dated facts into a single list:

* what the outside world reported — registration, first/last sightings,
  listings, publication dates — read from the cached source answers;
* what happened here — first enrichment, score changes, verdicts, notes,
  case/tag assignments, watchlist activity.

Every event carries a UTC timestamp. Dates a source gave without a time are
flagged ``date_only``; dates still ahead (expiry, remediation due) ``future``.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from . import database, score

# (source key, top-level field, label, optional field used as detail)
_EXTERNAL: tuple[tuple[str, str, str, str | None], ...] = (
    ("whois", "creation_date", "Domain registered", "registrar"),
    ("whois", "updated_date", "WHOIS record updated", None),
    ("whois", "expiration_date", "Domain registration expires", None),
    ("virustotal", "creation_date", "Domain registered", None),
    ("virustotal", "first_seen_itw_date", "First seen in the wild", None),
    ("virustotal", "first_submission_date", "First submitted to VirusTotal", None),
    ("virustotal", "last_submission_date", "Last submitted to VirusTotal", None),
    ("virustotal", "last_analysis_date", "Last VirusTotal analysis", None),
    ("virustotal", "last_https_certificate_date", "TLS certificate last seen by VirusTotal", None),
    ("pdns", "first_seen", "First passive-DNS record", None),
    ("pdns", "last_seen", "Latest passive-DNS record", None),
    ("threatfox", "first_seen", "Listed on ThreatFox", "malware_printable"),
    ("threatfox", "last_seen", "Last seen on ThreatFox", None),
    ("urlhaus", "firstseen", "Listed on URLhaus", "threat"),
    ("urlhaus", "date_added", "Listed on URLhaus", "threat"),
    ("malwarebazaar", "first_seen", "First seen on MalwareBazaar", "signature"),
    ("malwarebazaar", "last_seen", "Last seen on MalwareBazaar", None),
    ("pulsedive", "stamp_added", "Added to Pulsedive", None),
    ("pulsedive", "stamp_seen", "Last seen by Pulsedive", None),
    ("greynoise", "last_seen", "Last seen scanning the internet (GreyNoise)", "classification"),
    ("abuseipdb", "lastReportedAt", "Latest abuse report (AbuseIPDB)", None),
    ("shodan", "last_update", "Last Shodan scan", None),
    ("nvd", "published", "CVE published", None),
    ("nvd", "lastModified", "CVE record last modified", None),
    ("kev", "dateAdded", "Added to CISA Known Exploited list", "vulnerabilityName"),
    ("kev", "dueDate", "CISA remediation due", None),
)

_FORMATS = ("%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d")
_EARLIEST = datetime(1985, 1, 1, tzinfo=timezone.utc)


def parse_when(raw: Any) -> tuple[datetime, bool] | None:
    """Parse a source timestamp to ``(aware UTC datetime, date_only)``.

    Accepts epoch seconds or milliseconds, ISO-8601 (with or without zone or
    fractional seconds), ``YYYY-MM-DD HH:MM:SS[ UTC]`` and bare dates; a list
    yields its first parseable entry. Naive values are taken as UTC — every
    provider here reports UTC. Implausible dates return None.
    """
    if isinstance(raw, list):
        for entry in raw:
            parsed = parse_when(entry)
            if parsed:
                return parsed
        return None
    dt: datetime | None = None
    date_only = False
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int | float):
        seconds = raw / 1000 if raw > 1e11 else raw
        try:
            dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    elif isinstance(raw, str):
        text = raw.strip()
        if not text:
            return None
        for fmt in _FORMATS:
            try:
                dt = datetime.strptime(text, fmt)
                date_only = fmt == "%Y-%m-%d"
                break
            except ValueError:
                continue
        if dt is None:
            try:
                dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                return None
    else:
        return None
    dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    if dt < _EARLIEST or dt > datetime.now(timezone.utc) + timedelta(days=365 * 30):
        return None
    return dt, date_only


def _local(raw: Any) -> datetime | None:
    """Our own rows are stored as naive local time — convert to UTC."""
    if raw is None:
        return None
    try:
        dt = raw if isinstance(raw, datetime) else datetime.fromisoformat(str(raw))
    except ValueError:
        return None
    return dt.astimezone(timezone.utc)


def _event(at: datetime, kind: str, label: str, *, source: str | None = None,
           detail: str | None = None, date_only: bool = False) -> dict[str, Any]:
    return {
        "at": at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "kind": kind,
        "label": label,
        "source": source,
        "detail": (detail or None) and str(detail)[:300],
        "date_only": date_only,
        "future": at > datetime.now(timezone.utc),
        "_ts": at.timestamp(),  # full precision for ordering; dropped before returning
    }


def _external_events(ioc_id: int) -> list[dict[str, Any]]:
    payloads: dict[str, dict] = {}
    for row in database.get_all_enrichments(ioc_id):  # oldest first -> newest wins
        try:
            data = json.loads(row["data"])
        except (TypeError, ValueError):
            continue
        if isinstance(data, dict):
            payloads[row["source"]] = data

    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for source, key, label, detail_key in _EXTERNAL:
        data = payloads.get(source)
        if not data:
            continue
        parsed = parse_when(data.get(key))
        if not parsed:
            continue
        at, date_only = parsed
        detail = data.get(detail_key) if detail_key else None
        # Two sources reporting the same fact on the same day are one event.
        slot = (label, at.strftime("%Y-%m-%d"))
        if slot in merged:
            known = merged[slot]
            if source not in known["source"].split(", "):
                known["source"] += ", " + source
            known["detail"] = known["detail"] or (str(detail)[:300] if isinstance(detail, str) and detail else None)
            continue
        merged[slot] = _event(at, "source", label, source=source,
                              detail=detail if isinstance(detail, str) else None, date_only=date_only)

    cert = (payloads.get("crtsh") or {}).get("most_recent")
    if isinstance(cert, dict):
        parsed = parse_when(cert.get("not_before"))
        if parsed:
            issuer = cert.get("issuer")
            merged[("cert", "")] = _event(parsed[0], "source", "Latest TLS certificate issued", source="crtsh",
                                          detail=issuer if isinstance(issuer, str) else None)
    return list(merged.values())


def _local_events(ioc_id: int) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    conn = database.get_db_connection()
    try:
        ioc = conn.execute(
            'SELECT first_seen, verdict, verdict_note, verdict_at FROM iocs WHERE id = ?', (ioc_id,)
        ).fetchone()
        watch = conn.execute(
            'SELECT threshold, added, last_checked, last_score, last_delta FROM watchlist WHERE ioc_id = ?', (ioc_id,)
        ).fetchone()
    finally:
        conn.close()

    if ioc:
        at = _local(ioc["first_seen"])
        if at:
            events.append(_event(at, "local", "First enriched here"))
        at = _local(ioc["verdict_at"])
        if at and ioc["verdict"]:
            events.append(_event(at, "analyst", f"Verdict set: {str(ioc['verdict']).replace('_', ' ')}",
                                 detail=ioc["verdict_note"]))

    previous: int | None = None
    for point in database.get_score_history(ioc_id, limit=500):
        at = _local(point["recorded_at"])
        value = int(point["score"])
        if at is None or value == previous:
            continue  # only changes are news
        label = (f"Score {value} · {score.risk_tier(value)}" if previous is None
                 else f"Score {previous} → {value} · {score.risk_tier(value)}")
        events.append(_event(at, "score", label, detail=None if previous is None else f"{value - previous:+d}"))
        previous = value

    for note in database.list_notes(ioc_id):
        at = _local(note["created"])
        if at:
            events.append(_event(at, "analyst", "Note", detail=note["body"]))
    for tag in database.get_tags_for_ioc(ioc_id):
        at = _local(tag["created"])
        if not at:
            continue
        if tag.get("case_name"):
            events.append(_event(at, "analyst", f"Added to case {tag['case_name']}", detail=tag.get("note")))
        elif tag.get("tag"):
            events.append(_event(at, "analyst", f"Tagged {tag['tag']}", detail=tag.get("note")))
    if watch:
        at = _local(watch["added"])
        if at:
            events.append(_event(at, "analyst", "Added to watchlist", detail=f"alert when score moves by {watch['threshold']} or more"))
        at = _local(watch["last_checked"])
        if at:
            delta = watch["last_delta"]
            events.append(_event(at, "local", "Latest watchlist check",
                                 detail=f"score {watch['last_score']}" + (f" ({int(delta):+d})" if delta is not None else "")))
    return events


def timeline_for(ioc_id: int) -> list[dict[str, Any]]:
    """All dated events for one cached IOC, newest first."""
    events = _external_events(ioc_id) + _local_events(ioc_id)
    # Rows written in the same second must still read newest-first, so order
    # on the full-precision time and, for exact ties, on insertion order.
    ordered = sorted(enumerate(events), key=lambda pair: (pair[1]["_ts"], pair[0]), reverse=True)
    out = []
    for _, event in ordered:
        event.pop("_ts", None)
        out.append(event)
    return out

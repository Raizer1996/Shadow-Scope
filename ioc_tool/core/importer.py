"""Import indicators — and what is already known about them — from a file.

Three shapes are understood, detected from the content:

* **STIX 2.x** JSON (a bundle, a list of objects, or one object): indicator
  patterns, cyber-observables and ``vulnerability`` objects. An indicator's
  name/description becomes a note, its labels become tags, and anything it
  ``indicates`` (malware, threat actor, campaign…) is added as a tag.
* **CSV** with a header row naming an indicator column; optional ``case``,
  ``tag(s)``, ``note`` and ``verdict`` columns ride along.
* **Plain text** — a list, a log excerpt, a report. Indicators are picked
  out; there is no metadata to carry.

``parse`` only reads. ``apply`` writes to the local cache and never calls a
provider: imported indicators are registered un-enriched, ready to be looked
up later.
"""

from __future__ import annotations

import csv
import io
import json
import re
from typing import Any

from . import database, extractor, parser
from . import defang as defang_mod

TYPES = ("ip", "domain", "url", "hash", "cve", "asn")
MAX_ROWS = 2000
MAX_TAGS = 12
_NOTE_MAX = 2000
_NAME_MAX = 80

_IOC_COLUMNS = ("ioc", "indicator", "value", "observable", "ioc_value", "indicator_value",
                "ip", "ip_address", "domain", "hostname", "url", "hash", "sha256", "sha1", "md5", "cve")
_CASE_COLUMNS = ("case", "case_name", "campaign", "incident")
_TAG_COLUMNS = ("tag", "tags", "label", "labels")
_NOTE_COLUMNS = ("note", "notes", "comment", "comments", "description")
_VERDICT_COLUMNS = ("verdict", "disposition", "classification")

_STIX_VALUE_RE = re.compile(
    r"(?:ipv4-addr|ipv6-addr|domain-name|url|autonomous-system)\s*:\s*(?:value|number)\s*=\s*'?((?:[^'\\]|\\.)+?)'?\s*(?:\]|\)|AND|OR|$)",
    re.IGNORECASE,
)
_STIX_HASH_RE = re.compile(
    r"file\s*:\s*hashes\s*\.\s*'?(?:MD5|SHA-?1|SHA-?256)'?\s*=\s*'([0-9a-fA-F]{32,64})'", re.IGNORECASE
)
_STIX_OBSERVABLES = ("ipv4-addr", "ipv6-addr", "domain-name", "url")
_STIX_NAMED = ("malware", "threat-actor", "campaign", "intrusion-set", "tool", "attack-pattern")


class _Rows:
    """Ordered, de-duplicated rows; metadata from repeats is merged."""

    def __init__(self) -> None:
        self.rows: dict[str, dict[str, Any]] = {}
        self.skipped = 0

    def add(self, raw: Any, *, case: str | None = None, tags: list[str] | None = None,
            note: str | None = None, verdict: str | None = None) -> None:
        if isinstance(raw, int) and not isinstance(raw, bool):
            raw = f"AS{raw}"
        if not isinstance(raw, str) or not raw.strip():
            return
        candidate = defang_mod.refang(raw.strip().strip(",;\"'"))
        ioc_type = parser.detect_type(candidate)
        if ioc_type not in TYPES:
            self.skipped += 1
            return
        value = parser.normalize_value(candidate, ioc_type)
        row = self.rows.setdefault(value.lower(), {
            "ioc": value, "type": ioc_type, "case": None, "tags": [], "note": None, "verdict": None,
        })
        row["case"] = row["case"] or _clean(case, _NAME_MAX)
        for tag in tags or []:
            cleaned = _clean(tag, _NAME_MAX)
            if cleaned and cleaned.lower() not in (t.lower() for t in row["tags"]) and len(row["tags"]) < MAX_TAGS:
                row["tags"].append(cleaned)
        row["note"] = row["note"] or _clean(note, _NOTE_MAX)
        row["verdict"] = row["verdict"] or _verdict(verdict)


def _clean(value: Any, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    text = " ".join(value.split())
    return text[:limit] or None


def _verdict(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    key = value.strip().lower().replace(" ", "_").replace("-", "_")
    key = {"fp": "false_positive", "malware": "malicious", "bad": "malicious",
           "clean": "benign", "good": "benign", "safe": "benign"}.get(key, key)
    return key if key in database.VERDICTS else None


# --------------------------------------------------------------------- STIX

def _stix_objects(doc: Any) -> list[dict] | None:
    if isinstance(doc, dict) and isinstance(doc.get("objects"), list):
        objs = doc["objects"]
    elif isinstance(doc, list):
        objs = doc
    elif isinstance(doc, dict) and "type" in doc:
        objs = [doc]
    else:
        return None
    objs = [o for o in objs if isinstance(o, dict) and isinstance(o.get("type"), str)]
    known = {"indicator", "vulnerability", "file", "autonomous-system", "relationship",
             *_STIX_OBSERVABLES, *_STIX_NAMED}
    return objs if any(o["type"] in known for o in objs) else None


def _parse_stix(objs: list[dict], out: _Rows) -> None:
    names = {o["id"]: o["name"] for o in objs
             if o["type"] in _STIX_NAMED and isinstance(o.get("id"), str) and isinstance(o.get("name"), str)}
    indicates: dict[str, list[str]] = {}
    for o in objs:
        if o["type"] == "relationship" and o.get("target_ref") in names and isinstance(o.get("source_ref"), str):
            indicates.setdefault(o["source_ref"], []).append(names[o["target_ref"]])

    for o in objs:
        kind = o["type"]
        if kind == "indicator":
            raw_pattern = o.get("pattern")
            pattern: str = raw_pattern if isinstance(raw_pattern, str) else ""
            if o.get("pattern_type", "stix") != "stix":
                out.skipped += 1
                continue
            values = [m.replace("\\'", "'").replace("\\\\", "\\") for m in _STIX_VALUE_RE.findall(pattern)]
            values += _STIX_HASH_RE.findall(pattern)
            if not values:
                out.skipped += 1
                continue
            tags = [t for key in ("labels", "indicator_types") for t in (o.get(key) or []) if isinstance(t, str)]
            tags += indicates.get(o.get("id", ""), [])
            name, desc = _clean(o.get("name"), 200), _clean(o.get("description"), _NOTE_MAX)
            note = " — ".join(p for p in (name, desc) if p) or None
            for value in values:
                out.add(value, tags=tags, note=note)
        elif kind in _STIX_OBSERVABLES:
            out.add(o.get("value"))
        elif kind == "autonomous-system":
            out.add(o.get("number"))
        elif kind == "file":
            raw_hashes = o.get("hashes")
            hashes: dict[str, Any] = raw_hashes if isinstance(raw_hashes, dict) else {}
            best = next((hashes[k] for k in ("SHA-256", "SHA256", "SHA-1", "SHA1", "MD5") if k in hashes), None)
            out.add(best)
        elif kind == "vulnerability":
            out.add(o.get("name"), note=_clean(o.get("description"), _NOTE_MAX))


# ---------------------------------------------------------------------- CSV

def _parse_csv(text: str, out: _Rows) -> bool:
    """Parse ``text`` as CSV with a recognisable header. False if it is not one."""
    head = text.lstrip().split("\n", 1)[0]
    if not any(sep in head for sep in (",", ";", "\t", "|")) and head.strip().lower() not in _IOC_COLUMNS:
        return False
    try:
        dialect: Any = csv.Sniffer().sniff(text[:4000], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.reader(io.StringIO(text), dialect)
    try:
        header = [h.strip().lower().lstrip("﻿").replace(" ", "_") for h in next(reader)]
    except (StopIteration, csv.Error):
        return False

    def col(names: tuple[str, ...]) -> int | None:
        return next((header.index(n) for n in names if n in header), None)

    ioc_cols = [i for i, h in enumerate(header) if h in _IOC_COLUMNS]
    if not ioc_cols:
        return False
    c_case, c_tag, c_note, c_verdict = col(_CASE_COLUMNS), col(_TAG_COLUMNS), col(_NOTE_COLUMNS), col(_VERDICT_COLUMNS)

    def cell(row: list[str], idx: int | None) -> str | None:
        return row[idx].strip() if idx is not None and idx < len(row) and row[idx].strip() else None

    try:
        for row in reader:
            if not any(c.strip() for c in row):
                continue
            tags = [t for t in re.split(r"[;,|]", cell(row, c_tag) or "") if t.strip()]
            found = False
            for idx in ioc_cols:
                value = cell(row, idx)
                if value:
                    found = True
                    out.add(value, case=cell(row, c_case), tags=tags, note=cell(row, c_note), verdict=cell(row, c_verdict))
            if not found:
                out.skipped += 1
    except csv.Error:
        pass
    return True


# --------------------------------------------------------------------- text

def _parse_text(text: str, out: _Rows) -> None:
    for line in text.splitlines():
        token = line.strip().strip(",;")
        if token and not token.startswith("#") and " " not in token:
            out.add(token)
    skipped = out.skipped  # only whole-line misses count as "not recognised"
    for bucket in extractor.extract_iocs(text).values():
        for raw in bucket:
            out.add(raw)
    out.skipped = skipped


def parse(text: str) -> dict[str, Any]:
    """Detect the format and return ``{format, rows, total, truncated, skipped, known}``.

    ``known`` counts rows already in the local cache; each row carries
    ``cached``. Read-only.
    """
    out = _Rows()
    fmt = "text"
    stripped = (text or "").lstrip("﻿ \t\r\n")
    objs = None
    if stripped[:1] in ("{", "["):
        try:
            objs = _stix_objects(json.loads(stripped))
        except ValueError:
            objs = None
    if objs is not None:
        fmt = "stix"
        _parse_stix(objs, out)
    elif _parse_csv(stripped, out):
        fmt = "csv"
    else:
        _parse_text(stripped, out)

    rows = list(out.rows.values())
    total = len(rows)
    rows = rows[:MAX_ROWS]
    known = 0
    if rows:
        database.init_db()
        conn = database.get_db_connection()
        try:
            have: set[str] = set()
            for start in range(0, len(rows), 400):
                chunk = [r["ioc"].lower() for r in rows[start:start + 400]]
                marks = ",".join("?" * len(chunk))
                have.update(r["v"] for r in conn.execute(
                    f"SELECT LOWER(value) AS v FROM iocs WHERE LOWER(value) IN ({marks})", chunk))
        finally:
            conn.close()
        for row in rows:
            row["cached"] = row["ioc"].lower() in have
            known += row["cached"]
    return {"format": fmt, "rows": rows, "total": total, "truncated": max(0, total - MAX_ROWS),
            "skipped": out.skipped, "known": known}


def apply(rows: list[dict[str, Any]], *, case: str | None = None) -> dict[str, int]:
    """Register rows in the local cache with their metadata. No provider calls.

    Every value is re-validated here — the rows come back from a browser.
    ``case`` (when given) is used for rows that carry none. An existing
    verdict is never overwritten; a note or tag already present is not
    duplicated, so importing the same file twice changes nothing.
    """
    stats = {"imported": 0, "new": 0, "cases": 0, "tags": 0, "notes": 0, "verdicts": 0, "rejected": 0}
    default_case = _clean(case, _NAME_MAX)
    database.init_db()
    seen_cases: set[str] = set()
    for raw in rows[:MAX_ROWS]:
        candidate = defang_mod.refang(str(raw.get("ioc") or "").strip())
        ioc_type = parser.detect_type(candidate)
        if ioc_type not in TYPES:
            stats["rejected"] += 1
            continue
        value = parser.normalize_value(candidate, ioc_type)
        is_new = database.get_ioc_id(value) is None
        ioc_id = database.add_or_update_ioc(value, ioc_type)
        stats["imported"] += 1
        stats["new"] += is_new

        existing = database.get_tags_for_ioc(ioc_id)
        row_case = _clean(raw.get("case"), _NAME_MAX) or default_case
        if row_case and not any(t.get("case_name") for t in existing):
            if row_case not in seen_cases:
                database.upsert_case(row_case)
                seen_cases.add(row_case)
            database.set_ioc_case(value, row_case)
            stats["cases"] += 1
        have_tags = {str(t["tag"]).lower() for t in existing if t.get("tag")}
        raw_tags = raw.get("tags")
        tags: list[Any] = raw_tags if isinstance(raw_tags, list) else []
        for tag in tags[:MAX_TAGS]:
            cleaned = _clean(tag, _NAME_MAX)
            if cleaned and cleaned.lower() not in have_tags:
                database.tag_ioc(ioc_id, tag=cleaned)
                have_tags.add(cleaned.lower())
                stats["tags"] += 1
        note = _clean(raw.get("note"), _NOTE_MAX)
        if note and note not in {n["body"] for n in database.list_notes(ioc_id)}:
            database.add_note(ioc_id, note)
            stats["notes"] += 1
        verdict = _verdict(raw.get("verdict"))
        if verdict and database.get_verdict(ioc_id) is None:
            database.set_verdict(ioc_id, verdict, "imported")
            stats["verdicts"] += 1
    return stats

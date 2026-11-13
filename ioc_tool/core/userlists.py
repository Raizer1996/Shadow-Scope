"""Your own blocklist and allowlist, kept in the local database.

Entries are managed from the dashboard (or the API) and take effect without a
restart — unlike the env-driven :mod:`allowlist`, which stays as it is.

* **allow** — a match short-circuits enrichment exactly like the env
  allowlist: no provider is called and the result scores 0.
* **block** — a match adds a ``Blocklist`` source scoring 100 at full weight,
  so the indicator reads Critical whatever the public sources say.

An entry is one of: an exact indicator (IP, URL, hash, CVE, ASN), a CIDR
(``203.0.113.0/24``), or a domain — which also covers its subdomains
(``evil.example`` or ``*.evil.example``). When several entries match, the most
specific one wins; on a tie the blocklist does.
"""

from __future__ import annotations

import ipaddress
import sqlite3
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from . import database, parser
from . import defang as defang_mod

LISTS = ("block", "allow")
BLOCK_SOURCE = "Blocklist"
_EXACT_KINDS = ("ip", "url", "hash", "cve", "asn", "email")
_NOTE_MAX = 300


def normalize(raw: str) -> tuple[str, str]:
    """Classify a list entry. Returns ``(kind, pattern)``; ValueError if unusable."""
    text = defang_mod.refang((raw or "").strip())
    if not text:
        raise ValueError("empty entry")
    if "/" in text and "://" not in text:
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            net = None
        if net is not None:
            if net.prefixlen < (8 if net.version == 4 else 16):
                raise ValueError("network too wide — use /8 or narrower (IPv6: /16)")
            return "cidr", str(net)
    wildcard = text.startswith(("*.", "."))
    if wildcard:
        text = text.lstrip("*").lstrip(".")
    if "://" not in text:
        text = text.rstrip(".")  # fully-qualified form: evil.example.
    ioc_type = parser.detect_type(text)
    if ioc_type == "domain":
        return "domain", text.lower().rstrip(".")
    if wildcard or ioc_type not in _EXACT_KINDS:
        raise ValueError("not an IP, CIDR, domain, URL, e-mail address, hash, CVE or ASN")
    value = parser.normalize_value(text, ioc_type)
    return ioc_type, value.lower() if ioc_type in ("hash", "url", "email") else value


def add(list_name: str, raw: str, note: str | None = None) -> dict[str, Any]:
    """Add (or update the note of) an entry. Returns the stored row."""
    if list_name not in LISTS:
        raise ValueError(f"list must be one of {LISTS}")
    kind, pattern = normalize(raw)
    note = " ".join((note or "").split())[:_NOTE_MAX] or None
    conn = database.get_db_connection()
    try:
        conn.execute(
            'INSERT INTO user_lists (list, kind, pattern, note, created) VALUES (?, ?, ?, ?, ?) '
            'ON CONFLICT(list, pattern) DO UPDATE SET note = COALESCE(excluded.note, user_lists.note)',
            (list_name, kind, pattern, note, datetime.now()),
        )
        conn.commit()
        row = conn.execute(
            'SELECT id, list, kind, pattern, note, created FROM user_lists WHERE list = ? AND pattern = ?',
            (list_name, pattern),
        ).fetchone()
        return _row(row)
    finally:
        conn.close()


def remove(entry_id: int) -> int:
    conn = database.get_db_connection()
    try:
        cur = conn.execute('DELETE FROM user_lists WHERE id = ?', (int(entry_id),))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def entries() -> list[dict[str, Any]]:
    """Every entry, newest first. Empty when the table does not exist yet."""
    conn = database.get_db_connection()
    try:
        rows = conn.execute(
            'SELECT id, list, kind, pattern, note, created FROM user_lists ORDER BY created DESC, id DESC'
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()
    return [_row(r) for r in rows]


def _row(row: Any) -> dict[str, Any]:
    return {"id": int(row["id"]), "list": row["list"], "kind": row["kind"], "pattern": row["pattern"],
            "note": row["note"], "created": str(row["created"] or "")[:16]}


def _host(url: str) -> str:
    try:
        return (urlsplit(url if "//" in url else "//" + url).hostname or "").lower()
    except ValueError:
        return ""


def _specificity(entry: dict[str, Any], value: str, ioc_type: str) -> int | None:
    """How tightly ``entry`` matches, or None. Higher is more specific."""
    kind, pattern = entry["kind"], entry["pattern"]
    if kind in _EXACT_KINDS and kind == ioc_type and value.lower() == pattern.lower():
        return 10_000
    if kind == "cidr" and ioc_type == "ip":
        try:
            addr, net = ipaddress.ip_address(value), ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            return None
        return net.prefixlen if addr.version == net.version and addr in net else None
    if kind == "domain" and ioc_type == "domain":
        target = value.lower().rstrip(".")
        return 1000 + len(pattern) if target == pattern or target.endswith("." + pattern) else None
    return None


def match(value: str, ioc_type: str) -> dict[str, Any] | None:
    """The winning entry for an indicator, or None.

    A URL matches its own exact entry first, then falls back to its host
    (domain or IP entries). Returns the entry plus ``matched_on``.
    """
    rows = entries()
    if not rows:
        return None
    candidates = [(value, ioc_type)]
    if ioc_type == "url":
        host = _host(value)
        if host:
            candidates.append((host, "ip" if parser.detect_type(host) == "ip" else "domain"))
    elif ioc_type == "email" and "@" in value:
        candidates.append((value.rsplit("@", 1)[1].lower(), "domain"))
    best: tuple[int, int, dict[str, Any], str] | None = None
    for rank, (cand, cand_type) in enumerate(candidates):
        for entry in rows:
            spec = _specificity(entry, cand, cand_type)
            if spec is None:
                continue
            # Direct match on the value beats a match on its host; then the
            # tighter rule; then block over allow.
            key = (spec - rank * 20_000, 1 if entry["list"] == "block" else 0)
            if best is None or key > (best[0], best[1]):
                best = (key[0], key[1], entry, cand)
    if best is None:
        return None
    return {**best[2], "matched_on": best[3]}


def allow_hit(value: str, ioc_type: str) -> dict[str, Any] | None:
    """Short-circuit context when the winning entry is on the allowlist."""
    hit = match(value, ioc_type)
    if not hit or hit["list"] != "allow":
        return None
    return {"reason": "your allowlist", "match": hit["pattern"], "note": hit["note"]}


def block_hit(value: str, ioc_type: str) -> dict[str, Any] | None:
    """Source payload when the winning entry is on the blocklist."""
    hit = match(value, ioc_type)
    if not hit or hit["list"] != "block":
        return None
    return {"listed": True, "match": hit["pattern"], "kind": hit["kind"], "note": hit["note"], "added": hit["created"]}

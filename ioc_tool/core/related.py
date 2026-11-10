"""Related indicators for one cached IOC — cache-only, no API spend.

Answers "what else should I look at?" from data ShadowScope already holds:

* indicators already in the cache that share something with this one
  (case, malware family, network, registered domain, tags, registrar);
* indicators *named inside* this one's enrichment data but not enriched yet
  (hostnames an IP served, addresses a domain resolved to, subdomains seen
  in certificates). Those come back with ``cached: False`` so the UI can
  offer to enrich them.

Everything here reads SQLite. Nothing is fetched from a provider.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any
from urllib.parse import urlsplit

from . import database, parser

# Suffixes where the registered domain is three labels, not two. Deliberately
# short: the grouping is a convenience, and pulling in a public-suffix list for
# it is not worth a dependency (same call as ``heuristics._extract_label``).
_COMPOUND_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.jp", "co.kr", "co.il", "co.in", "co.za", "com.br", "com.cn",
    "com.mx", "com.tr", "com.ar", "com.sg", "com.hk", "com.tw", "com.ua",
})

# Top-level keys, across all sources, whose values name other hosts.
_HOST_KEYS = ("ptr", "hostname", "hostnames", "top_rrnames", "domains", "aliases")
_NETWORK_SCAN_CAP = 20000
# What a source says about *this* indicator lives at the top level of its
# payload. Deeper copies of the same keys are other things entirely (tags of
# every OTX pulse that mentions the indicator, a TLS certificate's
# ``signature`` blob) and make everything look related to everything.
_FAMILY_KEYS = ("malware", "malware_printable", "family", "signature")
_TAG_KEYS = ("tag", "tags")
_TAG_VERIFY_CAP = 80


def registered_domain(host: str) -> str:
    """Best-effort registrable domain: ``a.b.evil.co.uk`` -> ``evil.co.uk``."""
    parts = [p for p in host.strip().lower().rstrip(".").split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    if ".".join(parts[-2:]) in _COMPOUND_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _url_host(url: str) -> str:
    try:
        return (urlsplit(url if "//" in url else "//" + url).hostname or "").lower()
    except ValueError:
        return ""


def _clean_host(raw: Any) -> tuple[str, str] | None:
    """Normalise a hostname/IP candidate. Returns ``(value, type)`` or None."""
    if not isinstance(raw, str):
        return None
    value = raw.strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    if not value or len(value) > 253 or " " in value:
        return None
    kind = parser.detect_type(value)
    if kind not in ("ip", "domain"):
        return None
    return value, kind


def _latest_payloads(ioc_id: int) -> dict[str, dict]:
    """Newest parsed payload per source for one IOC."""
    out: dict[str, dict] = {}
    for row in database.get_all_enrichments(ioc_id):  # oldest first -> last wins
        try:
            data = json.loads(row["data"])
        except (TypeError, ValueError):
            continue
        if isinstance(data, dict):
            out[row["source"]] = data
    return out


def _query(sql: str, params: list | tuple = ()) -> list[dict]:
    conn = database.get_db_connection()
    try:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def _item(row: dict, why: str | None = None) -> dict[str, Any]:
    score = row.get("last_score")
    return {
        "ioc": row["value"],
        "type": row["type"],
        "score": int(score) if score is not None else None,
        "cached": True,
        "why": why,
    }


def _group(key: str, title: str, pivot: str, items: list[dict], limit: int) -> dict[str, Any] | None:
    if not items:
        return None
    # Known-bad first, then things already in the cache, then alphabetical.
    items.sort(key=lambda i: (-(i["score"] if i["score"] is not None else -1), not i["cached"], i["ioc"]))
    return {"key": key, "title": title, "pivot": pivot, "total": len(items), "items": items[:limit]}


def _own_values(payloads: dict[str, dict], keys: tuple[str, ...]) -> list[str]:
    """Lower-cased top-level string values under ``keys``, first-seen order."""
    out: dict[str, None] = {}
    for data in payloads.values():
        for key in keys:
            val = data.get(key)
            for entry in val if isinstance(val, list) else [val]:
                if isinstance(entry, str) and 3 <= len(entry.strip()) <= 64:
                    out.setdefault(entry.strip().lower())
    return list(out)


def _sharing_fields(ioc_id: int, kinds: tuple[str, ...], values: list[str] | None = None) -> tuple[list[str], list[dict]]:
    """Other IOCs indexed under any of ``values`` for the given index kinds.

    ``values`` defaults to everything this IOC is indexed under for ``kinds``.
    """
    marks = ",".join("?" * len(kinds))
    if values is None:
        mine = _query(
            f"SELECT DISTINCT LOWER(value) AS v FROM enrichment_fields WHERE ioc_id = ? AND kind IN ({marks})",
            [ioc_id, *kinds],
        )
        values = [r["v"] for r in mine if len(r["v"]) >= 3]
    values = values[:200]
    if not values:
        return [], []
    vmarks = ",".join("?" * len(values))
    rows = _query(
        f"SELECT i.id, i.value, i.type, i.last_score, GROUP_CONCAT(DISTINCT LOWER(f.value)) AS shared "
        f"FROM enrichment_fields f JOIN iocs i ON i.id = f.ioc_id "
        f"WHERE f.kind IN ({marks}) AND LOWER(f.value) IN ({vmarks}) AND i.id != ? "
        f"GROUP BY i.id ORDER BY COUNT(DISTINCT LOWER(f.value)) DESC, i.last_seen DESC LIMIT 200",
        [*kinds, *values, ioc_id],
    )
    return values, rows


def _network_of(value: str, payloads: dict[str, dict]) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """Announced prefix if a source reported one, else the /24 (v4) or /48 (v6)."""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    candidates: list[Any] = [(payloads.get("virustotal") or {}).get("network")]
    asys = (payloads.get("censys") or {}).get("autonomous_system")
    if isinstance(asys, dict):
        candidates.append(asys.get("bgp_prefix"))
    for cand in candidates:
        if not isinstance(cand, str):
            continue
        try:
            net = ipaddress.ip_network(cand, strict=False)
        except ValueError:
            continue
        # A /8 "same network" is noise, not a pivot.
        floor = 16 if net.version == 4 else 32
        if addr in net and net.prefixlen >= floor:
            return net
    return ipaddress.ip_network(f"{addr}/{24 if addr.version == 4 else 48}", strict=False)


def _named_hosts(value: str, ioc_type: str, payloads: dict[str, dict]) -> tuple[dict[str, tuple[str, str]], dict[str, tuple[str, str]]]:
    """Hosts named in this IOC's own data: ``(seen_with, cert_subdomains)``.

    Each maps value -> (type, source that named it).
    """
    seen: dict[str, tuple[str, str]] = {}
    certs: dict[str, tuple[str, str]] = {}

    def add(bucket: dict[str, tuple[str, str]], raw: Any, source: str) -> None:
        cleaned = _clean_host(raw)
        if cleaned and cleaned[0] != value:
            bucket.setdefault(cleaned[0], (cleaned[1], source))

    for source, data in payloads.items():
        for key in _HOST_KEYS:
            val = data.get(key)
            for entry in val if isinstance(val, list) else [val]:
                add(seen, entry, source)
        for rec in data.get("last_dns_records") or []:
            if isinstance(rec, dict) and rec.get("type") in ("A", "AAAA", "CNAME", "MX", "NS"):
                add(seen, rec.get("value"), source)
        for sub in data.get("unique_subdomains") or []:
            add(certs, sub, source)

    if ioc_type == "url":
        host = _url_host(value)
        if host:
            add(seen, host, "url host")
    for name in certs:
        seen.pop(name, None)
    return seen, certs


def _resolve(named: dict[str, tuple[str, str]]) -> list[dict]:
    """Turn named hosts into items, marking which are already cached."""
    if not named:
        return []
    names = list(named)[:400]
    marks = ",".join("?" * len(names))
    cached = {r["value"].lower(): r for r in _query(
        f"SELECT value, type, last_score FROM iocs WHERE LOWER(value) IN ({marks})", names
    )}
    items = []
    for name in names:
        kind, source = named[name]
        row = cached.get(name)
        if row:
            items.append(_item(row, f"named by {source}"))
        else:
            items.append({"ioc": name, "type": kind, "score": None, "cached": False, "why": f"named by {source}"})
    return items


def related_for(ioc_id: int, value: str, ioc_type: str, *, limit: int = 12) -> list[dict[str, Any]]:
    """Groups of indicators related to one cached IOC. Empty list when none."""
    payloads = _latest_payloads(ioc_id)
    groups: list[dict[str, Any] | None] = []

    # --- same case -------------------------------------------------------
    case = next((t["case_name"] for t in database.get_tags_for_ioc(ioc_id) if t.get("case_name")), None)
    if case:
        rows = [r for r in database.list_iocs_for_case(case) if r["id"] != ioc_id]
        groups.append(_group("case", "SAME CASE", case, [_item(r) for r in rows], limit))

    # --- same malware family ---------------------------------------------
    fams, rows = _sharing_fields(ioc_id, ("malware", "family"), _own_values(payloads, _FAMILY_KEYS))
    groups.append(_group("family", "SAME MALWARE", ", ".join(fams[:3]), [_item(r, r["shared"]) for r in rows], limit))

    # --- same network ----------------------------------------------------
    if ioc_type == "ip":
        net = _network_of(value, payloads)
        if net is not None:
            hits = []
            for r in _query(
                "SELECT id, value, type, last_score FROM iocs WHERE type = 'ip' AND id != ? LIMIT ?",
                [ioc_id, _NETWORK_SCAN_CAP],
            ):
                try:
                    if ipaddress.ip_address(r["value"]) in net:
                        hits.append(_item(r))
                except (ValueError, TypeError):
                    continue
            groups.append(_group("network", "SAME NETWORK", str(net), hits, limit))

    # --- same registered domain / hosted here ----------------------------
    host = value if ioc_type in ("domain", "ip") else _url_host(value) if ioc_type == "url" else ""
    if host:
        anchor = host if parser.detect_type(host) == "ip" else registered_domain(host)
        like = "%" + anchor.replace("%", "").replace("_", r"\_") + "%"
        hits = []
        for r in _query(
            "SELECT id, value, type, last_score FROM iocs "
            "WHERE type IN ('domain', 'url') AND id != ? AND LOWER(value) LIKE ? ESCAPE '\\' LIMIT 500",
            [ioc_id, like],
        ):
            other = r["value"].lower() if r["type"] == "domain" else _url_host(r["value"])
            if other == anchor or other.endswith("." + anchor):
                hits.append(_item(r))
        title = "HOSTED ON THIS IP" if anchor == host and ioc_type == "ip" else "SAME DOMAIN"
        groups.append(_group("domain", title, anchor, hits, limit))

    # --- hosts named in this IOC's own data ------------------------------
    seen, certs = _named_hosts(value, ioc_type, payloads)
    groups.append(_group("seen_with", "SEEN WITH", "dns · rdns · passive dns", _resolve(seen), limit))
    groups.append(_group("certs", "SUBDOMAINS IN CERTIFICATES", "certificate transparency", _resolve(certs), limit))

    # --- shared tags / registrar -----------------------------------------
    # The index also holds nested tags, so confirm each candidate carries the
    # tag as one of its own before calling it related.
    tags, rows = _sharing_fields(ioc_id, ("tag",), _own_values(payloads, _TAG_KEYS))
    mine = set(tags)
    tagged = []
    for r in rows[:_TAG_VERIFY_CAP]:
        shared = [t for t in _own_values(_latest_payloads(r["id"]), _TAG_KEYS) if t in mine]
        if shared:
            tagged.append((len(shared), _item(r, ",".join(shared))))
    tagged.sort(key=lambda pair: -pair[0])
    pivot = ", ".join(tags[:3]) + (f" +{len(tags) - 3}" if len(tags) > 3 else "")
    groups.append(_group("tags", "SHARED TAGS", pivot, [item for _, item in tagged], limit))
    regs, rows = _sharing_fields(ioc_id, ("registrar",))
    groups.append(_group("registrar", "SAME REGISTRAR", ", ".join(regs[:1]), [_item(r) for r in rows], limit))

    return [g for g in groups if g]

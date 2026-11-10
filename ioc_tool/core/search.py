"""Search across everything ShadowScope has stored locally. Cache-only.

One query answers "where have I seen this?" over: indicator values, analyst
verdicts and their notes, free notes, case names, tags, the indexed source
fields (malware family, registrar, source tags) and — when ``deep`` is on —
the raw text of every cached source answer.

Free text is split into words; every word must match somewhere (AND), each
as a case-insensitive substring. ``"quoted phrases"`` stay together. The
structured filters (type, score, verdict, case, …) narrow the same result.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any

from . import database, score
from . import defang as defang_mod

TYPES = ("ip", "domain", "url", "hash", "cve", "asn", "email")
SORTS = {
    "score": "COALESCE(i.last_score, -1) DESC, i.last_seen DESC",
    "recent": "i.last_seen DESC",
    "value": "LOWER(i.value) ASC",
}
MAX_TERMS = 8
MAX_TERM_LEN = 100

_TERM_RE = re.compile(r'"([^"]+)"|(\S+)')
_CASE_SQL = "(SELECT t.case_name FROM ioc_tags t WHERE t.ioc_id = i.id AND t.case_name IS NOT NULL LIMIT 1)"
_NOTES_SQL = "(SELECT COUNT(*) FROM ioc_notes n WHERE n.ioc_id = i.id)"
_WATCH_SQL = "EXISTS (SELECT 1 FROM watchlist w WHERE w.ioc_id = i.id)"

# (label shown to the user, SQL that is true when the bound pattern matches)
_FIELD_MATCHERS: tuple[tuple[str, str], ...] = (
    ("indicator", "LOWER(i.value) LIKE :p ESCAPE '\\'"),
    ("verdict", "(LOWER(COALESCE(i.verdict, '')) LIKE :p ESCAPE '\\' "
                "OR LOWER(COALESCE(i.verdict_note, '')) LIKE :p ESCAPE '\\')"),
    ("note", "EXISTS (SELECT 1 FROM ioc_notes n WHERE n.ioc_id = i.id AND LOWER(n.body) LIKE :p ESCAPE '\\')"),
    ("case", "EXISTS (SELECT 1 FROM ioc_tags t WHERE t.ioc_id = i.id "
             "AND LOWER(COALESCE(t.case_name, '')) LIKE :p ESCAPE '\\')"),
    ("tag", "EXISTS (SELECT 1 FROM ioc_tags t WHERE t.ioc_id = i.id AND "
            "(LOWER(COALESCE(t.tag, '')) LIKE :p ESCAPE '\\' OR LOWER(COALESCE(t.note, '')) LIKE :p ESCAPE '\\'))"),
    ("source field", "EXISTS (SELECT 1 FROM enrichment_fields f WHERE f.ioc_id = i.id "
                     "AND LOWER(f.value) LIKE :p ESCAPE '\\')"),
)
_DEEP_MATCHER = ("source data", "EXISTS (SELECT 1 FROM enrichments e WHERE e.ioc_id = i.id "
                                "AND LOWER(e.data) LIKE :p ESCAPE '\\')")


def parse_terms(q: str | None) -> list[str]:
    """Split free text into lower-cased search terms (quoted phrases kept whole)."""
    terms: list[str] = []
    for phrase, word in _TERM_RE.findall(q or ""):
        raw = (phrase or word).strip()
        if not raw:
            continue
        # Let a defanged paste (1[.]2[.]3[.]4, hxxp://…) find the real value.
        term = defang_mod.refang(raw).lower()[:MAX_TERM_LEN]
        if term and term not in terms:
            terms.append(term)
        if len(terms) >= MAX_TERMS:
            break
    return terms


def _like(term: str) -> str:
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def search(
    q: str | None = None,
    *,
    types: list[str] | None = None,
    min_score: int | None = None,
    max_score: int | None = None,
    verdict: str | None = None,
    case: str | None = None,
    watched: bool | None = None,
    has_notes: bool | None = None,
    since_days: int | None = None,
    deep: bool = True,
    sort: str = "score",
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """Run a search. Returns ``{"total", "terms", "rows"}``.

    ``verdict`` / ``case`` accept a concrete value, ``"any"`` (has one) or
    ``"none"`` (has none). Unknown ``sort`` falls back to score order.
    """
    terms = parse_terms(q)
    matchers = _FIELD_MATCHERS + ((_DEEP_MATCHER,) if deep else ())
    where: list[str] = []
    params: dict[str, Any] = {}

    for n, term in enumerate(terms):
        key = f"t{n}"
        params[key] = _like(term)
        where.append("(" + " OR ".join(sql.replace(":p", f":{key}") for _, sql in matchers) + ")")

    wanted = [t for t in (types or []) if t in TYPES]
    if wanted:
        marks = []
        for n, t in enumerate(wanted):
            params[f"ty{n}"] = t
            marks.append(f":ty{n}")
        where.append(f"i.type IN ({', '.join(marks)})")
    if min_score is not None:
        params["smin"] = int(min_score)
        where.append("i.last_score >= :smin")
    if max_score is not None:
        params["smax"] = int(max_score)
        where.append("COALESCE(i.last_score, 0) <= :smax")
    if verdict == "any":
        where.append("i.verdict IS NOT NULL")
    elif verdict == "none":
        where.append("i.verdict IS NULL")
    elif verdict:
        params["verdict"] = verdict
        where.append("i.verdict = :verdict")
    if case == "any":
        where.append(f"{_CASE_SQL} IS NOT NULL")
    elif case == "none":
        where.append(f"{_CASE_SQL} IS NULL")
    elif case:
        params["case"] = case
        where.append("EXISTS (SELECT 1 FROM ioc_tags t WHERE t.ioc_id = i.id AND t.case_name = :case)")
    if watched is not None:
        where.append(_WATCH_SQL if watched else f"NOT {_WATCH_SQL}")
    if has_notes is not None:
        where.append(f"{_NOTES_SQL} {'>' if has_notes else '='} 0")
    if since_days is not None and since_days > 0:
        params["since"] = (datetime.now() - timedelta(days=int(since_days))).isoformat(sep=" ")
        where.append("i.last_seen >= :since")

    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    order = SORTS.get(sort, SORTS["score"])
    conn = database.get_db_connection()
    try:
        total = int(conn.execute(f"SELECT COUNT(*) AS n FROM iocs i{where_sql}", params).fetchone()["n"])
        rows = [dict(r) for r in conn.execute(
            f"SELECT i.id, i.value, i.type, i.last_score, i.last_seen, i.verdict, "
            f"{_CASE_SQL} AS case_name, {_NOTES_SQL} AS notes, {_WATCH_SQL} AS watched "
            f"FROM iocs i{where_sql} ORDER BY {order} LIMIT :lim OFFSET :off",
            {**params, "lim": max(1, min(int(limit), 500)), "off": max(0, int(offset))},
        ).fetchall()]

        out = []
        for r in rows:
            matched: list[str] = []
            for term in terms:
                for label, sql in matchers:
                    if label in matched:
                        continue
                    hit = conn.execute(
                        f"SELECT 1 FROM iocs i WHERE i.id = :id AND {sql}", {"id": r["id"], "p": _like(term)}
                    ).fetchone()
                    if hit:
                        matched.append(label)
            # Say *which* source answered with the text, not just "source data".
            if "source data" in matched and terms:
                clause = " OR ".join(f"LOWER(e.data) LIKE :s{n} ESCAPE '\\'" for n in range(len(terms)))
                srcs = conn.execute(
                    f"SELECT DISTINCT e.source FROM enrichments e WHERE e.ioc_id = :id AND ({clause}) ORDER BY e.source",
                    {"id": r["id"], **{f"s{n}": _like(t) for n, t in enumerate(terms)}},
                ).fetchall()
                matched[matched.index("source data")] = "source data: " + ", ".join(s["source"] for s in srcs[:6])
            last_score = r["last_score"]
            out.append({
                "ioc": r["value"],
                "type": r["type"],
                "score": int(last_score) if last_score is not None else None,
                "tier": score.risk_tier(last_score) if last_score is not None else None,
                "verdict": r["verdict"],
                "case": r["case_name"],
                "watched": bool(r["watched"]),
                "notes": int(r["notes"]),
                "last_seen": str(r["last_seen"]) if r["last_seen"] is not None else None,
                "matched": matched,
            })
    finally:
        conn.close()
    return {"total": total, "terms": terms, "rows": out}

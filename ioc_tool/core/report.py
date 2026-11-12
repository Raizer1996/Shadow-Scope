"""Shareable reports for one indicator or a whole case. Cache-only.

A report is first assembled as a list of neutral *blocks* (headings, key/value
pairs, tables, lists, paragraphs) and then serialised twice from the same
blocks: to Markdown, and to a self-contained HTML page meant for the browser's
"Print → Save as PDF". Rendering from one structure keeps the two formats from
drifting apart and means no Markdown parser or PDF library is needed.

Reports get forwarded, so indicators are always written defanged, and every
value is escaped for its target format — source data is untrusted text.
"""

from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from typing import Any

from . import database, related, score, timeline
from . import defang as defang_mod

Block = tuple[Any, ...]
MAX_CASE_MEMBERS = 200
_TIMELINE_ROWS = 25
_VERDICT_LABEL = {"malicious": "Malicious", "suspicious": "Suspicious", "benign": "Benign",
                  "false_positive": "False positive"}


def _defang(value: str) -> str:
    return defang_mod.defang(value)


def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _sources(ioc_id: int) -> list[dict[str, Any]]:
    """Newest row per source: name, score, when it was fetched."""
    latest: dict[str, dict[str, Any]] = {}
    for row in database.get_all_enrichments(ioc_id):  # oldest first -> newest wins
        latest[row["source"]] = {"source": row["source"], "score": row["score"],
                                 "fetched": str(row["timestamp"] or "")[:16]}
    return sorted(latest.values(), key=lambda r: (-(r["score"] or 0), r["source"]))


def _ioc_facts(ioc_id: int, value: str, ioc_type: str) -> dict[str, Any]:
    conn = database.get_db_connection()
    try:
        row = conn.execute('SELECT last_score, first_seen, last_seen FROM iocs WHERE id = ?', (ioc_id,)).fetchone()
    finally:
        conn.close()
    last_score = row["last_score"] if row else None
    tags = database.get_tags_for_ioc(ioc_id)
    return {
        "ioc": value,
        "type": ioc_type,
        "score": int(last_score) if last_score is not None else None,
        "tier": score.risk_tier(last_score) if last_score is not None else None,
        "first_seen": str(row["first_seen"] or "")[:16] if row else "",
        "last_seen": str(row["last_seen"] or "")[:16] if row else "",
        "verdict": database.get_verdict(ioc_id),
        "case": next((t["case_name"] for t in tags if t.get("case_name")), None),
        "tags": [t["tag"] for t in tags if t.get("tag")],
        "notes": database.list_notes(ioc_id),
        "watch": database.watch_get(ioc_id),
        "unavailable": database.get_last_unavailable(ioc_id),
        "sources": _sources(ioc_id),
    }


def _summary_pairs(f: dict[str, Any]) -> list[tuple[str, str]]:
    verdict = f["verdict"]
    pairs = [
        ("Indicator", _defang(f["ioc"])),
        ("Type", f["type"]),
        ("Score", f"{f['score']} / 100 — {f['tier']}" if f["score"] is not None else "not enriched yet"),
        ("Analyst verdict", _VERDICT_LABEL.get(verdict["verdict"], verdict["verdict"]) if verdict else "none"),
    ]
    if verdict and verdict.get("note"):
        pairs.append(("Verdict note", verdict["note"]))
    if f["case"]:
        pairs.append(("Case", f["case"]))
    if f["tags"]:
        pairs.append(("Tags", ", ".join(f["tags"])))
    if f["watch"]:
        pairs.append(("Watchlist", f"alert when score moves by {f['watch']['threshold']} or more"))
    if f["first_seen"]:
        pairs.append(("First enriched", f["first_seen"]))
    if f["last_seen"]:
        pairs.append(("Last enriched", f["last_seen"]))
    return pairs


def _ioc_blocks(f: dict[str, Any], ioc_id: int, *, level: int, full: bool) -> list[Block]:
    blocks: list[Block] = [("kv", _summary_pairs(f))]
    if f["unavailable"]:
        blocks.append(("p", "Incomplete: no answer from " + ", ".join(sorted(f["unavailable"]))
                       + " on the latest run — the score may be too low."))
    if f["notes"]:
        blocks.append(("h", level + 1, "Notes"))
        blocks.append(("list", [f"{str(n['created'])[:16]} — {n['body']}" for n in f["notes"]]))
    if f["sources"]:
        blocks.append(("h", level + 1, "Sources"))
        blocks.append(("table", ["Source", "Score", "Fetched"],
                       [[s["source"], "—" if s["score"] is None else str(s["score"]), s["fetched"]] for s in f["sources"]]))
    if not full:
        return blocks

    events = timeline.timeline_for(ioc_id)
    if events:
        blocks.append(("h", level + 1, "Timeline"))
        rows = []
        for e in events[:_TIMELINE_ROWS]:
            when = e["at"][:10] if e["date_only"] else e["at"][:16].replace("T", " ")
            what = e["label"] + (" (upcoming)" if e["future"] else "")
            rows.append([when, what, e["detail"] or "", e["source"] or ""])
        blocks.append(("table", ["When (UTC)", "Event", "Detail", "Source"], rows))
        if len(events) > _TIMELINE_ROWS:
            blocks.append(("p", f"{len(events) - _TIMELINE_ROWS} older events not shown."))

    groups = related.related_for(ioc_id, f["ioc"], f["type"], limit=8)
    if groups:
        blocks.append(("h", level + 1, "Related indicators"))
        for g in groups:
            items = []
            for item in g["items"]:
                state = f"score {item['score']}" if item["score"] is not None else (
                    "in cache" if item["cached"] else "not enriched")
                items.append(f"{_defang(item['ioc'])} — {item['type']}, {state}")
            more = g["total"] - len(g["items"])
            if more > 0:
                items.append(f"… and {more} more")
            blocks.append(("p", f"{g['title'].capitalize()} — {g['pivot']}"))
            blocks.append(("list", items))
    return blocks


def ioc_report(ioc_id: int, value: str, ioc_type: str) -> tuple[str, list[Block]]:
    """Title and blocks for a single-indicator report."""
    facts = _ioc_facts(ioc_id, value, ioc_type)
    title = f"Indicator report: {_defang(value)}"
    blocks: list[Block] = [("h", 1, title), ("p", f"Generated {_now()} by ShadowScope from locally cached data.")]
    blocks += _ioc_blocks(facts, ioc_id, level=1, full=True)
    return title, blocks


def case_report(case: str) -> tuple[str, list[Block]] | None:
    """Title and blocks for a case report, or None when the case is unknown."""
    info = database.get_case_meta().get(case, {})
    members = database.list_iocs_for_case(case)
    if not members and not info:
        return None
    title = f"Case report: {case}"
    blocks: list[Block] = [
        ("h", 1, title),
        ("p", f"Generated {_now()} by ShadowScope from locally cached data."),
        ("kv", [("Status", info.get("status", "open")), ("Indicators", str(len(members)))]),
    ]
    if info.get("description"):
        blocks.append(("p", info["description"]))

    shown = members[:MAX_CASE_MEMBERS]
    facts = [(m["id"], _ioc_facts(m["id"], m["value"], m["type"])) for m in shown]
    facts.sort(key=lambda pair: -(pair[1]["score"] if pair[1]["score"] is not None else -1))
    if facts:
        blocks.append(("h", 2, "Summary"))
        blocks.append(("table", ["Indicator", "Type", "Score", "Tier", "Analyst verdict", "Notes"], [[
            _defang(f["ioc"]), f["type"], "—" if f["score"] is None else str(f["score"]), f["tier"] or "—",
            _VERDICT_LABEL.get(f["verdict"]["verdict"], "—") if f["verdict"] else "—", str(len(f["notes"])),
        ] for _, f in facts]))
        if len(members) > MAX_CASE_MEMBERS:
            blocks.append(("p", f"{len(members) - MAX_CASE_MEMBERS} more indicators not shown."))
        blocks.append(("h", 2, "Indicators"))
        for ioc_id, f in facts:
            blocks.append(("h", 3, _defang(f["ioc"])))
            blocks += _ioc_blocks(f, ioc_id, level=3, full=False)
    return title, blocks


# ------------------------------------------------------------- serialisers

def _md_text(value: Any) -> str:
    """One line of source text that cannot turn into Markdown structure or raw HTML.

    Emphasis, code and angle brackets are escaped. Links and images are
    neutralised by breaking ``](`` rather than escaping every bracket, so a
    defanged ``1[.]2[.]3[.]4`` stays readable in the raw file.
    """
    text = re.sub(r"([\\`*_<>])", r"\\\1", " ".join(str(value).split()))
    return text.replace("](", "]\\(")


def _md_cell(value: Any) -> str:
    return _md_text(value).replace("|", "\\|")


def to_markdown(blocks: list[Block]) -> str:
    out: list[str] = []
    for block in blocks:
        kind = block[0]
        if kind == "h":
            out += ["#" * int(block[1]) + " " + _md_text(block[2]), ""]
        elif kind == "p":
            out += [_md_text(block[1]), ""]
        elif kind == "kv":
            out += [f"- **{_md_text(k)}:** {_md_text(v)}" for k, v in block[1]] + [""]
        elif kind == "list":
            out += [f"- {_md_text(item)}" for item in block[1]] + [""]
        elif kind == "table":
            headers, rows = block[1], block[2]
            out.append("| " + " | ".join(_md_cell(h) for h in headers) + " |")
            out.append("|" + "---|" * len(headers))
            out += ["| " + " | ".join(_md_cell(c) for c in row) + " |" for row in rows] + [""]
    return "\n".join(out).rstrip() + "\n"


_CSS = """
body{font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#111;background:#fff;max-width:900px;margin:32px auto;padding:0 20px}
h1{font-size:22px;border-bottom:2px solid #111;padding-bottom:6px}h2{font-size:17px;margin-top:28px;border-bottom:1px solid #bbb;padding-bottom:3px}
h3{font-size:15px;margin-top:22px;font-family:Consolas,Menlo,monospace}h4{font-size:13px;margin:14px 0 4px;text-transform:uppercase;letter-spacing:.06em;color:#444}
table{border-collapse:collapse;width:100%;margin:6px 0 12px;font-size:12.5px}th,td{border:1px solid #bbb;padding:4px 7px;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:#eee}dl{display:grid;grid-template-columns:max-content 1fr;gap:3px 14px;margin:8px 0}dt{font-weight:600;color:#333}dd{margin:0;overflow-wrap:anywhere}
ul{margin:4px 0 10px;padding-left:20px}li{overflow-wrap:anywhere}p{margin:6px 0}.bar{margin:0 0 18px}.bar button{font:inherit;padding:6px 14px;cursor:pointer}
@media print{.bar{display:none}body{margin:0;max-width:none}h2,h3,h4{break-after:avoid}tr{break-inside:avoid}}
"""


def to_html(title: str, blocks: list[Block]) -> str:
    esc = html.escape
    out = [
        "<!doctype html>", '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        f"<title>{esc(title)}</title><style>{_CSS}</style></head><body>",
        '<div class="bar"><button onclick="window.print()">Print / Save as PDF</button></div>',
    ]
    for block in blocks:
        kind = block[0]
        if kind == "h":
            level = max(1, min(int(block[1]), 4))
            out.append(f"<h{level}>{esc(str(block[2]))}</h{level}>")
        elif kind == "p":
            out.append(f"<p>{esc(str(block[1]))}</p>")
        elif kind == "kv":
            out.append("<dl>" + "".join(f"<dt>{esc(str(k))}</dt><dd>{esc(str(v))}</dd>" for k, v in block[1]) + "</dl>")
        elif kind == "list":
            out.append("<ul>" + "".join(f"<li>{esc(str(item))}</li>" for item in block[1]) + "</ul>")
        elif kind == "table":
            head = "".join(f"<th>{esc(str(h))}</th>" for h in block[1])
            body = "".join("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in row) + "</tr>" for row in block[2])
            out.append(f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>")
    out.append("</body></html>")
    return "\n".join(out) + "\n"


def filename(stem: str, fmt: str) -> str:
    """A safe download name: ``report-<stem>.md`` / ``.html``."""
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._")[:80] or "report"
    return f"report-{safe}.{'html' if fmt == 'html' else 'md'}"


def render(title: str, blocks: list[Block], fmt: str) -> str:
    return to_html(title, blocks) if fmt == "html" else to_markdown(blocks)


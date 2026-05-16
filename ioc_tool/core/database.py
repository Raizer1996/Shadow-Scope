import contextlib
import glob
import json
import os
import sqlite3
from datetime import datetime

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')

# Default DB lives at ioc_tool/data/ioc.db — same path as before so any
# user who never sets --workspace keeps working off their existing cache.
DB_PATH = os.path.join(DATA_DIR, 'ioc.db')


def workspace_db_path(name: str) -> str:
    """Return the SQLite file path for a named workspace.

    Named workspaces live alongside the default DB in the same data dir
    (so the Docker volume mount at ``/app/ioc_tool/data`` continues to
    persist all of them).
    """
    safe = "".join(c for c in name if c.isalnum() or c in ("-", "_")) or "default"
    return os.path.join(DATA_DIR, f"ioc-{safe}.db")


def set_workspace(name: str | None) -> str:
    """Switch the active SQLite file by workspace name.

    ``name`` is read from the CLI ``--workspace`` flag (or
    ``SHADOWSCOPE_WORKSPACE`` env). ``None`` / empty string reverts to
    the default ``ioc.db``. Returns the resolved DB path so callers can
    log it if they want.
    """
    global DB_PATH
    DB_PATH = os.path.join(DATA_DIR, 'ioc.db') if not name else workspace_db_path(name)
    return DB_PATH


def list_workspaces() -> list[dict]:
    """Enumerate every workspace DB present on disk.

    The default workspace appears as ``"default"`` (file ``ioc.db``).
    Named workspaces are derived from ``ioc-<name>.db``. Each entry
    carries the file path and on-disk byte size — useful for
    ``shadowscope workspaces`` to show analysts what's available.
    """
    out: list[dict] = []
    legacy = os.path.join(DATA_DIR, 'ioc.db')
    if os.path.exists(legacy):
        out.append({"name": "default", "path": legacy, "size": os.path.getsize(legacy)})
    for path in sorted(glob.glob(os.path.join(DATA_DIR, "ioc-*.db"))):
        base = os.path.basename(path)
        name = base[len("ioc-"):-len(".db")]
        out.append({"name": name, "path": path, "size": os.path.getsize(path)})
    return out

# Python 3.12 deprecated the default datetime → SQLite adapter and the
# inverse text → datetime converter. Register an explicit handler so the
# library doesn't fall back to the deprecated path (which emits a runtime
# DeprecationWarning on every INSERT carrying a ``datetime`` value).
# ISO 8601 with a space separator round-trips losslessly and sorts
# correctly as a string — same shape the existing parsers in enrich.py
# already accept.
sqlite3.register_adapter(datetime, lambda dt: dt.isoformat(sep=" "))

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Table: iocs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT UNIQUE NOT NULL,
            type TEXT NOT NULL,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            tags TEXT,
            last_score INTEGER
        )
    ''')
    # Migration for pre-watch-mode DBs that already exist without the column.
    with contextlib.suppress(sqlite3.OperationalError):
        cursor.execute('ALTER TABLE iocs ADD COLUMN last_score INTEGER')

    # Table: enrichments
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS enrichments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_id INTEGER,
            source TEXT,
            data TEXT,
            timestamp TIMESTAMP,
            score INTEGER,
            FOREIGN KEY (ioc_id) REFERENCES iocs (id)
        )
    ''')

    # Table: ioc_tags — many-to-many between IOCs and free-form labels +
    # optional case/campaign identifier. Idempotent: same (ioc_id, tag,
    # case) triple is only inserted once thanks to the UNIQUE constraint.
    # ``case`` is nullable for tags that aren't tied to a specific
    # campaign (e.g. just "phishing" with no case context).
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ioc_tags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_id INTEGER NOT NULL,
            tag TEXT,
            case_name TEXT,
            note TEXT,
            created TIMESTAMP,
            FOREIGN KEY (ioc_id) REFERENCES iocs (id),
            UNIQUE (ioc_id, tag, case_name)
        )
    ''')

    # Table: score_history — append-only snapshots of the composite
    # score per IOC, written by `update_last_score`. Backs the Watch
    # tab's "score over time" graph (a real series instead of the old
    # single-step delta against `last_score`).
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS score_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_id INTEGER NOT NULL,
            score INTEGER NOT NULL,
            recorded_at TIMESTAMP NOT NULL,
            FOREIGN KEY (ioc_id) REFERENCES iocs (id)
        )
    ''')
    cursor.execute(
        'CREATE INDEX IF NOT EXISTS idx_score_history_ioc '
        'ON score_history(ioc_id, recorded_at)'
    )

    # Table: enrichment_fields — denormalised lookup index over the
    # structured fields stored inside `enrichments.data`. Pivot queries
    # that previously did `LOWER(data) LIKE '%"needle"%'` (a full table
    # scan) now hit an indexed (kind, value) lookup. Populated by
    # `add_enrichment` whenever a row is inserted, plus a one-shot
    # backfill below for pre-existing caches.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS enrichment_fields (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            enrichment_id INTEGER NOT NULL,
            ioc_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            value TEXT NOT NULL,
            FOREIGN KEY (enrichment_id) REFERENCES enrichments (id),
            FOREIGN KEY (ioc_id) REFERENCES iocs (id)
        )
    ''')
    cursor.execute(
        'CREATE INDEX IF NOT EXISTS idx_efields_kind_value '
        'ON enrichment_fields(kind, value COLLATE NOCASE)'
    )
    cursor.execute(
        'CREATE INDEX IF NOT EXISTS idx_efields_ioc ON enrichment_fields(ioc_id)'
    )

    # One-shot backfill: empty index + non-empty enrichments → reindex.
    # Cheap on small caches, also makes the migration invisible to users.
    cursor.execute("SELECT COUNT(*) AS n FROM enrichment_fields")
    if int(cursor.fetchone()["n"]) == 0:
        cursor.execute("SELECT COUNT(*) AS n FROM enrichments")
        if int(cursor.fetchone()["n"]) > 0:
            _backfill_enrichment_fields(cursor)

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# enrichment_fields — pivot index
# ---------------------------------------------------------------------------
#
# We index four field kinds chosen to mirror the existing pivot API:
#   tag       — string elements of any "tag" / "tags" array in the payload
#   malware   — value of any "malware" field (threatfox + family aliases)
#   family    — value of any "family" or "signature" field (malwarebazaar)
#   registrar — value of the WHOIS "registrar" field
#
# A small recursive walker yields ``(kind, value)`` pairs for each match.
# Anything else falls through to the LIKE fallback in
# ``find_iocs_by_field``.

_FIELD_KEY_TO_KIND: dict[str, str] = {
    "tag": "tag",
    "tags": "tag",
    "malware": "malware",
    "family": "family",
    "signature": "family",
    "registrar": "registrar",
}


def _iter_indexable_fields(payload):  # type: ignore[no-untyped-def]
    """Yield ``(kind, value)`` pairs found anywhere in a JSON payload.

    Strings → one pair. Lists of strings under an indexable key → one
    pair per element. Non-string scalars are skipped (numbers, bools, etc).
    Recurses into nested dicts and lists.
    """
    if isinstance(payload, dict):
        for key, val in payload.items():
            kind = _FIELD_KEY_TO_KIND.get(key)
            if kind and isinstance(val, str) and val:
                yield (kind, val)
            elif kind and isinstance(val, list):
                for item in val:
                    if isinstance(item, str) and item:
                        yield (kind, item)
            # Always recurse — nested structures can also carry these keys.
            yield from _iter_indexable_fields(val)
    elif isinstance(payload, list):
        for item in payload:
            yield from _iter_indexable_fields(item)


def _insert_enrichment_fields(cursor, enrichment_id: int, ioc_id: int, data) -> None:
    """Persist every (kind, value) pair extracted from ``data`` for this row."""
    seen: set[tuple[str, str]] = set()
    for kind, value in _iter_indexable_fields(data):
        key = (kind, value.lower())
        if key in seen:
            continue
        seen.add(key)
        cursor.execute(
            'INSERT INTO enrichment_fields (enrichment_id, ioc_id, kind, value) '
            'VALUES (?, ?, ?, ?)',
            (enrichment_id, ioc_id, kind, value),
        )


def _backfill_enrichment_fields(cursor) -> int:
    """Replay every enrichment row through the field extractor.

    Run automatically by ``init_db`` when the index table is empty but
    enrichments already exist. Safe to call repeatedly — TRUNCATEs the
    target before refilling so dup runs stay idempotent. Returns the
    total number of indexed rows written.
    """
    cursor.execute('DELETE FROM enrichment_fields')
    cursor.execute('SELECT id, ioc_id, data FROM enrichments')
    written = 0
    for row in cursor.fetchall():
        try:
            data = json.loads(row["data"])
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        before = written
        for kind, value in _iter_indexable_fields(data):
            cursor.execute(
                'INSERT INTO enrichment_fields '
                '(enrichment_id, ioc_id, kind, value) VALUES (?, ?, ?, ?)',
                (row["id"], row["ioc_id"], kind, value),
            )
            written += 1
        # No-op iteration is fine — many sources just have no indexable
        # fields. We still record `written` once at the end of each row.
        _ = before
    return written


def rebuild_field_index() -> int:
    """Public re-entry to force a full backfill (e.g. after schema change).

    Returns the number of rows written. Callable from CLI or manually
    via ``python -m ioc_tool.core.database``-style scripts. Does NOT touch
    enrichments — only the side index.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        written = _backfill_enrichment_fields(cursor)
        conn.commit()
        return written
    finally:
        conn.close()


def tag_ioc(ioc_id: int, tag: str | None = None, case: str | None = None, note: str | None = None) -> int:
    """Attach a tag and/or case to an IOC. Returns the row id of the inserted entry.

    Idempotent under the UNIQUE constraint: a repeat call with the same
    ``(ioc_id, tag, case)`` triple silently no-ops and returns the
    existing row's id. ``note`` updates on conflict so analysts can
    revise the rationale without creating duplicate rows.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now()
    try:
        cursor.execute(
            '''
            INSERT INTO ioc_tags (ioc_id, tag, case_name, note, created)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (ioc_id, tag, case_name) DO UPDATE SET note = excluded.note
            RETURNING id
            ''',
            (ioc_id, tag, case, note, now),
        )
        row = cursor.fetchone()
        row_id = int(row['id']) if row else 0
        conn.commit()
        return row_id
    finally:
        conn.close()


def get_tags_for_ioc(ioc_id: int) -> list[dict]:
    """Return all tag rows attached to an IOC, ordered by creation time."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''
        SELECT id, tag, case_name, note, created
        FROM ioc_tags
        WHERE ioc_id = ?
        ORDER BY created ASC
        ''',
        (ioc_id,),
    )
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def list_iocs_for_case(case: str) -> list[dict]:
    """Return every IOC tied to ``case``, with their type + first_seen."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''
        SELECT DISTINCT i.id, i.value, i.type, i.first_seen, i.last_seen
        FROM iocs i
        JOIN ioc_tags t ON t.ioc_id = i.id
        WHERE t.case_name = ?
        ORDER BY i.last_seen DESC
        ''',
        (case,),
    )
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def list_cases() -> list[dict]:
    """List every distinct case name with its IOC count."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''
        SELECT case_name, COUNT(DISTINCT ioc_id) AS ioc_count
        FROM ioc_tags
        WHERE case_name IS NOT NULL AND case_name != ''
        GROUP BY case_name
        ORDER BY ioc_count DESC, case_name ASC
        '''
    )
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def list_cases_with_summary() -> list[dict]:
    """List cases enriched with derived severity + opened timestamps.

    Severity = max ``iocs.last_score`` across the case's members. Opened
    = min ``ioc_tags.created`` for the case_name. Both are derived at
    query time rather than stored as separate columns — the existing
    ``ioc_tags`` schema doesn't carry them, and re-deriving keeps the
    case view always in sync with whatever the latest enrichment said.
    Used by the brutalist Cases tab via ``/api/ui/cases``.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''
        SELECT
            t.case_name,
            COUNT(DISTINCT t.ioc_id) AS ioc_count,
            COALESCE(MAX(i.last_score), 0) AS severity,
            MIN(t.created) AS opened_at
        FROM ioc_tags t
        JOIN iocs i ON i.id = t.ioc_id
        WHERE t.case_name IS NOT NULL AND t.case_name != ''
        GROUP BY t.case_name
        ORDER BY severity DESC, ioc_count DESC, t.case_name ASC
        '''
    )
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def remove_case(case_name: str) -> int:
    """Detach every IOC from ``case_name``.

    Deletes the ``ioc_tags`` rows whose ``case_name`` matches. Returns
    the count of removed rows; ``0`` for a no-op or unknown case. The
    underlying IOCs and their enrichments are preserved — this only
    untags the case relationship.
    """
    if not case_name:
        return 0
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM ioc_tags WHERE case_name = ?",
        (case_name,),
    )
    removed = cursor.rowcount
    conn.commit()
    conn.close()
    return max(0, removed)


def set_ioc_case(ioc_value: str, case_name: str | None) -> bool:
    """Assign or unassign a case for an IOC.

    ``case_name=None`` (or empty) removes every case_name row for the IOC
    — but preserves other tag-only rows. A non-empty value first clears
    any existing case_name rows for the IOC (an IOC can only belong to
    one case at a time in the UI), then inserts the fresh assignment.

    Returns True if the IOC was found, False otherwise. The mutation is
    idempotent: setting the same case twice silently re-inserts via the
    UPSERT path in ``tag_ioc``.
    """
    ioc_id = get_ioc_id(ioc_value)
    if ioc_id is None:
        return False
    conn = get_db_connection()
    cursor = conn.cursor()
    # Clear any prior case assignment first — single-case-per-IOC is the
    # UI's mental model. Tag-only rows (case_name IS NULL) stay intact.
    cursor.execute(
        "DELETE FROM ioc_tags WHERE ioc_id = ? AND case_name IS NOT NULL",
        (ioc_id,),
    )
    conn.commit()
    conn.close()
    if case_name and case_name.strip():
        tag_ioc(ioc_id, tag=None, case=case_name.strip(), note=None)
    return True


def list_tags() -> list[dict]:
    """List every distinct tag with its IOC count (case-agnostic)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''
        SELECT tag, COUNT(DISTINCT ioc_id) AS ioc_count
        FROM ioc_tags
        WHERE tag IS NOT NULL AND tag != ''
        GROUP BY tag
        ORDER BY ioc_count DESC, tag ASC
        '''
    )
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def update_last_score(ioc_id: int, score: int) -> None:
    """Persist the latest composite score on the iocs row + append a history row.

    The history row is a snapshot of ``(ioc_id, score, recorded_at)`` and
    is the data source for the Watch tab's true score-over-time graph
    (instead of the previous one-step delta against ``last_score``).
    Cheap insert, fire-and-forget — same suppression that wraps the
    caller protects the enrichment pipeline from any storage failure.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    score_int = int(score)
    cursor.execute('UPDATE iocs SET last_score = ? WHERE id = ?', (score_int, ioc_id))
    cursor.execute(
        'INSERT INTO score_history (ioc_id, score, recorded_at) '
        'VALUES (?, ?, ?)',
        (ioc_id, score_int, datetime.now()),
    )
    conn.commit()
    conn.close()


def get_score_history(ioc_id: int, *, limit: int = 200) -> list[dict]:
    """Return chronological score snapshots for an IOC (oldest first).

    Used by ``GET /api/ui/score_history/{value}`` to drive the Watch tab
    graph. ``limit`` defaults to 200 because the Watch panel only needs
    a recent window; older data is still preserved on disk for ad-hoc
    queries. Returns an empty list when no history rows exist.
    """
    if limit <= 0:
        return []
    conn = get_db_connection()
    try:
        rows = conn.execute(
            'SELECT id, score, recorded_at FROM score_history '
            'WHERE ioc_id = ? ORDER BY recorded_at ASC, id ASC LIMIT ?',
            (ioc_id, int(limit)),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def list_iocs(case: str | None = None) -> list[dict]:
    """Return every IOC, optionally filtered to a single case."""
    conn = get_db_connection()
    cursor = conn.cursor()
    if case:
        cursor.execute(
            '''
            SELECT DISTINCT i.id, i.value, i.type, i.last_score, i.last_seen
            FROM iocs i
            JOIN ioc_tags t ON t.ioc_id = i.id
            WHERE t.case_name = ?
            ORDER BY i.last_seen DESC
            ''',
            (case,),
        )
    else:
        cursor.execute(
            'SELECT id, value, type, last_score, last_seen FROM iocs ORDER BY last_seen DESC'
        )
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def remove_tag(ioc_id: int, tag: str | None = None, case: str | None = None) -> int:
    """Delete a specific tag row. Returns the number of rows deleted."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''
        DELETE FROM ioc_tags
        WHERE ioc_id = ? AND tag IS ? AND case_name IS ?
        ''',
        (ioc_id, tag, case),
    )
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    return deleted

def add_or_update_ioc(value, ioc_type, tags=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now()

    cursor.execute('SELECT id, first_seen FROM iocs WHERE value = ?', (value,))
    row = cursor.fetchone()

    if row:
        ioc_id = row['id']
        cursor.execute('''
            UPDATE iocs SET last_seen = ?, tags = ? WHERE id = ?
        ''', (now, json.dumps(tags) if tags else None, ioc_id))
    else:
        cursor.execute('''
            INSERT INTO iocs (value, type, first_seen, last_seen, tags)
            VALUES (?, ?, ?, ?, ?)
        ''', (value, ioc_type, now, now, json.dumps(tags) if tags else None))
        ioc_id = cursor.lastrowid

    conn.commit()
    conn.close()
    return ioc_id

def get_ioc_id(value):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM iocs WHERE value = ?', (value,))
    row = cursor.fetchone()
    conn.close()
    return row['id'] if row else None

def add_enrichment(ioc_id, source, data, score):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now()

    cursor.execute('''
        INSERT INTO enrichments (ioc_id, source, data, timestamp, score)
        VALUES (?, ?, ?, ?, ?)
    ''', (ioc_id, source, json.dumps(data), now, score))
    enrichment_id = cursor.lastrowid or 0
    if enrichment_id:
        _insert_enrichment_fields(cursor, enrichment_id, ioc_id, data)

    conn.commit()
    conn.close()

def get_all_enrichments(ioc_id: int) -> list[dict]:
    """Return every cached enrichment row for an IOC, oldest first.

    Used by the history view to render a chronological scoreline.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''
        SELECT id, source, score, timestamp, data
        FROM enrichments
        WHERE ioc_id = ?
        ORDER BY timestamp ASC
        ''',
        (ioc_id,),
    )
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_latest_enrichment(ioc_id, source):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT * FROM enrichments
        WHERE ioc_id = ? AND source = ?
        ORDER BY timestamp DESC LIMIT 1
    ''', (ioc_id, source))

    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_recent_iocs(limit: int = 8) -> list[dict]:
    """Return newest IOCs that have at least one enrichment row.

    Ordered by `iocs.last_seen` desc so the dashboard recent strip mirrors
    "what was enriched most recently in this workspace". Each entry has the
    columns the brutalist UI shape needs upstream:
        {id, value, type, last_seen, last_score}

    Used by the `/api/ui/recent` endpoint to seed the dashboard from real
    cache instead of demo fixtures. `limit <= 0` returns an empty list.
    """
    if limit <= 0:
        return []
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''
        SELECT i.id, i.value, i.type, i.last_seen, i.last_score
        FROM iocs i
        WHERE EXISTS (
            SELECT 1 FROM enrichments e WHERE e.ioc_id = i.id
        )
        ORDER BY i.last_seen DESC
        LIMIT ?
        ''',
        (int(limit),),
    )
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def find_iocs_by_field(
    needle: str,
    *,
    kind: str = "any",
    limit: int = 16,
    exclude_value: str | None = None,
) -> list[dict]:
    """Find IOCs whose latest enrichments mention ``needle``.

    Used by the pivot endpoint to surface related infrastructure across
    the whole workspace, not just whatever happens to be on the recent
    strip. The match is a case-insensitive substring scan over the JSON
    text of each enrichment row, with kind-specific refinements:

    * ``kind="tag"`` — needle wrapped in quotes so an array element
      `"emotet"` matches but the substring "emotetable" doesn't.
    * ``kind="malware"`` / ``kind="family"`` — same quoted exact match,
      keyed on either the ``malware`` or ``family`` field shape.
    * ``kind="registrar"`` — quoted match on the registrar key payload.
    * ``kind="ioc"`` — search the ``iocs.value`` column directly (cheap
      direct lookup, no JSON scan).
    * ``kind="any"`` — bare substring, the most permissive form.

    Returns the same row shape as ``get_recent_iocs`` so the API layer
    can reuse ``_build_modules_from_cache`` + ``_to_ui_shape`` to ship
    pivot results in the brutalist UI shape. Empty list when nothing
    matches — never raises on a malformed needle.
    """
    needle = (needle or "").strip()
    if not needle or limit <= 0:
        return []
    conn = get_db_connection()
    cursor = conn.cursor()

    if kind == "ioc":
        # Direct lookup on iocs.value — `LIKE` so the user can pivot on
        # a partial domain too (e.g. clicking "evil.example" matches
        # subdomains).
        sql = (
            "SELECT id, value, type, last_seen, last_score FROM iocs "
            "WHERE LOWER(value) LIKE ? "
        )
        params: list = [f"%{needle.lower()}%"]
        if exclude_value:
            sql += "AND value != ? "
            params.append(exclude_value)
        sql += "ORDER BY last_seen DESC LIMIT ?"
        params.append(int(limit))
        cursor.execute(sql, params)
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

    # Indexable kinds hit the `enrichment_fields` side table (built by
    # ``_insert_enrichment_fields`` at write time). The (kind, value)
    # index makes this O(log n) lookup instead of the full-scan LIKE on
    # `enrichments.data` we used to do.
    if kind in ("tag", "malware", "family", "registrar"):
        sql = (
            "SELECT i.id, i.value, i.type, MAX(e.timestamp) AS last_seen, "
            "       i.last_score "
            "FROM enrichment_fields f "
            "JOIN iocs i ON i.id = f.ioc_id "
            "JOIN enrichments e ON e.ioc_id = i.id "
            "WHERE f.kind = ? AND f.value = ? COLLATE NOCASE "
        )
        params = [kind, needle]
        if exclude_value:
            sql += "AND i.value != ? "
            params.append(exclude_value)
        sql += "GROUP BY i.id ORDER BY last_seen DESC LIMIT ?"
        params.append(int(limit))
        cursor.execute(sql, params)
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

    # Fallback: `kind="any"` still uses the substring LIKE. Cheaper than
    # extending the index to "every string anywhere", which would balloon
    # the side table for marginal value.
    pattern = f"%{needle.lower()}%"

    sql = (
        "SELECT i.id, i.value, i.type, MAX(e.timestamp) AS last_seen, i.last_score "
        "FROM iocs i "
        "JOIN enrichments e ON e.ioc_id = i.id "
        "WHERE LOWER(e.data) LIKE ? "
    )
    params = [pattern]
    if exclude_value:
        sql += "AND i.value != ? "
        params.append(exclude_value)
    sql += "GROUP BY i.id ORDER BY last_seen DESC LIMIT ?"
    params.append(int(limit))
    cursor.execute(sql, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


# ---------------------------------------------------------------------------
# Retention / cache maintenance
# ---------------------------------------------------------------------------
#
# `add_enrichment` appends a new row on every fetch; without a janitor those
# rows accumulate forever. The functions below let analysts (or the auto-
# prune hook in `core/enrich.py`) bound the cache by age, by per-source row
# count, or wipe slices explicitly. They all operate on the *currently active
# workspace* — `set_workspace` rewires `DB_PATH` first.


def prune_enrichments_older_than(days: float) -> int:
    """Delete enrichment rows whose timestamp is older than ``days``.

    Returns the number of rows removed. ``days <= 0`` is a no-op (returns 0)
    so that misconfigured retention envs can't accidentally wipe everything.
    """
    if days <= 0:
        return 0
    conn = get_db_connection()
    cursor = conn.cursor()
    # Stored as ISO 8601 with a space separator — `datetime('now', '-Nd')`
    # produces the same shape, so a string comparison is exact.
    cursor.execute(
        "DELETE FROM enrichments WHERE timestamp < datetime('now', ?)",
        (f"-{days} days",),
    )
    removed = cursor.rowcount
    conn.commit()
    conn.close()
    return max(0, removed)


def prune_enrichments_keep_last_n(n: int) -> int:
    """Keep only the newest ``n`` rows per (ioc_id, source) pair.

    Useful for capping history-bloat while still preserving the most recent
    chronology that the `history` view renders. Returns the number of rows
    removed. ``n <= 0`` is a no-op (returns 0).
    """
    if n <= 0:
        return 0
    conn = get_db_connection()
    cursor = conn.cursor()
    # Window-function-free implementation: rank rows per group by descending
    # timestamp via a correlated subquery, then delete anything past the cap.
    cursor.execute(
        '''
        DELETE FROM enrichments
        WHERE id IN (
            SELECT e1.id FROM enrichments e1
            WHERE (
                SELECT COUNT(*) FROM enrichments e2
                WHERE e2.ioc_id = e1.ioc_id
                  AND e2.source = e1.source
                  AND e2.timestamp > e1.timestamp
            ) >= ?
        )
        ''',
        (n,),
    )
    removed = cursor.rowcount
    conn.commit()
    conn.close()
    return max(0, removed)


def clear_enrichments(
    *,
    source: str | None = None,
    ioc_value: str | None = None,
    all: bool = False,
) -> int:
    """Delete enrichment rows by source, by IOC value, or wholesale.

    Exactly one of ``source``, ``ioc_value``, ``all`` must be truthy. The
    function refuses an empty filter set rather than silently deleting
    everything — pass ``all=True`` explicitly to wipe the table.
    """
    active = [bool(source), bool(ioc_value), bool(all)]
    if sum(active) != 1:
        raise ValueError(
            "clear_enrichments: pass exactly one of source=, ioc_value=, all=True"
        )
    conn = get_db_connection()
    cursor = conn.cursor()
    if all:
        cursor.execute("DELETE FROM enrichments")
    elif source:
        cursor.execute("DELETE FROM enrichments WHERE source = ?", (source,))
    else:
        cursor.execute(
            '''
            DELETE FROM enrichments
            WHERE ioc_id IN (SELECT id FROM iocs WHERE value = ?)
            ''',
            (ioc_value,),
        )
    removed = cursor.rowcount
    conn.commit()
    conn.close()
    return max(0, removed)


def cache_stats() -> dict:
    """Return a snapshot of the enrichment cache for the active workspace.

    Shape:
        {
            "db_path": "...",
            "db_size_bytes": int,
            "ioc_count": int,
            "enrichment_count": int,
            "oldest_timestamp": str | None,
            "newest_timestamp": str | None,
            "per_source": [{"source": str, "rows": int}, ...],   # desc by rows
        }
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM iocs")
    ioc_count = int(cursor.fetchone()[0])
    cursor.execute("SELECT COUNT(*) FROM enrichments")
    enr_count = int(cursor.fetchone()[0])
    cursor.execute(
        "SELECT MIN(timestamp), MAX(timestamp) FROM enrichments"
    )
    oldest, newest = cursor.fetchone()
    cursor.execute(
        '''
        SELECT source, COUNT(*) AS rows
        FROM enrichments
        GROUP BY source
        ORDER BY rows DESC, source ASC
        '''
    )
    per_source = [{"source": r[0], "rows": int(r[1])} for r in cursor.fetchall()]
    conn.close()
    size = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
    return {
        "db_path": DB_PATH,
        "db_size_bytes": size,
        "ioc_count": ioc_count,
        "enrichment_count": enr_count,
        "oldest_timestamp": oldest,
        "newest_timestamp": newest,
        "per_source": per_source,
    }


# ---------------------------------------------------------------------------
# Auto-prune scheduling marker
# ---------------------------------------------------------------------------
#
# A tiny key/value meta table lets the auto-prune hook in core/enrich.py
# remember when it last ran without bloating the schema with a dedicated
# table. The table is created on demand so existing DBs migrate silently.


def _ensure_meta_table(cursor) -> None:
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        '''
    )


def get_meta(key: str) -> str | None:
    conn = get_db_connection()
    cursor = conn.cursor()
    _ensure_meta_table(cursor)
    cursor.execute("SELECT value FROM meta WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None


def set_meta(key: str, value: str) -> None:
    conn = get_db_connection()
    cursor = conn.cursor()
    _ensure_meta_table(cursor)
    cursor.execute(
        '''
        INSERT INTO meta (key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        ''',
        (key, value),
    )
    conn.commit()
    conn.close()

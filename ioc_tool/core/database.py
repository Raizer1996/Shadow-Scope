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

    conn.commit()
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
    """Persist the latest composite score on the iocs row. Drives watch-mode diffing."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE iocs SET last_score = ? WHERE id = ?', (int(score), ioc_id))
    conn.commit()
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

import json
import os
import sqlite3
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'ioc.db')

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
            tags TEXT
        )
    ''')

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

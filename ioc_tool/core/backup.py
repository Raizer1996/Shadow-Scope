"""Back up and restore the local database.

One SQLite file holds everything that is yours: cached source answers, score
history, verdicts, notes, cases, watchlist, saved filters and block/allow
lists. API keys live in ``.env`` and are **never** part of a backup.

* :func:`snapshot` writes a consistent copy using SQLite's online backup API,
  so it is safe while the server is running.
* :func:`inspect` checks that a file really is a healthy ShadowScope database
  and says what it holds — used for the "are you sure?" step.
* :func:`restore` replaces the live database with a backup, after first
  saving the current one next to it as ``<name>.pre-restore-<time>.bak``.
"""

from __future__ import annotations

import contextlib
import glob
import os
import sqlite3
from datetime import datetime
from typing import Any

from . import database

_MAGIC = b"SQLite format 3\x00"
_REQUIRED_TABLES = ("iocs", "enrichments")
_COUNTED = ("iocs", "enrichments", "ioc_notes", "cases", "watchlist", "user_lists", "saved_filters")
KEEP_PRE_RESTORE = 3


class BackupError(ValueError):
    """The file cannot be used as a backup."""


def snapshot(dest_path: str) -> int:
    """Write a consistent copy of the live database to ``dest_path``. Returns its size."""
    database.init_db()
    src = sqlite3.connect(database.DB_PATH)
    try:
        dest = sqlite3.connect(dest_path)
        try:
            src.backup(dest)
        finally:
            dest.close()
    finally:
        src.close()
    return os.path.getsize(dest_path)


def _counts(conn: sqlite3.Connection) -> dict[str, int]:
    have = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    return {t: int(conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]) for t in _COUNTED if t in have}


def current_summary() -> dict[str, int]:
    """Row counts of the live database."""
    database.init_db()
    conn = sqlite3.connect(database.DB_PATH)
    try:
        return _counts(conn)
    finally:
        conn.close()


def inspect(path: str) -> dict[str, Any]:
    """Validate a candidate backup file. Returns ``{size, counts, newest}``.

    Raises :class:`BackupError` when the file is not SQLite, fails SQLite's
    integrity check, or lacks the tables every ShadowScope database has.
    The file is opened read-only.
    """
    try:
        with open(path, "rb") as fh:
            if fh.read(len(_MAGIC)) != _MAGIC:
                raise BackupError("not a SQLite database file")
    except OSError as exc:
        raise BackupError(f"cannot read the file: {exc}") from exc
    uri = "file:" + path.replace("\\", "/").replace("?", "%3f").replace("#", "%23") + "?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        raise BackupError(f"cannot open the database: {exc}") from exc
    try:
        try:
            verdict = conn.execute("PRAGMA integrity_check").fetchone()[0]
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        except sqlite3.DatabaseError as exc:
            raise BackupError(f"the database is damaged: {exc}") from exc
        if verdict != "ok":
            raise BackupError(f"the database fails its integrity check: {str(verdict)[:120]}")
        missing = [t for t in _REQUIRED_TABLES if t not in tables]
        if missing:
            raise BackupError("not a ShadowScope database (no " + ", ".join(missing) + " table)")
        newest = conn.execute("SELECT MAX(last_seen) FROM iocs").fetchone()[0]
        return {"size": os.path.getsize(path), "counts": _counts(conn), "newest": str(newest)[:16] if newest else None}
    finally:
        conn.close()


def restore(src_path: str) -> dict[str, Any]:
    """Replace the live database with ``src_path``.

    The current database is first saved as ``<db>.pre-restore-<time>.bak``
    (the newest few are kept). The copy runs through SQLite's backup API
    inside one transaction on the live file, so a failure leaves the old
    contents in place. Older-schema backups are migrated by ``init_db``.
    """
    info = inspect(src_path)
    database.init_db()
    live = database.DB_PATH
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    saved = f"{live}.pre-restore-{stamp}.bak"
    snapshot(saved)

    src = sqlite3.connect(src_path)
    try:
        dest = sqlite3.connect(live)
        try:
            src.backup(dest)
        finally:
            dest.close()
    finally:
        src.close()
    database.init_db()

    old = sorted(glob.glob(glob.escape(live) + ".pre-restore-*.bak"))
    for stale in old[:-KEEP_PRE_RESTORE]:
        with contextlib.suppress(OSError):
            os.remove(stale)
    return {"restored": info["counts"], "previous_saved_as": os.path.basename(saved)}

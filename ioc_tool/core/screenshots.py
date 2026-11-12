"""Page screenshots from urlscan.io, fetched by the local server on demand.

The cached URLscan answer for an IP / domain / URL already lists past scans,
each with a screenshot urlscan.io took in its own sandbox. Seeing the page
— a fake login form, a parked domain, a blank 404 — is often faster than
reading ten source rows, and it is safe: nobody here visits the site.

Design points:

* **On demand.** Nothing is fetched until the analyst asks for one image.
* **Through the server, not the browser.** The dashboard never loads
  urlscan.io directly; the request goes out through ``core.http`` like any
  other source call (rate-limited, counted by the quota meter).
* **Not an open proxy.** The only URL ever requested is
  ``https://urlscan.io/screenshots/<uuid>.png``, where ``<uuid>`` must be a
  well-formed scan id that appears in *this indicator's* cached answer.
* **Cached on disk** next to the database (``screenshots/``), newest
  :data:`MAX_FILES` kept, so an image is downloaded once.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
from typing import Any

from . import database, http

_SOURCE = "urlscan"
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_URL = "https://urlscan.io/screenshots/{uuid}.png"
MAX_BYTES = 6 * 1024 * 1024
MAX_FILES = 200
TIMEOUT = 20


def valid_uuid(value: Any) -> bool:
    return isinstance(value, str) and bool(_UUID_RE.match(value))


def list_scans(ioc_id: int, *, limit: int = 8) -> list[dict[str, Any]]:
    """Past urlscan.io scans named in the indicator's cached answer, newest first."""
    row = database.get_latest_enrichment(ioc_id, _SOURCE)
    if not row:
        return []
    try:
        data = json.loads(row["data"])
    except (TypeError, ValueError):
        return []
    results = data.get("results") if isinstance(data, dict) else None
    scans: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in results if isinstance(results, list) else []:
        if not isinstance(item, dict):
            continue
        uuid = item.get("_id")
        if not isinstance(uuid, str) or not valid_uuid(uuid) or uuid in seen or not item.get("screenshot"):
            continue
        seen.add(uuid)
        raw_task, raw_page = item.get("task"), item.get("page")
        task: dict[str, Any] = raw_task if isinstance(raw_task, dict) else {}
        page: dict[str, Any] = raw_page if isinstance(raw_page, dict) else {}

        def text(value: Any, cap: int) -> str | None:
            return value[:cap] if isinstance(value, str) and value else None

        scans.append({
            "uuid": uuid,
            "time": text(task.get("time"), 32),
            "url": text(page.get("url") or task.get("url"), 300),
            "title": text(page.get("title"), 200),
            "status": text(str(page.get("status")) if page.get("status") is not None else None, 8),
            "cached": os.path.exists(_path(uuid)),
        })
    scans.sort(key=lambda s: s["time"] or "", reverse=True)
    return scans[:max(1, limit)]


def _dir() -> str:
    return os.path.join(os.path.dirname(database.DB_PATH) or ".", "screenshots")


def _path(uuid: str) -> str:
    return os.path.join(_dir(), f"{uuid}.png")


def _prune() -> None:
    try:
        files = [os.path.join(_dir(), f) for f in os.listdir(_dir()) if f.endswith(".png")]
    except OSError:
        return
    files.sort(key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0)
    for stale in files[:-MAX_FILES] if len(files) > MAX_FILES else []:
        with contextlib.suppress(OSError):
            os.remove(stale)


def fetch(uuid: str) -> bytes | None:
    """PNG bytes for one scan, from the disk cache or urlscan.io. None on any failure."""
    if not valid_uuid(uuid):
        return None
    path = _path(uuid)
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError:
        pass
    response = http.get(_SOURCE, _URL.format(uuid=uuid), timeout=TIMEOUT)
    if response is None or response.status_code != 200:
        return None
    body = response.content
    if not isinstance(body, bytes) or not body.startswith(_PNG_MAGIC) or len(body) > MAX_BYTES:
        return None
    with contextlib.suppress(OSError):
        os.makedirs(_dir(), exist_ok=True)
        tmp = f"{path}.{os.getpid()}.part"
        with open(tmp, "wb") as fh:
            fh.write(body)
        os.replace(tmp, path)
        _prune()
    return body

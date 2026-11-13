"""abuse.ch YARAify — which YARA rules and ClamAV signatures match a file.

YARAify scans submitted files against public and community YARA rules and
ClamAV signatures. Looking a hash up tells you whether *anyone* has
submitted that file and what matched — content-based evidence that is
independent of AV-vendor verdicts.

This module only **looks hashes up**. It never submits a file.

API docs: https://yaraify.abuse.ch/api/

* ``POST https://yaraify-api.abuse.ch/api/v1/`` with a JSON body
  ``{"query": "lookup_hash", "search_term": "<md5|sha1|sha256>"}``
* header ``Auth-Key`` — the same abuse.ch key as URLhaus / ThreatFox /
  MalwareBazaar (``ABUSECH_AUTH_KEY``).

The raw answer repeats every match once per scan task and can be large, so
it is reduced to a summary: file metadata, the de-duplicated rule and
signature names, and the malware families those names point to.

Soft-fail contract: any failure or "unknown hash" returns ``None``.
"""

from __future__ import annotations

import re
from typing import Any

from ..core import http
from . import _abusech

BASE_URL = "https://yaraify-api.abuse.ch/api/v1/"
TIMEOUT = 15

_SOURCE = "yaraify"
_MAX_RULES = 40
_MAX_SIGNATURES = 25

# Malpedia's generated rules are named <platform>_<family>_auto, which maps
# straight onto the Malpedia family id (win.emotet) other sources use.
_MALPEDIA_RULE = re.compile(r"^(win|elf|osx|apk|jar|js|py|ps1|vbs|symbian|ios)_([a-z0-9_]+?)_(?:auto|w\d+)$", re.IGNORECASE)


def _rule(entry: Any, *, unpacked: bool) -> dict[str, Any] | None:
    if not isinstance(entry, dict):
        return None
    name = entry.get("rule_name")
    if not isinstance(name, str) or not name.strip():
        return None
    out: dict[str, Any] = {"rule_name": name.strip(), "unpacked": unpacked}
    for key in ("author", "description", "reference", "tlp"):
        val = entry.get(key)
        if isinstance(val, str) and val.strip():
            out[key] = val.strip()[:200]
    return out


def summarise(data: dict[str, Any]) -> dict[str, Any] | None:
    """Reduce a ``lookup_hash`` ``data`` object to the fields worth caching."""
    raw_meta, raw_tasks = data.get("metadata"), data.get("tasks")
    meta: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
    tasks: list[Any] = raw_tasks if isinstance(raw_tasks, list) else []
    if not meta and not tasks:
        return None

    rules: dict[str, dict[str, Any]] = {}
    signatures: dict[str, None] = {}
    for task in tasks:
        if not isinstance(task, dict):
            continue
        for sig in task.get("clamav_results") or []:
            if isinstance(sig, str) and sig.strip():
                signatures.setdefault(sig.strip())
        for entry in task.get("static_results") or []:
            rule = _rule(entry, unpacked=False)
            if rule:
                rules.setdefault(rule["rule_name"].lower(), rule)
        for unpacked in task.get("unpack_results") or []:
            if not isinstance(unpacked, dict):
                continue
            for entry in unpacked.get("unpacked_yara_matches") or []:
                rule = _rule(entry, unpacked=True)
                if rule:
                    rules.setdefault(rule["rule_name"].lower(), rule)

    families: dict[str, None] = {}
    for rule in rules.values():
        m = _MALPEDIA_RULE.match(rule["rule_name"])
        if m:
            families.setdefault(f"{m.group(1).lower()}.{m.group(2).lower()}")

    out: dict[str, Any] = {
        "sightings": meta.get("sightings"),
        "first_seen": meta.get("first_seen"),
        "last_seen": meta.get("last_seen"),
        "file_size": meta.get("file_size"),
        "file_type_mime": meta.get("file_type_mime"),
        "sha256_hash": meta.get("sha256_hash"),
        "imphash": meta.get("imphash"),
        "tlsh": meta.get("tlsh"),
        "scans": len([t for t in tasks if isinstance(t, dict)]),
        "yara_rule_count": len(rules),
        "yara_rules": list(rules.values())[:_MAX_RULES],
        "clamav": list(signatures)[:_MAX_SIGNATURES],
        "families": list(families),
    }
    if families:
        # Top-level ``family`` joins the pivot index, so a file can be related
        # to other indicators of the same Malpedia family.
        out["family"] = next(iter(families))
    return out


def enrich_hash(value: str) -> dict | None:
    """Look a hash up on YARAify. ``None`` when unknown, unauthenticated or on error."""
    if not _abusech.configured():
        return None  # the API answers 401 without an Auth-Key; skip the round-trip
    response = http.post(
        _SOURCE,
        BASE_URL,
        json={"query": "lookup_hash", "search_term": value},
        headers=_abusech.auth_headers(),
        timeout=TIMEOUT,
    )
    if response is None or response.status_code != 200:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict) or payload.get("query_status") != "ok":
        return None
    data = payload.get("data")
    if not isinstance(data, dict):
        return None
    return summarise(data)

"""One way to load ``.env`` for every entry point — CLI, REST server, MCP server.

Two things used to go wrong:

* The MCP server looked for ``.env`` next to the package, which only exists
  in a source checkout. Installed copies keep it in the per-user home
  (:func:`paths.env_file`), so the MCP tools saw no API keys at all.
* ``python-dotenv`` keeps the **last** value of a repeated key. The template
  ships empty ``KEY=`` lines, so pasting ``KEY=value`` on a new line *above*
  the empty one silently left the source switched off.

:func:`load` reads the right file and, for a repeated key whose last value is
empty, keeps the last **non-empty** one and records a warning naming the key
(never its value). Variables already present in the real environment always
win, as with ``load_dotenv``.
"""

from __future__ import annotations

import io
import os
import re

from dotenv import dotenv_values, load_dotenv

from . import paths

_ASSIGN = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")
_WARNINGS: list[str] = []


def warnings() -> list[str]:
    """Problems noticed in the ``.env`` file on the last :func:`load`. Key names only."""
    return list(_WARNINGS)


def _assignments(text: str) -> dict[str, list[tuple[int, str]]]:
    """``{KEY: [(line_no, raw_line), ...]}`` for every uncommented assignment."""
    found: dict[str, list[tuple[int, str]]] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("#"):
            continue
        match = _ASSIGN.match(line)
        if match:
            found.setdefault(match.group(1), []).append((number, line))
    return found


def _value(line: str) -> str:
    """Parse one ``KEY=value`` line the way python-dotenv would."""
    parsed = dotenv_values(stream=io.StringIO(line + "\n"))
    return next(iter(parsed.values()), None) or ""


def load(path: str | None = None) -> list[str]:
    """Load ``.env`` into ``os.environ``. Returns warnings (also via :func:`warnings`)."""
    target = path or paths.env_file()
    _WARNINGS.clear()
    try:
        with open(target, encoding="utf-8-sig") as fh:
            text = fh.read()
    except OSError:
        return []

    already = set(os.environ)
    # utf-8-sig: Notepad's UTF-8-with-BOM would otherwise glue U+FEFF onto the
    # first key name and silently drop it.
    load_dotenv(target, encoding="utf-8-sig")

    for key, lines in _assignments(text).items():
        if len(lines) < 2:
            continue
        values = [(number, _value(raw)) for number, raw in lines]
        filled = [(number, value) for number, value in values if value.strip()]
        where = ", ".join(str(number) for number, _ in values)
        if not filled:
            continue
        last_number, last_value = values[-1]
        if not last_value.strip():
            keep_number, keep_value = filled[-1]
            if key not in already:
                os.environ[key] = keep_value
            _WARNINGS.append(
                f"{key} is set on lines {where} of .env and the last one (line {last_number}) is empty — "
                f"using the value from line {keep_number}. Delete the empty line."
            )
        elif len({value for _, value in filled}) > 1:
            _WARNINGS.append(
                f"{key} is set on lines {where} of .env with different values — the last one (line {last_number}) is used."
            )
    return warnings()

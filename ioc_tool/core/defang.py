"""Defang / refang IOC strings.

Threat analysts commonly share IOCs in *defanged* form so that links don't
auto-fire in mail clients, ticket systems, or chat. Examples::

    1[.]2[.]3[.]4
    hxxp://evil[.]com/path
    bad[.]example[.]com
    attacker[at]gmail[.]com

This module provides two pure functions:

* :func:`refang` — convert a defanged IOC back to its live form so the
  rest of ShadowScope's parser / enrichment pipeline can recognise it.
* :func:`defang` — convert a live IOC into a link-safe form suitable for
  inclusion in human-readable reports.

Both functions are idempotent and dependency-free (stdlib only).
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Refang — defanged → live
# ---------------------------------------------------------------------------

# Order matters: handle multi-character tokens (``[at]``, ``hxxp``) before
# single-character bracket tokens so the simpler rules don't accidentally
# corrupt the longer ones.
_REFANG_TEXT_REPLACEMENTS: tuple[tuple[str, str], ...] = (
    # @ variants — handle "[at]" / "(at)" first
    ("[at]", "@"),
    ("(at)", "@"),
    ("{at}", "@"),
    (" at ", "@"),  # rare but seen ("user at example dot com")
    # bracketed @
    ("[@]", "@"),
    ("(@)", "@"),
    ("{@}", "@"),
    # bracketed dot
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    # bracketed colon
    ("[:]", ":"),
    ("(:)", ":"),
    ("{:}", ":"),
    # bracketed slashes (less common but seen)
    ("[/]", "/"),
    ("(/)", "/"),
)

# Scheme rewrites. Use a regex so we can preserve case style ("hXXp" → "http",
# "HXXP" → "HTTP") and only match at the start of a scheme.
_SCHEME_PATTERN = re.compile(
    r"\b(h)(x{2})(ps?)://",
    re.IGNORECASE,
)
_FTP_SCHEME_PATTERN = re.compile(r"\bfxp://", re.IGNORECASE)


def _restore_http_scheme(match: re.Match[str]) -> str:
    """Convert an ``hxxp(s)://`` match back to ``http(s)://`` preserving case.

    The middle ``xx`` segment is rewritten to ``tt`` using the case of the
    original ``xx`` characters so ``HXXP`` → ``HTTP``, ``hxxp`` → ``http``,
    ``hXXp`` → ``htTp`` (close enough — matches common analyst conventions).
    """
    h, xx, ps = match.group(1), match.group(2), match.group(3)
    tt = "".join("T" if ch.isupper() else "t" for ch in xx)
    return f"{h}{tt}{ps}://"


def refang(value: str) -> str:
    """Convert a defanged IOC string back to its live form.

    Handles the common defanging conventions used by analysts:

    * ``[.]`` ``(.)`` ``{.}`` → ``.``
    * ``[:]`` ``(:)`` ``{:}`` → ``:``
    * ``[@]`` ``(@)`` ``{@}`` ``[at]`` ``(at)`` → ``@``
    * ``hxxp://`` ``hxxps://`` ``hXXp://`` → ``http(s)://`` (case-aware)
    * ``fxp://`` → ``ftp://``
    * Leading / trailing whitespace stripped.

    Idempotent: ``refang(refang(x)) == refang(x)``.
    """
    if value is None:
        return value  # type: ignore[return-value]

    out = value.strip()

    for needle, replacement in _REFANG_TEXT_REPLACEMENTS:
        if needle in out:
            out = out.replace(needle, replacement)

    out = _SCHEME_PATTERN.sub(_restore_http_scheme, out)
    out = _FTP_SCHEME_PATTERN.sub(lambda m: "FTP://" if m.group(0).isupper() else "ftp://", out)

    return out


# ---------------------------------------------------------------------------
# Defang — live → safe-to-share
# ---------------------------------------------------------------------------

# Pre-compile patterns we use during defang. We intentionally do NOT touch
# path separators (``/``) — many analyst tools only defang dots / schemes / @.
_HTTPS_SCHEME = re.compile(r"\bhttps://", re.IGNORECASE)
_HTTP_SCHEME = re.compile(r"\bhttp://", re.IGNORECASE)
_FTP_SCHEME = re.compile(r"\bftp://", re.IGNORECASE)

# A dot is "already defanged" if it's wrapped in square brackets — used to
# keep :func:`defang` idempotent.
_LIVE_DOT = re.compile(r"(?<!\[)\.(?!\])")
_LIVE_AT = re.compile(r"(?<!\[)@(?!\])")


def defang(value: str) -> str:
    """Convert a live IOC string into a defanged, link-safe form.

    Conventional output::

        .  →  [.]
        @  →  [@]
        http://   →  hxxp://
        https://  →  hxxps://
        ftp://    →  fxp://

    Path separators are *not* defanged (analyst convention).
    Idempotent: ``defang(defang(x)) == defang(x)``.
    """
    if value is None:
        return value  # type: ignore[return-value]

    out = value.strip()

    # Schemes first, before dots get bracketed (so we don't have to deal with
    # ``hxxps://`` containing already-bracketed text).
    out = _HTTPS_SCHEME.sub(lambda m: "hXXps://" if m.group(0).isupper() else "hxxps://", out)
    out = _HTTP_SCHEME.sub(lambda m: "hXXp://" if m.group(0).isupper() else "hxxp://", out)
    out = _FTP_SCHEME.sub(lambda m: "fXp://" if m.group(0).isupper() else "fxp://", out)

    # Then bracket bare dots / @s that aren't already bracketed.
    out = _LIVE_DOT.sub("[.]", out)
    out = _LIVE_AT.sub("[@]", out)

    return out

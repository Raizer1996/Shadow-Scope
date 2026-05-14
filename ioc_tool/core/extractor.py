"""Extract IOCs from arbitrary free-form text blobs.

Analysts receive IOCs embedded in prose — tickets, emails, threat reports,
log dumps. This module pulls them out so the rest of the enrichment pipeline
can score them in one pass.

Pipeline:

1. :func:`ioc_tool.core.defang.refang` runs over the whole blob first so
   defanged variants (``1[.]2[.]3[.]4``, ``hxxp://evil[.]com``,
   ``user[at]example[.]com``) are caught alongside their live forms.
2. Type-specific regexes pull candidates.
3. Each candidate is validated (e.g. IPv4 strings go through
   :func:`ipaddress.ip_address`; domain candidates that look like filenames
   are rejected).
4. Lists are deduplicated in first-seen order; empty buckets are dropped
   from the returned dict.

Pure stdlib. No external dependencies.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Dict, Iterable, List
from urllib.parse import urlparse

from .defang import refang

# ---------------------------------------------------------------------------
# Compiled regexes
# ---------------------------------------------------------------------------

# IPv4 — loose match, validated downstream via ipaddress.ip_address().
# Use lookarounds instead of \b so we reject things like 1.2.3.4.5 where a
# 5th octet follows. Same on the left to reject leading-dot extensions.
_IPV4_RE = re.compile(
    r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"
)

# Hash — MD5 (32) / SHA1 (40) / SHA256 (64) hex strings on word boundaries.
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")

# URL — http(s):// followed by non-whitespace. Trailing punctuation is
# trimmed downstream so sentences like "see http://evil.com/bad." don't
# capture the period.
_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)

# Email — RFC-ish. Requires a dot in the domain portion so generic
# strings like "foo@bar" without a TLD are rejected.
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# Domain — broad candidate match. Filtered downstream against URL hosts,
# IP addresses, and filename extensions.
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)

# Trailing punctuation we strip from URL captures (sentence terminators,
# quotes, brackets) — common when URLs are embedded in prose.
_URL_TRAILING_PUNCT = ".,;:!?)\"'>]}"

# File extensions that often look like domains but aren't. We reject any
# domain candidate ending in one of these so `report.pdf` or `script.py`
# doesn't surface as a "domain" IOC.
_FILENAME_TLDS: frozenset[str] = frozenset({
    "exe", "dll", "zip", "py", "js", "html", "txt", "md", "pdf",
    "png", "jpg", "json", "yml", "yaml", "toml", "ini", "cfg",
    "log", "csv",
})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dedup_preserve(items: Iterable[str]) -> List[str]:
    """Return items deduplicated, preserving first-seen order."""
    seen: set[str] = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _is_valid_ipv4(candidate: str) -> bool:
    """Return True if ``candidate`` parses as an IPv4 address."""
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return isinstance(ip, ipaddress.IPv4Address)


def _strip_url_trailing(url: str) -> str:
    """Trim sentence punctuation from the tail of a URL capture.

    Balances simple brackets/parens so ``(http://x.com/path)`` doesn't
    lose its closing slash but ``http://x.com/path)`` (no opening paren)
    does drop the trailing paren.
    """
    while url and url[-1] in _URL_TRAILING_PUNCT:
        last = url[-1]
        if last == ")" and url.count("(") > url.count(")"):
            break
        if last == "]" and url.count("[") > url.count("]"):
            break
        if last == "}" and url.count("{") > url.count("}"):
            break
        url = url[:-1]
    return url


def _url_host(url: str) -> str:
    """Return the lowercased hostname for a URL, or '' if unparseable."""
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        return ""
    return host.lower()


def _looks_like_filename(candidate: str) -> bool:
    """Reject domain-looking strings whose final label is a known file ext."""
    final_label = candidate.rsplit(".", 1)[-1].lower()
    return final_label in _FILENAME_TLDS


def _tld_is_alpha(candidate: str) -> bool:
    """The trailing label must be at least 2 alphabetic characters."""
    final_label = candidate.rsplit(".", 1)[-1]
    return len(final_label) >= 2 and final_label.isalpha()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def extract_iocs(text: str) -> Dict[str, List[str]]:
    """Extract all IOCs from a free-form text blob.

    Refangs the input first (so ``1[.]2[.]3[.]4`` and ``hxxp://evil[.]com``
    are caught the same as their live forms), then runs regex extractors
    for each supported type.

    Returns a dict keyed by IOC type::

        {"ip": ["1.2.3.4", "9.9.9.9"],
         "domain": ["evil.com"],
         "url": ["http://evil.com/bad"],
         "hash": ["f7d6a82..."],
         "email": ["attacker@evil.com"]}

    Each list is deduplicated and order-preserving (first-seen wins).
    Empty lists are omitted from the returned dict.
    """
    if not text:
        return {}

    refanged = refang(text)

    # --- IPs ---------------------------------------------------------------
    raw_ip_candidates = _IPV4_RE.findall(refanged)
    ips = _dedup_preserve(c for c in raw_ip_candidates if _is_valid_ipv4(c))

    # --- URLs --------------------------------------------------------------
    raw_urls = [_strip_url_trailing(u) for u in _URL_RE.findall(refanged)]
    urls = _dedup_preserve(u for u in raw_urls if u)

    # --- Emails ------------------------------------------------------------
    emails = _dedup_preserve(_EMAIL_RE.findall(refanged))

    # --- Hashes ------------------------------------------------------------
    # findall returns the matched alternative; lowercase for consistent
    # downstream comparisons (most threat-intel APIs are case-insensitive
    # but lowercase is the de-facto sharing convention).
    hashes = _dedup_preserve(h.lower() for h in _HASH_RE.findall(refanged))

    # --- Domains -----------------------------------------------------------
    # Hosts already captured by the URL extractor are excluded so we don't
    # double-count. Same for raw IP strings (which match the domain regex
    # if they're all-numeric).
    url_hosts = {_url_host(u) for u in urls if _url_host(u)}
    email_domains = {e.rsplit("@", 1)[-1].lower() for e in emails}
    ip_set = set(ips)

    raw_domain_candidates = _DOMAIN_RE.findall(refanged)
    domains: List[str] = []
    for cand in raw_domain_candidates:
        lowered = cand.lower()
        if cand in ip_set:
            continue
        if lowered in url_hosts:
            continue
        if lowered in email_domains:
            continue
        if _looks_like_filename(cand):
            continue
        if not _tld_is_alpha(cand):
            continue
        domains.append(cand)
    domains = _dedup_preserve(domains)

    result: Dict[str, List[str]] = {
        "ip": ips,
        "domain": domains,
        "url": urls,
        "hash": hashes,
        "email": emails,
    }
    # Drop empty buckets — callers expect a tight dict for summaries.
    return {k: v for k, v in result.items() if v}

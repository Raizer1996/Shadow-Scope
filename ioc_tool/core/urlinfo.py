"""What an indicator's own text gives away — URLs and e-mail addresses.

Both are analysed locally with no network call:

* :func:`analyse_url` breaks a URL into host, port, path, file extension and
  parameter names and flags structure that is typical of delivery and
  phishing links (credentials in the URL, a raw-IP host, an executable
  download, a redirect parameter carrying another URL, …).
* :func:`analyse_email` splits an address, says whether the domain is a free
  mailbox provider or a disposable-address service, and runs the existing
  look-alike / IDN checks on the domain.

These are *structure* signals. They can raise suspicion; they cannot prove
anything, so scores are capped well below what a reputation source can give.
The reputation of an e-mail's domain comes from enriching that domain, which
the orchestrator does for every address that is not on a free provider.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from . import heuristics, related

SCORE_CAP = 70

_EXECUTABLE_EXT = frozenset({
    "exe", "scr", "dll", "msi", "bat", "cmd", "com", "pif", "ps1", "vbs", "vbe", "js", "jse", "wsf", "hta",
    "jar", "lnk", "iso", "img", "apk", "dmg", "pkg", "elf", "sh", "bin", "cab", "msix", "appx", "chm",
})
_ARCHIVE_EXT = frozenset({"zip", "rar", "7z", "gz", "tgz", "tar", "bz2", "xz", "ace", "arj", "z"})
_MACRO_EXT = frozenset({"docm", "xlsm", "pptm", "dotm", "xlam", "xll", "one"})
_SHORTENERS = frozenset({
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "t.ly",
    "rb.gy", "shorturl.at", "tiny.cc", "lnkd.in", "s.id", "v.gd", "qr.ae", "soo.gd", "bl.ink", "short.io",
})
_COMMON_PORTS = frozenset({80, 443, 8080, 8443})
_LURE_WORDS = ("login", "signin", "sign-in", "logon", "verify", "verification", "account", "secure", "update",
               "password", "passwd", "wallet", "banking", "confirm", "webscr", "authenticate", "recover", "unlock")
_REDIRECT_PARAMS = frozenset({"url", "u", "redirect", "redirect_uri", "redirect_url", "redir", "next", "target",
                              "dest", "destination", "goto", "return", "returnurl", "return_to", "continue", "link", "out"})

_FREE_MAIL = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "ymail.com",
    "icloud.com", "me.com", "mac.com", "aol.com", "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net",
    "gmx.de", "web.de", "mail.com", "zoho.com", "yandex.com", "yandex.ru", "mail.ru", "bk.ru", "inbox.ru", "list.ru",
    "qq.com", "163.com", "126.com", "tutanota.com", "tuta.io", "fastmail.com", "hey.com", "walla.co.il", "seznam.cz",
    "orange.fr", "free.fr", "laposte.net", "t-online.de", "libero.it", "rediffmail.com", "naver.com", "daum.net",
})
_DISPOSABLE_MAIL = frozenset({
    "mailinator.com", "guerrillamail.com", "guerrillamail.net", "sharklasers.com", "10minutemail.com", "temp-mail.org",
    "tempmail.com", "throwawaymail.com", "yopmail.com", "getnada.com", "trashmail.com", "maildrop.cc", "dispostable.com",
    "mailnesia.com", "fakeinbox.com", "mintemail.com", "tempr.email", "discard.email", "moakt.com", "emailondeck.com",
    "mohmal.com", "spamgourmet.com", "mytemp.email", "tempmailo.com", "burnermail.io", "33mail.com", "mailcatch.com",
})
_ROLE_LOCALS = frozenset({
    "admin", "administrator", "root", "postmaster", "hostmaster", "webmaster", "abuse", "security", "noc", "support",
    "help", "helpdesk", "info", "contact", "sales", "billing", "accounts", "accounting", "invoice", "invoices",
    "payroll", "hr", "jobs", "careers", "noreply", "no-reply", "donotreply", "notifications", "service", "office", "it",
})


def _flag(flags: list[dict[str, Any]], key: str, label: str, points: int) -> None:
    flags.append({"id": key, "label": label, "points": points})


def _score(flags: list[dict[str, Any]]) -> int:
    """Strongest flag, nudged up a little for each additional one, capped."""
    pts = sorted((f["points"] for f in flags if f["points"] > 0), reverse=True)
    return min(SCORE_CAP, pts[0] + 5 * (len(pts) - 1)) if pts else 0


def analyse_url(url: str) -> dict[str, Any] | None:
    """Break a URL down and flag suspicious structure. None if it cannot be parsed."""
    try:
        parts = urlsplit(url.strip())
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        return None
    if not host or parts.scheme.lower() not in ("http", "https"):
        return None
    scheme = parts.scheme.lower()
    path = parts.path or "/"
    decoded_path = unquote(path)
    last = decoded_path.rsplit("/", 1)[-1]
    ext = last.rsplit(".", 1)[-1].lower() if "." in last and not last.endswith(".") else ""
    ext = ext if re.fullmatch(r"[a-z0-9]{1,6}", ext) else ""
    params = parse_qsl(parts.query, keep_blank_values=True)[:40]

    try:
        ipaddress.ip_address(host)
        ip_host = True
    except ValueError:
        ip_host = False
    registered = host if ip_host else related.registered_domain(host)
    sub_labels = 0 if ip_host else max(0, host.count(".") - registered.count("."))

    flags: list[dict[str, Any]] = []
    if parts.username is not None or "@" in parts.netloc:
        _flag(flags, "credentials", "user name or password embedded before the host — hides the real destination", 60)
    if ip_host:
        _flag(flags, "ip_host", "raw IP address instead of a domain name", 40)
    if ext in _EXECUTABLE_EXT:
        _flag(flags, "executable", f"links straight to a program or script (.{ext})", 50)
    elif ext in _MACRO_EXT:
        _flag(flags, "macro_document", f"links to a macro-enabled document (.{ext})", 40)
    elif ext in _ARCHIVE_EXT:
        _flag(flags, "archive", f"links to an archive (.{ext})", 25)
    if any(label.startswith("xn--") for label in host.split(".")):
        _flag(flags, "punycode", "internationalised (punycode) host name — may imitate another name", 40)
    carried = [k for k, v in params if k.lower() in _REDIRECT_PARAMS and re.match(r"(?i)^(https?:)?(//|%2f%2f)", v.strip())]
    if carried:
        _flag(flags, "redirect", f"parameter '{carried[0]}' carries another URL — possible open redirect", 35)
    if port is not None and port not in _COMMON_PORTS:
        _flag(flags, "port", f"non-standard port {port}", 30)
    if host in _SHORTENERS:
        _flag(flags, "shortener", "link shortener — the real destination is hidden", 25)
    if sub_labels >= 4:
        _flag(flags, "deep_subdomain", f"{sub_labels} sub-domain levels in front of {registered}", 25)
    haystack = (host + decoded_path).lower()
    lures = [w for w in _LURE_WORDS if w in haystack]
    if lures:
        _flag(flags, "lure_words", "login / account wording: " + ", ".join(lures[:4]), 30 if scheme == "http" else 15)
    encoded = len(re.findall(r"%[0-9a-fA-F]{2}", path + "?" + parts.query))
    if len(path) + len(parts.query) > 200 or encoded > 15:
        _flag(flags, "long_or_encoded", "very long or heavily encoded path / parameters", 20)
    if scheme == "http":
        _flag(flags, "plain_http", "not encrypted (http)", 10)

    return {
        "scheme": scheme,
        "host": host,
        "registered_domain": registered,
        "port": port,
        "path": path[:400],
        "extension": ext or None,
        "params": [k for k, _ in params][:20],
        "ip_host": ip_host,
        "flags": flags,
        "score": _score(flags),
    }


def analyse_email(address: str) -> dict[str, Any] | None:
    """Split an e-mail address and flag what its text reveals. None if malformed."""
    text = address.strip().lower()
    if text.count("@") != 1:
        return None
    local, domain = text.split("@")
    domain = domain.rstrip(".")
    if not local or "." not in domain:
        return None
    base, _, tag = local.partition("+")
    free = domain in _FREE_MAIL
    disposable = domain in _DISPOSABLE_MAIL
    role = base in _ROLE_LOCALS

    flags: list[dict[str, Any]] = []
    if disposable:
        _flag(flags, "disposable", "disposable / throw-away address service", 60)
    typo = None if free or disposable else heuristics.typosquat_check(domain)
    if typo and typo.get("score"):
        looks = typo.get("match") or "a known brand"
        _flag(flags, "lookalike", f"domain looks like {looks}", min(SCORE_CAP, int(typo["score"])))
    idn = heuristics.idn_check(domain)
    if idn and idn.get("score"):
        _flag(flags, "idn", "internationalised domain that may imitate another name", min(SCORE_CAP, int(idn["score"])))
    digits = sum(c.isdigit() for c in base)
    if len(base) >= 12 and digits / len(base) > 0.4:
        _flag(flags, "random_local", "mailbox name looks machine-generated", 20)
    if free:
        _flag(flags, "free_provider", "free mailbox provider — the domain says nothing about the sender", 0)
    if role:
        _flag(flags, "role_account", f"role mailbox ({base}@) rather than a person", 0)
    if tag:
        _flag(flags, "plus_tag", f"sub-address tag +{tag[:30]}", 0)

    return {
        "local": local,
        "domain": domain,
        "registered_domain": related.registered_domain(domain),
        "free_provider": free,
        "disposable": disposable,
        "role_account": role,
        "tag": tag or None,
        # The orchestrator enriches the domain unless it is a shared mailbox host.
        "enrich_domain": not free,
        "flags": flags,
        "score": _score(flags),
    }

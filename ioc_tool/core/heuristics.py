"""Local heuristics — score-bumping signals derived without external API calls.

Each heuristic consumes data already gathered by the enrichment pipeline
(WHOIS, the IOC string itself, env-configured watchlists) and returns a
structured ``dict`` plus an integer ``score`` in ``[0, 100]``. The
orchestrator (:func:`ioc_tool.core.enrich.enrich_ioc_async`) bundles the
active heuristics under a single ``Heuristics`` pseudo-module so they
appear alongside real sources in the output.

Heuristics are intentionally cheap (no I/O after the initial enrichment
batch finishes) and deterministic — useful both as risk amplifiers and
as analyst hints. Each function returns ``None`` when it has no signal
(e.g. NRD with no WHOIS creation date) so the orchestrator can skip the
entry silently.
"""

from __future__ import annotations

import math
from collections import Counter
from datetime import datetime
from typing import Any

# We use a "fraction of common bigrams" approach rather than per-bigram
# log-probabilities — robust to table size and matches the analyst's
# mental model ("does this look like English?"). The set below is the
# ~200 most-frequent English bigrams; anything outside it is treated as
# unusual. Source: Norvig's word-frequency corpus, top-200 by count.
_COMMON_ENGLISH_BIGRAMS = frozenset({
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti", "es",
    "or", "te", "of", "ed", "is", "it", "al", "ar", "st", "to", "nt", "ng",
    "se", "ha", "as", "ou", "io", "le", "ve", "co", "me", "de", "hi", "ri",
    "ro", "ic", "ne", "ea", "ra", "ce", "li", "ch", "ll", "be", "ma", "si",
    "om", "ur", "ca", "el", "ta", "la", "ns", "di", "fo", "ho", "pe", "ec",
    "pr", "no", "ct", "us", "ac", "ot", "il", "tr", "ly", "nc", "et", "ut",
    "ss", "so", "rs", "un", "lo", "wa", "ge", "ie", "wh", "ee", "wi", "em",
    "ad", "ol", "rt", "po", "we", "na", "ul", "ni", "ts", "mo", "ow", "pa",
    "im", "mi", "ai", "sh", "ir", "su", "id", "os", "ia", "am", "fi", "ci",
    "vi", "pl", "ig", "tu", "ev", "ld", "ry", "mp", "fe", "bl", "ab", "gh",
    "ty", "op", "wo", "sa", "ay", "ex", "ke", "fr", "oo", "av", "ag", "if",
    "ap", "gr", "od", "bo", "sp", "rd", "do", "uc", "bu", "ei", "ov", "by",
    "rm", "ep", "tt", "oc", "fa", "ef", "cu", "rn", "sc", "gi", "da", "yo",
    "cr", "cl", "du", "ga", "qu", "ue", "ff", "ba", "ey", "ls", "va", "um",
    "pp", "ua", "up", "lu", "go", "ht", "ru", "ug", "ds", "lt", "pi", "rc",
    "rr", "eg", "au", "ck", "ew", "mu", "br", "bi", "pt", "ak", "pu", "ui",
    "rg", "ib", "tl", "ny", "ki", "rk", "ys", "ob", "mm", "fu", "ph", "og",
    "ju", "sm", "lk", "ws", "ks", "ft",
})

# ---------------------------------------------------------------------------
# NRD — Newly Registered Domain
# ---------------------------------------------------------------------------
#
# Domains < 30 days old are heavily abused for phishing and C2: most
# malicious infrastructure is registered within hours or days of the
# campaign that uses it. We piggyback on the WHOIS source's already-
# fetched ``creation_date`` rather than making a second lookup.
#
# Score mapping:
#   age < 7   → 95   (extremely fresh — strong signal)
#   age < 30  → 75   (newly registered — classic NRD bucket)
#   age < 90  → 40   (recent — mild signal, often abused but also legit)
#   age >= 90 → 0    (mature — no signal)


def nrd_check(creation_date: Any) -> dict | None:
    """Compute an NRD score from a WHOIS ``creation_date`` value.

    Accepts the same shapes the WHOIS module produces:
    :class:`datetime`, ISO-format ``str``, or a list of either (registrars
    occasionally return multiple). Returns ``None`` when no usable date is
    available — caller should treat that as "no signal" and skip the entry.
    """
    parsed = _coerce_to_datetime(creation_date)
    if parsed is None:
        return None

    age_days = (datetime.now() - parsed).days
    if age_days < 0:
        # Future-dated creation? Treat as unparseable rather than crashing.
        return None

    if age_days < 7:
        score = 95
        bucket = "fresh"
    elif age_days < 30:
        score = 75
        bucket = "nrd"
    elif age_days < 90:
        score = 40
        bucket = "recent"
    else:
        score = 0
        bucket = "mature"

    return {
        "score": score,
        "age_days": age_days,
        "bucket": bucket,
        "created": parsed.date().isoformat(),
    }


def _coerce_to_datetime(value: Any) -> datetime | None:
    """Best-effort conversion of WHOIS creation_date variants → datetime."""
    if value is None:
        return None
    if isinstance(value, list):
        if not value:
            return None
        value = value[0]
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None


# ---------------------------------------------------------------------------
# DGA — Domain Generation Algorithm detection
# ---------------------------------------------------------------------------
#
# Algorithmically-generated domains (Conficker, Necurs, CryptoLocker,
# many modern banking trojans) look like "kq3v9z7hxnt8" — high entropy,
# improbable letter pairs, long consonant runs. We combine three cheap
# signals on the *registrable label* (the bit before the eTLD):
#
#   1. Shannon entropy of the characters (higher = more random)
#   2. Average -log10 bigram probability (higher = more improbable)
#   3. Longest run of consonants in a row (DGA strings cluster consonants)
#
# Each signal maps to a 0–100 sub-score; the final DGA score is their
# weighted average. Short labels (< 7 chars) are skipped — too little
# signal, too many legitimate short names.


def _entropy_score(label: str) -> float:
    """Shannon entropy mapped to 0-100. ``log` -> ~1.6, random 12-char -> ~3.5."""
    if not label:
        return 0.0
    counts = Counter(label)
    total = len(label)
    entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
    # Empirical bands: < 2.5 = English-like, 3.0 = mixed, > 3.5 = random
    return max(0.0, min(100.0, (entropy - 2.5) * 100.0))


def _bigram_score(label: str) -> float:
    """Fraction-of-uncommon-bigrams mapped to 0-100.

    English-like labels hit > 60% common bigrams; DGA-style labels hit
    < 20%. We map the ``uncommon_fraction`` linearly: 0.40 → 0, 0.90 → 100.
    """
    if len(label) < 2:
        return 0.0
    pairs = [label[i:i + 2] for i in range(len(label) - 1)]
    uncommon = sum(1 for p in pairs if p not in _COMMON_ENGLISH_BIGRAMS)
    fraction = uncommon / len(pairs)
    return max(0.0, min(100.0, (fraction - 0.40) * 200.0))


def _consonant_run_score(label: str) -> float:
    """Longest run of consonants → 0-100. Legit English rarely exceeds 4."""
    vowels = set("aeiouy")
    longest = current = 0
    for ch in label.lower():
        if ch.isalpha() and ch not in vowels:
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    # 4 → 0, 7+ → 100, linear in between.
    return max(0.0, min(100.0, (longest - 4) * 33.0))


def _extract_label(domain: str) -> str:
    """Pull the registrable label from a domain — the part before the eTLD.

    We deliberately use a naïve "second-to-last dot-separated chunk" rule
    instead of dragging in `tldextract`. Compound TLDs (``.co.uk``) might
    misclassify, but the score is a soft signal so a small false-positive
    rate is acceptable in exchange for zero new dependencies.
    """
    cleaned = domain.strip().lower().rstrip(".")
    parts = [p for p in cleaned.split(".") if p]
    if len(parts) < 2:
        return cleaned
    return parts[-2]


def dga_check(domain: str) -> dict | None:
    """Score a domain on DGA-ness. Returns ``None`` for inputs too short to score.

    Output:
        {"score": int 0-100, "label": str, "entropy": float,
         "bigram_improbability": float, "longest_consonant_run": int}

    Score weighting: entropy 35%, bigram 50%, consonant-run 15%. Bigram
    carries the most weight because it best discriminates English from
    random — entropy alone false-positives on long-but-pronounceable
    names like "cloudinfrastructure".
    """
    label = _extract_label(domain)
    if len(label) < 7:
        return None

    entropy = _entropy_score(label)
    bigram = _bigram_score(label)
    crun = _consonant_run_score(label)

    composite = int(round(0.35 * entropy + 0.50 * bigram + 0.15 * crun))

    # Longest consonant run for the analyst-facing field.
    vowels = set("aeiouy")
    longest_run = current = 0
    for ch in label:
        if ch.isalpha() and ch not in vowels:
            current += 1
            longest_run = max(longest_run, current)
        else:
            current = 0

    return {
        "score": composite,
        "label": label,
        "entropy": round(_shannon(label), 3),
        "bigram_improbability": round(_avg_bigram(label), 3),
        "longest_consonant_run": longest_run,
    }


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _avg_bigram(s: str) -> float:
    """Return the fraction of uncommon bigrams (0.0 = all English, 1.0 = none)."""
    if len(s) < 2:
        return 0.0
    pairs = [s[i:i + 2] for i in range(len(s) - 1)]
    uncommon = sum(1 for p in pairs if p not in _COMMON_ENGLISH_BIGRAMS)
    return uncommon / len(pairs)

import sys

import whois

from ..core import http

try:  # python-whois raises this for 'No match for domain' — a legitimate no-hit
    from whois.parser import PywhoisError as _NoMatch
except Exception:  # pragma: no cover - older/newer layouts
    _NoMatch = ()  # type: ignore[assignment]


def get_whois_data(domain):
    try:
        w = whois.whois(domain)
        # Convert to dict for easier handling, handling datetime objects
        return w
    except Exception as e:
        if not isinstance(e, _NoMatch):
            # Timeout / refused / parser crash: the source did not answer.
            http.mark_failure('whois', f"exception:{type(e).__name__}")
        # stderr only: this runs in a worker thread during `enrich --json`,
        # and anything on stdout corrupts the piped JSON/CSV payload.
        print(f"WHOIS error: {e}", file=sys.stderr)
        return None

import sys

import whois


def get_whois_data(domain):
    try:
        w = whois.whois(domain)
        # Convert to dict for easier handling, handling datetime objects
        return w
    except Exception as e:
        # stderr only: this runs in a worker thread during `enrich --json`,
        # and anything on stdout corrupts the piped JSON/CSV payload.
        print(f"WHOIS error: {e}", file=sys.stderr)
        return None

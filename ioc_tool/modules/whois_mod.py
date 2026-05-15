import whois


def get_whois_data(domain):
    try:
        w = whois.whois(domain)
        # Convert to dict for easier handling, handling datetime objects
        return w
    except Exception as e:
        print(f"WHOIS error: {e}")
        return None

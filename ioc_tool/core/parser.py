import ipaddress
import re

from .defang import refang


def normalize_value(value, ioc_type):
    """Return the canonical form of an IOC for a given type.

    Currently only CVE identifiers are normalised — they're uppercased
    and stripped so ``cve-2024-1234`` and ``CVE-2024-1234`` collapse to
    one cache key downstream. Other IOC types are returned unchanged
    (refanging is handled separately in :func:`detect_type`).
    """
    if value is None:
        return value
    if ioc_type == 'cve':
        return value.strip().upper()
    return value


def detect_type(value):
    value = refang(value.strip())

    # CVE identifier — checked before email/url/domain branches so
    # strings like 'CVE-2024-1234' aren't misclassified. The canonical
    # form is uppercased; downstream code can rely on the 'CVE-' prefix.
    if re.match(r'^CVE-\d{4}-\d{4,}$', value, re.IGNORECASE):
        return 'cve'

    # IP Address
    try:
        ipaddress.ip_address(value)
        return 'ip'
    except ValueError:
        pass

    # Hash (MD5, SHA1, SHA256)
    if re.match(r'^[a-fA-F0-9]{32}$', value):
        return 'hash' # MD5
    if re.match(r'^[a-fA-F0-9]{40}$', value):
        return 'hash' # SHA1
    if re.match(r'^[a-fA-F0-9]{64}$', value):
        return 'hash' # SHA256

    # Email
    if re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', value):
        return 'email'

    # URL (Simple check)
    if re.match(r'^https?://', value):
        return 'url'

    # Domain (Fallback, basic regex)
    if re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', value):
        return 'domain'

    return 'unknown'

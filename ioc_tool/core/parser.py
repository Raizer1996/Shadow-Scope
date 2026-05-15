import ipaddress
import re

from .defang import refang


def normalize_value(value, ioc_type):
    """Return the canonical form of an IOC for a given type.

    - CVE: uppercased + stripped so ``cve-2024-1234`` and
      ``CVE-2024-1234`` share a cache key.
    - ASN: stripped to ``ASxxxxx`` (uppercase, no spaces). Accepts
      ``AS15169``, ``as15169``, ``asn15169``, or bare ``15169``.
    - Everything else: unchanged (refanging happens in detect_type).
    """
    if value is None:
        return value
    if ioc_type == 'cve':
        return value.strip().upper()
    if ioc_type == 'asn':
        digits = re.sub(r'(?i)^as(n)?', '', value.strip())
        return f"AS{digits.lstrip('0') or '0'}"
    return value


def detect_type(value):
    value = refang(value.strip())

    # CVE identifier — checked before email/url/domain branches so
    # strings like 'CVE-2024-1234' aren't misclassified. The canonical
    # form is uppercased; downstream code can rely on the 'CVE-' prefix.
    if re.match(r'^CVE-\d{4}-\d{4,}$', value, re.IGNORECASE):
        return 'cve'

    # ASN identifier — ``AS12345`` / ``ASN12345`` / ``as12345``. We
    # explicitly require the ``AS`` prefix to avoid false-positives on
    # bare integers (which could be anything). 1-10 digits covers the
    # 32-bit ASN range (0 to 4_294_967_295).
    if re.match(r'^AS(N)?\d{1,10}$', value, re.IGNORECASE):
        return 'asn'

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

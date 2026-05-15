"""Tests for the allowlist short-circuit module."""

from ioc_tool.core import allowlist

# ---------------------------------------------------------------------------
# CIDR allowlist
# ---------------------------------------------------------------------------


def test_no_env_means_no_match(monkeypatch):
    monkeypatch.delenv("ALLOWLIST_CIDRS", raising=False)
    monkeypatch.delenv("ALLOWLIST_DOMAINS", raising=False)
    assert allowlist.is_allowlisted("8.8.8.8", "ip") is None
    assert allowlist.is_allowlisted("example.com", "domain") is None


def test_cidr_match_ipv4(monkeypatch):
    monkeypatch.setenv("ALLOWLIST_CIDRS", "10.0.0.0/8,192.168.0.0/16")
    hit = allowlist.is_allowlisted("10.1.2.3", "ip")
    assert hit == {"reason": "cidr", "match": "10.0.0.0/8"}


def test_cidr_miss_outside_range(monkeypatch):
    monkeypatch.setenv("ALLOWLIST_CIDRS", "10.0.0.0/8")
    assert allowlist.is_allowlisted("8.8.8.8", "ip") is None


def test_cidr_match_ipv6(monkeypatch):
    monkeypatch.setenv("ALLOWLIST_CIDRS", "2001:db8::/32")
    hit = allowlist.is_allowlisted("2001:db8::1", "ip")
    assert hit is not None
    assert hit["reason"] == "cidr"


def test_cidr_version_mismatch_does_not_match(monkeypatch):
    """IPv6 input shouldn't match an IPv4 CIDR."""
    monkeypatch.setenv("ALLOWLIST_CIDRS", "10.0.0.0/8")
    assert allowlist.is_allowlisted("2001:db8::1", "ip") is None


def test_cidr_handles_typos_gracefully(monkeypatch):
    """A bad entry shouldn't disable the whole allowlist."""
    monkeypatch.setenv("ALLOWLIST_CIDRS", "garbage,10.0.0.0/8,not-a-cidr")
    hit = allowlist.is_allowlisted("10.1.2.3", "ip")
    assert hit is not None


def test_cidr_invalid_ip_input_returns_none(monkeypatch):
    monkeypatch.setenv("ALLOWLIST_CIDRS", "10.0.0.0/8")
    assert allowlist.is_allowlisted("not-an-ip", "ip") is None


# ---------------------------------------------------------------------------
# Domain allowlist
# ---------------------------------------------------------------------------


def test_domain_exact_match(monkeypatch):
    monkeypatch.setenv("ALLOWLIST_DOMAINS", "corp.example.com")
    hit = allowlist.is_allowlisted("corp.example.com", "domain")
    assert hit == {"reason": "domain", "match": "corp.example.com"}


def test_domain_subdomain_match(monkeypatch):
    monkeypatch.setenv("ALLOWLIST_DOMAINS", "corp.example.com")
    hit = allowlist.is_allowlisted("api.corp.example.com", "domain")
    assert hit is not None
    assert hit["match"] == "corp.example.com"


def test_domain_partial_suffix_does_not_match(monkeypatch):
    """``evilcorp.example.com`` must NOT match an allowlist for ``corp.example.com``."""
    monkeypatch.setenv("ALLOWLIST_DOMAINS", "corp.example.com")
    assert allowlist.is_allowlisted("evilcorp.example.com", "domain") is None


def test_domain_match_is_case_insensitive(monkeypatch):
    monkeypatch.setenv("ALLOWLIST_DOMAINS", "Corp.Example.COM")
    hit = allowlist.is_allowlisted("API.CORP.EXAMPLE.COM", "domain")
    assert hit is not None


# ---------------------------------------------------------------------------
# URL → domain extraction
# ---------------------------------------------------------------------------


def test_url_matches_domain_allowlist(monkeypatch):
    monkeypatch.setenv("ALLOWLIST_DOMAINS", "corp.example.com")
    hit = allowlist.is_allowlisted("https://api.corp.example.com/path", "url")
    assert hit is not None
    assert hit["match"] == "corp.example.com"


def test_url_miss_when_host_not_allowlisted(monkeypatch):
    monkeypatch.setenv("ALLOWLIST_DOMAINS", "corp.example.com")
    assert allowlist.is_allowlisted("https://evil.example.org", "url") is None


# ---------------------------------------------------------------------------
# Other IOC types — no allowlist applies
# ---------------------------------------------------------------------------


def test_hash_type_never_allowlisted(monkeypatch):
    monkeypatch.setenv("ALLOWLIST_CIDRS", "10.0.0.0/8")
    monkeypatch.setenv("ALLOWLIST_DOMAINS", "corp.example.com")
    assert allowlist.is_allowlisted("d41d8cd98f00b204e9800998ecf8427e", "hash") is None


def test_cve_type_never_allowlisted(monkeypatch):
    monkeypatch.setenv("ALLOWLIST_DOMAINS", "anything.com")
    assert allowlist.is_allowlisted("CVE-2024-1234", "cve") is None

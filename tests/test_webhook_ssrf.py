"""Tests for the SSRF defence on ``core.http.post_webhook``.

The webhook helper is a thin POST-to-arbitrary-URL surface used by both
``shadowscope enrich --webhook=URL`` and ``shadowscope watch --webhook=URL``.
Without input validation that surface is a textbook SSRF entry point —
an operator (or a config-injection attack) could point it at
``http://169.254.169.254/`` (AWS metadata), ``http://127.0.0.1:6379/``
(local Redis), or ``file://`` and pivot off the ShadowScope host into
infra it should not be able to reach.

The helper enforces a two-layer policy:

1. Scheme must be ``http`` or ``https``.
2. If the host parses as a literal IPv4/IPv6 address it must NOT be
   in any private, loopback, link-local, multicast, or reserved range.

Hostnames are pass-through in v1 (no DNS resolution) — that's a
deliberate tradeoff for the cheap stdlib-only check; a future TOCTOU-
safe version can ``getaddrinfo`` at request time.

The env opt-out ``SHADOWSCOPE_WEBHOOK_ALLOW_PRIVATE=1`` skips the
private-IP gate so on-prem SIEM / internal ticketing endpoints living
in RFC1918 space still work.

All tests stub out the underlying ``post`` so no real HTTP traffic
fires — we only verify the validation gate.
"""

from __future__ import annotations

import pytest

from ioc_tool.core import http as core_http

# ---------------------------------------------------------------------------
# Scheme gate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "gopher://x.test/",
    "ftp://x.test/",
    "javascript:alert(1)",
    "data:text/plain,abc",
])
def test_disallowed_scheme_rejected(url, capsys, monkeypatch):
    """Anything that isn't http/https soft-fails to ``False``."""
    called = []
    monkeypatch.setattr(core_http, "post", lambda *a, **k: called.append(a) or None)

    assert core_http.post_webhook(url, {"k": "v"}) is False
    # Underlying post must NOT have been invoked — the gate fires before
    # we hit the network.
    assert called == []
    err = capsys.readouterr().err
    assert "webhook URL rejected" in err
    assert "scheme" in err


# ---------------------------------------------------------------------------
# Private / loopback / link-local IP literals
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url", [
    # IPv4 RFC1918 + loopback + link-local + cloud-metadata
    "http://10.0.0.1/hook",
    "http://172.16.5.1/hook",
    "http://192.168.1.1/hook",
    "http://127.0.0.1/hook",
    "http://127.0.0.1:6379/",     # local Redis
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://0.0.0.0/hook",
    # IPv6 loopback + ULA + link-local
    "http://[::1]/hook",
    "http://[fc00::1]/hook",
    "http://[fd12:3456::1]/hook",
    "http://[fe80::1]/hook",
])
def test_private_ip_literal_rejected(url, capsys, monkeypatch):
    """Every documented private/loopback/link-local range is blocked."""
    called = []
    monkeypatch.setattr(core_http, "post", lambda *a, **k: called.append(a) or None)
    monkeypatch.delenv("SHADOWSCOPE_WEBHOOK_ALLOW_PRIVATE", raising=False)

    assert core_http.post_webhook(url, {"k": "v"}) is False
    assert called == []
    err = capsys.readouterr().err
    assert "webhook URL rejected" in err


def test_private_ip_allowed_via_env_opt_in(monkeypatch):
    """``SHADOWSCOPE_WEBHOOK_ALLOW_PRIVATE=1`` re-enables on-prem targets.

    On-prem SIEM / internal ticketing endpoints legitimately live in
    RFC1918 space; the env opt-in is the escape hatch for them.
    """
    monkeypatch.setenv("SHADOWSCOPE_WEBHOOK_ALLOW_PRIVATE", "1")

    class _Resp:
        status_code = 200

    seen = []

    def _capture(source_key, url, **kwargs):
        seen.append((source_key, url))
        return _Resp()

    monkeypatch.setattr(core_http, "post", _capture)
    assert core_http.post_webhook("http://10.0.0.1/hook", {"k": "v"}) is True
    assert seen == [("webhook", "http://10.0.0.1/hook")]


# ---------------------------------------------------------------------------
# Happy paths — public hosts pass straight through
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url", [
    "https://siem.example.com/hook",
    "http://example.com:8080/path",
    "https://1.1.1.1/hook",            # public IP literal — allowed
    "https://8.8.8.8/v1/events",
])
def test_public_url_accepted(url, monkeypatch):
    class _Resp:
        status_code = 204

    monkeypatch.setattr(core_http, "post", lambda *a, **k: _Resp())
    assert core_http.post_webhook(url, {"k": "v"}) is True


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_empty_url_rejected(capsys):
    assert core_http.post_webhook("", {"k": "v"}) is False
    assert "webhook URL rejected" in capsys.readouterr().err


def test_missing_host_rejected(capsys):
    """``https:///`` parses but has an empty hostname — must fail closed."""
    assert core_http.post_webhook("https:///path", {"k": "v"}) is False
    assert "webhook URL rejected" in capsys.readouterr().err


def test_hostname_pass_through_in_v1(monkeypatch):
    """Hostnames are NOT resolved in v1 — they pass the validator and
    the request goes out. (A future TOCTOU-safe revision can add a DNS
    resolve + post-resolution recheck.)
    """
    class _Resp:
        status_code = 200

    monkeypatch.setattr(core_http, "post", lambda *a, **k: _Resp())
    # ``localhost`` is a hostname, not an IP literal — the v1 gate lets
    # it through. Documenting this is the test's purpose: future hardening
    # will need to update this expectation.
    assert core_http.post_webhook("http://localhost/hook", {"k": "v"}) is True

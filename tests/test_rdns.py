"""Reverse-DNS lookup tests — patch stdlib ``socket.gethostbyaddr``.

We never hit a real resolver: every test fakes the syscall via
monkeypatch so the suite stays offline and deterministic.
"""

from __future__ import annotations

import socket

import pytest

from ioc_tool.modules import rdns


def test_rdns_returns_ptr_and_aliases(monkeypatch):
    monkeypatch.setattr(
        socket,
        "gethostbyaddr",
        lambda ip: ("mail.example.com", ["smtp.example.com"], [ip]),
    )
    out = rdns.enrich_ip("203.0.113.5")
    assert out == {"ptr": "mail.example.com", "aliases": ["smtp.example.com"]}


def test_rdns_empty_aliases(monkeypatch):
    monkeypatch.setattr(
        socket,
        "gethostbyaddr",
        lambda ip: ("host.example.com", [], [ip]),
    )
    out = rdns.enrich_ip("198.51.100.7")
    assert out == {"ptr": "host.example.com", "aliases": []}


@pytest.mark.parametrize("exc", [socket.herror, socket.gaierror, OSError])
def test_rdns_failure_returns_none(monkeypatch, exc):
    def boom(_ip):
        raise exc("nope")
    monkeypatch.setattr(socket, "gethostbyaddr", boom)
    assert rdns.enrich_ip("10.0.0.1") is None


def test_rdns_empty_input_returns_none():
    assert rdns.enrich_ip("") is None


def test_rdns_empty_hostname_returns_none(monkeypatch):
    monkeypatch.setattr(
        socket,
        "gethostbyaddr",
        lambda ip: ("", [], [ip]),
    )
    assert rdns.enrich_ip("192.0.2.1") is None


def test_rdns_restores_socket_timeout(monkeypatch):
    """Local timeout must not leak into the global state."""
    prev = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(None)
        monkeypatch.setattr(
            socket,
            "gethostbyaddr",
            lambda ip: ("h.example.com", [], [ip]),
        )
        rdns.enrich_ip("10.0.0.1")
        assert socket.getdefaulttimeout() is None
    finally:
        socket.setdefaulttimeout(prev)


def test_rdns_restores_timeout_on_failure(monkeypatch):
    prev = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(7.0)
        def boom(_ip):
            raise socket.herror("nx")
        monkeypatch.setattr(socket, "gethostbyaddr", boom)
        rdns.enrich_ip("10.0.0.1")
        assert socket.getdefaulttimeout() == 7.0
    finally:
        socket.setdefaulttimeout(prev)

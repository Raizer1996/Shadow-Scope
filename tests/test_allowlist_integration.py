"""Integration test — enrich_ioc short-circuits on allowlist hits."""

from ioc_tool.core import enrich


def test_allowlisted_ip_skips_all_sources(monkeypatch, tmp_path):
    """A CIDR-matched IP must skip every source and surface an Allowlist entry."""
    from ioc_tool.core import database as _db
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "ioc.db"))
    _db.init_db()

    fetched = []
    monkeypatch.setenv("ALLOWLIST_CIDRS", "10.0.0.0/8")
    # If any source were called, this would record a value — but we expect zero.
    from ioc_tool.modules import vt
    original = vt.enrich_ip
    def _spy(value):
        fetched.append(value)
        return original(value)
    monkeypatch.setattr(vt, "enrich_ip", _spy)

    result = enrich.enrich_ioc("10.1.2.3", "ip")

    assert result["ioc"] == "10.1.2.3"
    assert result["final_score"] == 0
    assert result["allowlisted"] is True
    assert "Allowlist" in result["modules"]
    assert result["modules"]["Allowlist"]["data"]["reason"] == "cidr"
    assert fetched == []  # no source was hit


def test_non_allowlisted_ip_still_enriches(monkeypatch, tmp_path):
    """An unmatched IP follows the normal pipeline (no allowlist short-circuit)."""
    from ioc_tool.core import database as _db
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "ioc.db"))
    _db.init_db()

    monkeypatch.setenv("ALLOWLIST_CIDRS", "10.0.0.0/8")
    # Stub every source so the test doesn't make network calls.
    from tests.test_bulk import _stub_all_network
    _stub_all_network(monkeypatch)

    result = enrich.enrich_ioc("8.8.8.8", "ip")
    assert result.get("allowlisted") is None
    assert "Allowlist" not in result["modules"]

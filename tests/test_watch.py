"""Tests for watch-mode plumbing: last_score persistence + CLI parser."""

import pytest

from ioc_tool.core import database


@pytest.fixture
def _isolated_db(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "ioc.db"))
    database.init_db()
    return database


def test_update_last_score_writes_value(_isolated_db):
    ioc_id = _isolated_db.add_or_update_ioc("8.8.8.8", "ip")
    _isolated_db.update_last_score(ioc_id, 42)
    rows = _isolated_db.list_iocs()
    assert rows[0]['value'] == "8.8.8.8"
    assert rows[0]['last_score'] == 42


def test_update_last_score_overwrites(_isolated_db):
    ioc_id = _isolated_db.add_or_update_ioc("8.8.8.8", "ip")
    _isolated_db.update_last_score(ioc_id, 10)
    _isolated_db.update_last_score(ioc_id, 90)
    rows = _isolated_db.list_iocs()
    assert rows[0]['last_score'] == 90


def test_list_iocs_returns_all_when_no_filter(_isolated_db):
    _isolated_db.add_or_update_ioc("a.example.com", "domain")
    _isolated_db.add_or_update_ioc("b.example.com", "domain")
    rows = _isolated_db.list_iocs()
    values = {r['value'] for r in rows}
    assert values == {"a.example.com", "b.example.com"}


def test_list_iocs_filters_by_case(_isolated_db):
    a = _isolated_db.add_or_update_ioc("a.example.com", "domain")
    b = _isolated_db.add_or_update_ioc("b.example.com", "domain")
    _isolated_db.tag_ioc(a, tag="x", case="campaign-x")
    _isolated_db.tag_ioc(b, tag="x", case="other")
    rows = _isolated_db.list_iocs(case="campaign-x")
    assert {r['value'] for r in rows} == {"a.example.com"}


def test_cli_parser_accepts_watch_subcommand():
    from ioc_tool.ui import cli
    parser = cli.build_parser()
    args = parser.parse_args(['watch', '--threshold', '20', '--case', 'campaign-x', '--json'])
    assert args.command == 'watch'
    assert args.threshold == 20
    assert args.case == 'campaign-x'
    assert args.json is True


def test_cli_parser_watch_threshold_defaults_to_10():
    from ioc_tool.ui import cli
    parser = cli.build_parser()
    args = parser.parse_args(['watch'])
    assert args.threshold == 10


def test_enrich_records_last_score(monkeypatch, _isolated_db):
    """End-to-end: running enrich stamps last_score on the iocs row."""
    from ioc_tool.core import enrich
    from tests.test_bulk import _stub_all_network
    _stub_all_network(monkeypatch)

    enrich.enrich_ioc("8.8.8.8", "ip")
    rows = _isolated_db.list_iocs()
    assert rows[0]['last_score'] == 0  # all sources stubbed → composite 0


def test_init_db_idempotent_with_existing_column(_isolated_db):
    """Calling init_db twice must not crash on the ALTER TABLE migration."""
    _isolated_db.init_db()
    _isolated_db.init_db()
    # Last call should still work normally.
    ioc_id = _isolated_db.add_or_update_ioc("x.example.com", "domain")
    _isolated_db.update_last_score(ioc_id, 1)

"""Tests for IOC tag / case storage + lookup."""

import pytest

from ioc_tool.core import database


@pytest.fixture
def _isolated_db(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "ioc.db"))
    database.init_db()
    return database


def test_tag_creates_row(_isolated_db):
    ioc_id = _isolated_db.add_or_update_ioc("evil.example.com", "domain")
    row_id = _isolated_db.tag_ioc(ioc_id, tag="phishing")
    assert row_id > 0


def test_tag_with_case_and_note(_isolated_db):
    ioc_id = _isolated_db.add_or_update_ioc("evil.example.com", "domain")
    _isolated_db.tag_ioc(ioc_id, tag="phishing", case="campaign-x", note="ATO landing page")
    tags = _isolated_db.get_tags_for_ioc(ioc_id)
    assert len(tags) == 1
    assert tags[0]["tag"] == "phishing"
    assert tags[0]["case_name"] == "campaign-x"
    assert tags[0]["note"] == "ATO landing page"


def test_tag_is_idempotent(_isolated_db):
    """Repeat tag with same triple should not create duplicates."""
    ioc_id = _isolated_db.add_or_update_ioc("evil.example.com", "domain")
    _isolated_db.tag_ioc(ioc_id, tag="phishing", case="campaign-x")
    _isolated_db.tag_ioc(ioc_id, tag="phishing", case="campaign-x")
    assert len(_isolated_db.get_tags_for_ioc(ioc_id)) == 1


def test_tag_upserts_note(_isolated_db):
    """Re-tagging the same (ioc, tag, case) updates the note."""
    ioc_id = _isolated_db.add_or_update_ioc("evil.example.com", "domain")
    _isolated_db.tag_ioc(ioc_id, tag="phishing", case="campaign-x", note="first")
    _isolated_db.tag_ioc(ioc_id, tag="phishing", case="campaign-x", note="second")
    tags = _isolated_db.get_tags_for_ioc(ioc_id)
    assert len(tags) == 1
    assert tags[0]["note"] == "second"


def test_remove_tag(_isolated_db):
    ioc_id = _isolated_db.add_or_update_ioc("evil.example.com", "domain")
    _isolated_db.tag_ioc(ioc_id, tag="phishing", case="campaign-x")
    deleted = _isolated_db.remove_tag(ioc_id, tag="phishing", case="campaign-x")
    assert deleted == 1
    assert _isolated_db.get_tags_for_ioc(ioc_id) == []


def test_list_iocs_for_case(_isolated_db):
    a = _isolated_db.add_or_update_ioc("a.example.com", "domain")
    b = _isolated_db.add_or_update_ioc("b.example.com", "domain")
    c = _isolated_db.add_or_update_ioc("c.example.com", "domain")
    _isolated_db.tag_ioc(a, tag="phishing", case="campaign-x")
    _isolated_db.tag_ioc(b, tag="c2", case="campaign-x")
    _isolated_db.tag_ioc(c, tag="benign", case="other-case")

    rows = _isolated_db.list_iocs_for_case("campaign-x")
    values = {r["value"] for r in rows}
    assert values == {"a.example.com", "b.example.com"}


def test_list_cases(_isolated_db):
    a = _isolated_db.add_or_update_ioc("a.example.com", "domain")
    b = _isolated_db.add_or_update_ioc("b.example.com", "domain")
    _isolated_db.tag_ioc(a, tag="phishing", case="campaign-x")
    _isolated_db.tag_ioc(b, tag="phishing", case="campaign-y")
    _isolated_db.tag_ioc(a, tag="c2", case="campaign-y")  # multi-case for one IOC

    cases = _isolated_db.list_cases()
    case_map = {c["case_name"]: c["ioc_count"] for c in cases}
    assert case_map["campaign-x"] == 1
    assert case_map["campaign-y"] == 2


def test_list_tags(_isolated_db):
    a = _isolated_db.add_or_update_ioc("a.example.com", "domain")
    b = _isolated_db.add_or_update_ioc("b.example.com", "domain")
    _isolated_db.tag_ioc(a, tag="phishing")
    _isolated_db.tag_ioc(b, tag="phishing")
    _isolated_db.tag_ioc(a, tag="c2")

    tags = _isolated_db.list_tags()
    tag_map = {t["tag"]: t["ioc_count"] for t in tags}
    assert tag_map["phishing"] == 2
    assert tag_map["c2"] == 1


def test_tag_without_value_is_allowed(_isolated_db):
    """A case-only attachment (no tag) is valid — case grouping without label."""
    ioc_id = _isolated_db.add_or_update_ioc("evil.example.com", "domain")
    _isolated_db.tag_ioc(ioc_id, tag=None, case="campaign-x", note="suspect")
    tags = _isolated_db.get_tags_for_ioc(ioc_id)
    assert len(tags) == 1
    assert tags[0]["tag"] is None
    assert tags[0]["case_name"] == "campaign-x"


# ---------------------------------------------------------------------------
# CLI parser hooks
# ---------------------------------------------------------------------------


def test_cli_parser_accepts_tag_subcommand():
    from ioc_tool.ui import cli
    parser = cli.build_parser()
    args = parser.parse_args(['tag', 'evil.example.com', '--tag', 'phishing', '--case', 'campaign-x'])
    assert args.command == 'tag'
    assert args.ioc == 'evil.example.com'
    assert args.tag == 'phishing'
    assert args.case == 'campaign-x'


def test_cli_parser_accepts_cases_subcommand():
    from ioc_tool.ui import cli
    parser = cli.build_parser()
    args = parser.parse_args(['cases', '--case', 'campaign-x'])
    assert args.command == 'cases'
    assert args.case == 'campaign-x'

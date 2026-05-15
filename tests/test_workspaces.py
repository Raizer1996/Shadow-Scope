"""Tests for the multi-workspace plumbing."""

import os

import pytest

from ioc_tool.core import database


@pytest.fixture
def _isolated_data_dir(monkeypatch, tmp_path):
    """Reroute DATA_DIR + DB_PATH into a temp directory."""
    monkeypatch.setattr(database, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "ioc.db"))
    return tmp_path


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------


def test_workspace_db_path_uses_safe_name(_isolated_data_dir):
    """Workspace names are sanitised — only alnum + - + _ allowed."""
    p = database.workspace_db_path("campaign-x")
    assert os.path.basename(p) == "ioc-campaign-x.db"


def test_workspace_db_path_strips_unsafe_chars(_isolated_data_dir):
    """Path-traversal attempts get stripped, not honoured."""
    p = database.workspace_db_path("../foo/bar")
    # Slashes + dots stripped; remaining safe chars are "foobar".
    assert os.path.basename(p) == "ioc-foobar.db"


def test_workspace_db_path_empty_falls_back_to_default(_isolated_data_dir):
    p = database.workspace_db_path("")
    assert os.path.basename(p) == "ioc-default.db"


# ---------------------------------------------------------------------------
# set_workspace
# ---------------------------------------------------------------------------


def test_set_workspace_none_keeps_default(_isolated_data_dir):
    """No workspace name means ``ioc.db`` — the historical path."""
    path = database.set_workspace(None)
    assert os.path.basename(path) == "ioc.db"
    assert path == database.DB_PATH


def test_set_workspace_named_switches(_isolated_data_dir):
    path = database.set_workspace("campaign-x")
    assert os.path.basename(path) == "ioc-campaign-x.db"
    assert path == database.DB_PATH


def test_set_workspace_roundtrips(_isolated_data_dir):
    database.set_workspace("alpha")
    database.set_workspace("beta")
    assert os.path.basename(database.DB_PATH) == "ioc-beta.db"
    database.set_workspace(None)
    assert os.path.basename(database.DB_PATH) == "ioc.db"


def test_set_workspace_creates_isolated_data(_isolated_data_dir):
    """Each workspace is a separate file — adding an IOC to one shouldn't show in another."""
    database.set_workspace("alpha")
    database.init_db()
    database.add_or_update_ioc("8.8.8.8", "ip")

    database.set_workspace("beta")
    database.init_db()
    rows = database.list_iocs()
    assert rows == []  # beta is empty even though alpha has 8.8.8.8

    database.set_workspace("alpha")
    rows = database.list_iocs()
    assert {r['value'] for r in rows} == {"8.8.8.8"}


# ---------------------------------------------------------------------------
# list_workspaces
# ---------------------------------------------------------------------------


def test_list_workspaces_empty(_isolated_data_dir):
    assert database.list_workspaces() == []


def test_list_workspaces_includes_default_and_named(_isolated_data_dir):
    # Default workspace
    database.set_workspace(None)
    database.init_db()
    # Two named workspaces
    database.set_workspace("alpha")
    database.init_db()
    database.set_workspace("beta")
    database.init_db()

    rows = database.list_workspaces()
    names = {r['name'] for r in rows}
    assert names == {"default", "alpha", "beta"}
    for row in rows:
        assert row['size'] >= 0
        assert os.path.exists(row['path'])


# ---------------------------------------------------------------------------
# CLI parser
# ---------------------------------------------------------------------------


def test_cli_parser_accepts_workspace_flag():
    from ioc_tool.ui import cli
    parser = cli.build_parser()
    args = parser.parse_args(['--workspace', 'campaign-x', 'enrich', '8.8.8.8'])
    assert args.workspace == 'campaign-x'


def test_cli_parser_workspace_falls_back_to_env(monkeypatch):
    from ioc_tool.ui import cli
    monkeypatch.setenv("SHADOWSCOPE_WORKSPACE", "from-env")
    parser = cli.build_parser()
    args = parser.parse_args(['enrich', '8.8.8.8'])
    assert args.workspace == 'from-env'


def test_cli_parser_workspace_default_none(monkeypatch):
    from ioc_tool.ui import cli
    monkeypatch.delenv("SHADOWSCOPE_WORKSPACE", raising=False)
    parser = cli.build_parser()
    args = parser.parse_args(['enrich', '8.8.8.8'])
    assert args.workspace is None


def test_cli_parser_workspaces_subcommand_registers():
    from ioc_tool.ui import cli
    parser = cli.build_parser()
    args = parser.parse_args(['workspaces'])
    assert args.command == 'workspaces'

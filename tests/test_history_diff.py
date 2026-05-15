"""Tests for the history view + diff subcommand plumbing."""

import json
import time

import pytest

from ioc_tool.core import database
from ioc_tool.ui import cli


@pytest.fixture
def _isolated_db(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "ioc.db"))
    database.init_db()
    return database


# ---------------------------------------------------------------------------
# get_all_enrichments — chronological retrieval
# ---------------------------------------------------------------------------


def test_get_all_enrichments_empty(_isolated_db):
    ioc_id = _isolated_db.add_or_update_ioc("8.8.8.8", "ip")
    assert _isolated_db.get_all_enrichments(ioc_id) == []


def test_get_all_enrichments_returns_all_rows(_isolated_db):
    ioc_id = _isolated_db.add_or_update_ioc("8.8.8.8", "ip")
    _isolated_db.add_enrichment(ioc_id, "virustotal", json.dumps({"x": 1}), 10)
    time.sleep(0.01)  # ensure ordering distinct
    _isolated_db.add_enrichment(ioc_id, "virustotal", json.dumps({"x": 2}), 50)
    _isolated_db.add_enrichment(ioc_id, "abuseipdb", json.dumps({"y": 1}), 90)
    rows = _isolated_db.get_all_enrichments(ioc_id)
    assert len(rows) == 3
    # Chronological — VT samples come first since they were inserted first.
    assert [r['source'] for r in rows[:2]] == ['virustotal', 'virustotal']
    assert [r['score'] for r in rows[:2]] == [10, 50]


# ---------------------------------------------------------------------------
# Sparkline rendering
# ---------------------------------------------------------------------------


def test_sparkline_empty_returns_empty():
    assert cli._sparkline([]) == ""


def test_sparkline_all_zero_renders_floor():
    """Zero values map to the bottom char (space)."""
    out = cli._sparkline([0, 0, 0])
    assert len(out) == 3
    # First char in _SPARK_CHARS is ' ' (the floor).
    assert all(c == cli._SPARK_CHARS[0] for c in out)


def test_sparkline_max_value_renders_ceiling():
    out = cli._sparkline([100, 100])
    assert all(c == cli._SPARK_CHARS[-1] for c in out)


def test_sparkline_distinct_buckets():
    """Different values produce different chars."""
    out = cli._sparkline([10, 50, 90])
    assert out[0] != out[1] != out[2]
    assert len(out) == 3


# ---------------------------------------------------------------------------
# CLI parser
# ---------------------------------------------------------------------------


def test_cli_parser_accepts_history():
    parser = cli.build_parser()
    args = parser.parse_args(['history', '8.8.8.8'])
    assert args.command == 'history'
    assert args.ioc == '8.8.8.8'
    assert args.source is None


def test_cli_parser_history_source_filter():
    parser = cli.build_parser()
    args = parser.parse_args(['history', '8.8.8.8', '--source', 'VirusTotal'])
    assert args.source == 'VirusTotal'


def test_cli_parser_accepts_diff():
    parser = cli.build_parser()
    args = parser.parse_args(['diff', '8.8.8.8', '1.1.1.1'])
    assert args.command == 'diff'
    assert args.ioc_a == '8.8.8.8'
    assert args.ioc_b == '1.1.1.1'

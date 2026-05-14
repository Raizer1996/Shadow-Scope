"""Smoke tests — no live API calls. Verify imports and pure-logic helpers."""

import pytest

from ioc_tool.core import score
from ioc_tool.ui import cli


def test_imports():
    """All core + module packages import without side effects (other than .env read)."""
    from ioc_tool import main  # noqa: F401
    from ioc_tool.core import enrich, database, parser  # noqa: F401
    from ioc_tool.modules import (  # noqa: F401
        vt,
        abuseipdb,
        shodan_mod,
        ip_quality_score,
        ipinfo_mod,
        tor,
        whois_mod,
        filescan_io,
        hybrid_analysis,
        joe_sandbox,
    )
    from ioc_tool.ui import cli, banner  # noqa: F401


def test_vt_score_zero_when_empty():
    assert score.calculate_vt_score({}) == 0
    assert score.calculate_vt_score(None) == 0


def test_vt_score_basic():
    stats = {"malicious": 5, "suspicious": 0, "harmless": 45, "undetected": 50}
    assert score.calculate_vt_score(stats) == 5  # 5/100 * 100


def test_abuseipdb_score():
    assert score.calculate_abuseipdb_score({"abuseConfidenceScore": 73}) == 73
    assert score.calculate_abuseipdb_score({}) == 0
    assert score.calculate_abuseipdb_score(None) == 0


def test_final_risk_average():
    assert score.calculate_final_risk([20, 40, 60]) == 40
    assert score.calculate_final_risk([]) == 0


def test_whois_score_unknown_age():
    assert score.calculate_whois_score(None) == 50


def test_cli_parser_builds_with_all_subcommands():
    """The argparse parser exposes the four expected subcommands."""
    parser = cli.build_parser()
    # subparsers action is registered as 'command' dest
    subparsers_action = next(
        a for a in parser._actions if getattr(a, 'dest', None) == 'command'
    )
    assert set(subparsers_action.choices.keys()) == {'enrich', 'analyze', 'shodan', 'show'}


def test_cli_enrich_help_exits_cleanly():
    """`enrich --help` should raise SystemExit(0) — argparse's success path."""
    parser = cli.build_parser()
    with pytest.raises(SystemExit) as excinfo:
        parser.parse_args(['enrich', '--help'])
    assert excinfo.value.code == 0


def test_cli_enrich_parses_positional_ioc():
    """Positional IOC routes to args.ioc with file defaulting to None."""
    parser = cli.build_parser()
    args = parser.parse_args(['enrich', '8.8.8.8'])
    assert args.command == 'enrich'
    assert args.ioc == '8.8.8.8'
    assert args.file is None


def test_cli_enrich_parses_file_flag():
    """`enrich -f path` sets args.file and leaves ioc None."""
    parser = cli.build_parser()
    args = parser.parse_args(['enrich', '-f', 'iocs.txt'])
    assert args.command == 'enrich'
    assert args.ioc is None
    assert args.file == 'iocs.txt'

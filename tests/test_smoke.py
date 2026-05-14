"""Smoke tests — no live API calls. Verify imports and pure-logic helpers."""

import pytest

from ioc_tool.core import defang as defang_mod, parser as parser_mod, score
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


# ---------------------------------------------------------------------------
# Defang / refang
# ---------------------------------------------------------------------------


def test_refang_basic():
    """All conventional defang patterns get restored to their live form."""
    assert defang_mod.refang("1[.]2[.]3[.]4") == "1.2.3.4"
    assert defang_mod.refang("hxxp://evil[.]com/path") == "http://evil.com/path"
    assert defang_mod.refang("hxxps://evil[.]com") == "https://evil.com"
    # Case-preserving on the xx -> tt swap; the rest of the string is left alone.
    assert defang_mod.refang("hXXp://EVIL[.]com") == "hTTp://EVIL.com"
    assert defang_mod.refang("HXXP://EVIL[.]COM") == "HTTP://EVIL.COM"
    assert defang_mod.refang("attacker[at]gmail[.]com") == "attacker@gmail.com"
    assert defang_mod.refang("user[@]example[.]com") == "user@example.com"
    assert defang_mod.refang("evil(.)example(.)com") == "evil.example.com"
    assert defang_mod.refang("evil{.}example{.}com") == "evil.example.com"
    assert defang_mod.refang("hxxp[:]//evil[.]com") == "http://evil.com"
    assert defang_mod.refang("  hxxp://evil[.]com  ") == "http://evil.com"
    assert defang_mod.refang("fxp://files[.]evil[.]com") == "ftp://files.evil.com"


def test_defang_basic():
    """Round-trip clean IOCs through defang."""
    assert defang_mod.defang("1.2.3.4") == "1[.]2[.]3[.]4"
    assert defang_mod.defang("http://evil.com/path") == "hxxp://evil[.]com/path"
    assert defang_mod.defang("https://evil.com") == "hxxps://evil[.]com"
    assert defang_mod.defang("attacker@gmail.com") == "attacker[@]gmail[.]com"
    assert defang_mod.defang("bad.example.com") == "bad[.]example[.]com"


def test_refang_idempotent():
    """refang(refang(x)) == refang(x) for the common shapes."""
    for sample in (
        "1[.]2[.]3[.]4",
        "hxxp://evil[.]com/path",
        "attacker[at]gmail[.]com",
        "8.8.8.8",
        "https://already-live.example.com",
    ):
        once = defang_mod.refang(sample)
        twice = defang_mod.refang(once)
        assert once == twice, f"refang not idempotent for {sample!r}: {once!r} != {twice!r}"


def test_defang_idempotent():
    """defang(defang(x)) == defang(x) for the common shapes."""
    for sample in (
        "1.2.3.4",
        "http://evil.com/path",
        "attacker@gmail.com",
        "bad.example.com",
        # already-defanged input should remain stable
        "1[.]2[.]3[.]4",
        "hxxp://evil[.]com",
    ):
        once = defang_mod.defang(sample)
        twice = defang_mod.defang(once)
        assert once == twice, f"defang not idempotent for {sample!r}: {once!r} != {twice!r}"


def test_refang_defang_roundtrip_common_case():
    """For typical defanged input, refang then defang reproduces the original."""
    samples = (
        "1[.]2[.]3[.]4",
        "hxxp://evil[.]com",
        "hxxps://evil[.]com",
        "bad[.]example[.]com",
        "attacker[@]gmail[.]com",
    )
    for sample in samples:
        assert defang_mod.defang(defang_mod.refang(sample)) == sample


def test_parser_handles_defanged_input():
    """parser.detect_type sees defanged IOCs and classifies them correctly."""
    assert parser_mod.detect_type("1[.]2[.]3[.]4") == "ip"
    assert parser_mod.detect_type("hxxp://evil[.]com") == "url"
    assert parser_mod.detect_type("bad[.]example[.]com") == "domain"
    assert parser_mod.detect_type("attacker[at]gmail[.]com") == "email"
    # Live forms keep working unchanged
    assert parser_mod.detect_type("8.8.8.8") == "ip"
    assert parser_mod.detect_type("https://example.com") == "url"


def test_cli_defang_flag_parses():
    """The top-level --defang flag is accepted on any subcommand."""
    parser = cli.build_parser()
    args = parser.parse_args(['--defang', 'enrich', '8.8.8.8'])
    assert args.defang is True
    assert args.command == 'enrich'
    assert args.ioc == '8.8.8.8'

    # default off
    args2 = parser.parse_args(['enrich', '8.8.8.8'])
    assert args2.defang is False

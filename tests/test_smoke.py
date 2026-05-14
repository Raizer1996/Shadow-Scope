"""Smoke tests — no live API calls. Verify imports and pure-logic helpers."""

import json
from datetime import datetime

import pytest

from ioc_tool.core import (
    defang as defang_mod,
    extractor as extractor_mod,
    output as output_mod,
    parser as parser_mod,
    score,
)
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


# ---------------------------------------------------------------------------
# JSON / CSV output formats
# ---------------------------------------------------------------------------


def _sample_ip_result() -> dict:
    """Build a representative enrichment dict mirroring enrich_ioc()."""
    return {
        "ioc": "8.8.8.8",
        "type": "ip",
        "final_score": 42,
        "modules": {
            "VirusTotal": {
                "score": 3,
                "data": {
                    "last_analysis_stats": {
                        "malicious": 3,
                        "suspicious": 0,
                        "harmless": 60,
                        "undetected": 30,
                    }
                },
            },
            "AbuseIPDB": {
                "score": 50,
                "data": {"abuseConfidenceScore": 50, "usageType": "Data Center"},
            },
            "Shodan": {
                "score": 0,
                "data": {"tags": ["vpn", "cloud"], "ports": [22, 80, 443]},
            },
            "IPQS": {
                "score": 25,
                "data": {"fraud_score": 25},
            },
            "IPinfo": {
                "score": 0,
                "data": {"org": "AS15169 Google LLC", "country": "US"},
            },
            "TOR": {"score": 100, "data": {"is_tor": True}},
        },
    }


def _sample_domain_result() -> dict:
    """Domain enrichment — no Shodan / IPinfo / Tor blocks present."""
    return {
        "ioc": "example.com",
        "type": "domain",
        "final_score": 10,
        "modules": {
            "VirusTotal": {
                "score": 0,
                "data": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 80,
                        "undetected": 10,
                    }
                },
            },
            "WHOIS": {
                "score": 10,
                "data": {"creation_date": "1995-08-14T04:00:00"},
            },
        },
    }


def test_to_json_serializes_all_fields():
    """to_json returns parseable JSON and round-trips the IOC value."""
    payload = output_mod.to_json([_sample_ip_result()])
    parsed = json.loads(payload)
    assert isinstance(parsed, list)
    assert parsed[0]["ioc"] == "8.8.8.8"
    assert parsed[0]["type"] == "ip"
    assert parsed[0]["final_score"] == 42
    # All module blocks must survive serialization
    assert "VirusTotal" in parsed[0]["modules"]
    assert "AbuseIPDB" in parsed[0]["modules"]
    assert parsed[0]["modules"]["Shodan"]["data"]["ports"] == [22, 80, 443]


def test_to_csv_has_expected_header():
    """First CSV line is the documented header row."""
    csv_str = output_mod.to_csv([_sample_ip_result()])
    first_line = csv_str.splitlines()[0]
    expected_header = ",".join(output_mod.CSV_COLUMNS)
    assert first_line == expected_header


def test_to_csv_handles_missing_modules():
    """IOCs without Shodan/IPinfo/Tor produce empty cells, not crashes."""
    csv_str = output_mod.to_csv([_sample_domain_result()])
    lines = csv_str.splitlines()
    assert len(lines) == 2  # header + 1 data row
    header = lines[0].split(",")
    row = lines[1].split(",")
    record = dict(zip(header, row))
    assert record["ioc"] == "example.com"
    assert record["type"] == "domain"
    assert record["shodan_tags"] == ""
    assert record["shodan_ports"] == ""
    assert record["ipinfo_org"] == ""
    assert record["tor"] == ""
    assert record["whois_creation_date"] == "1995-08-14T04:00:00"


def test_to_json_handles_datetime():
    """Datetime in the payload must serialize without TypeError."""
    sample = _sample_domain_result()
    sample["modules"]["WHOIS"]["data"]["creation_date"] = datetime(1995, 8, 14, 4, 0, 0)
    payload = output_mod.to_json([sample])
    parsed = json.loads(payload)
    creation = parsed[0]["modules"]["WHOIS"]["data"]["creation_date"]
    assert "1995-08-14" in creation


def test_risk_tier_boundaries():
    """Tier mapping aligns with docs/ARCHITECTURE.md."""
    assert output_mod._risk_tier(0) == "Safe"
    assert output_mod._risk_tier(19) == "Safe"
    assert output_mod._risk_tier(20) == "Low"
    assert output_mod._risk_tier(40) == "Medium"
    assert output_mod._risk_tier(60) == "High"
    assert output_mod._risk_tier(80) == "Critical"
    assert output_mod._risk_tier(100) == "Critical"


def test_cli_enrich_accepts_json_flag():
    """`enrich <ioc> --json` sets args.json=True / args.csv=False."""
    parser = cli.build_parser()
    args = parser.parse_args(['enrich', '8.8.8.8', '--json'])
    assert args.command == 'enrich'
    assert args.json is True
    assert args.csv is False


def test_cli_enrich_accepts_csv_flag():
    """`enrich <ioc> --csv` sets args.csv=True / args.json=False."""
    parser = cli.build_parser()
    args = parser.parse_args(['enrich', '8.8.8.8', '--csv'])
    assert args.command == 'enrich'
    assert args.csv is True
    assert args.json is False


def test_cli_json_and_csv_are_mutually_exclusive():
    """Passing both --json and --csv exits the parser."""
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(['enrich', '8.8.8.8', '--json', '--csv'])


# ---------------------------------------------------------------------------
# IOC extraction from text blobs
# ---------------------------------------------------------------------------


def test_extract_iocs_ip():
    """Two valid IPs surface; the bogus 999.999.999.999 string is dropped."""
    text = "We saw 1.2.3.4 then 9.9.9.9 and ignore 999.999.999.999 entirely"
    result = extractor_mod.extract_iocs(text)
    assert result.get("ip") == ["1.2.3.4", "9.9.9.9"]


def test_extract_iocs_defanged():
    """Refang runs before extraction so defanged IOCs are caught."""
    text = "see 1[.]2[.]3[.]4 and hxxp://evil[.]com/bad for details"
    result = extractor_mod.extract_iocs(text)
    assert "1.2.3.4" in result.get("ip", [])
    # The URL must be refanged into its live form.
    assert any(u.startswith("http://evil.com") for u in result.get("url", []))


def test_extract_iocs_mixed_blob():
    """A paragraph with all 5 IOC types yields one of each."""
    text = (
        "Incident report: attacker 198.51.100.42 hit our edge from "
        "http://malicious.example.org/payload. Phishing email came from "
        "attacker@evil.com referencing badguy.io. Dropped sample SHA256 "
        "d3486ae9136e7856bc42212385ea797094475802bcc9b2a8b6f23f5a1f5f4b6c."
    )
    result = extractor_mod.extract_iocs(text)
    assert "198.51.100.42" in result.get("ip", [])
    assert any("malicious.example.org" in u for u in result.get("url", []))
    assert "attacker@evil.com" in result.get("email", [])
    assert "badguy.io" in result.get("domain", [])
    assert (
        "d3486ae9136e7856bc42212385ea797094475802bcc9b2a8b6f23f5a1f5f4b6c"
        in result.get("hash", [])
    )


def test_extract_iocs_dedup():
    """Repeated IPs are collapsed to one entry, first-seen order preserved."""
    text = "1.2.3.4 again 1.2.3.4 and once more 1.2.3.4 alongside 5.6.7.8"
    result = extractor_mod.extract_iocs(text)
    assert result.get("ip") == ["1.2.3.4", "5.6.7.8"]


def test_extract_iocs_filename_excluded():
    """Strings like report.pdf / script.py must not surface as domains."""
    text = "Generated report.pdf and ran script.py against the host"
    result = extractor_mod.extract_iocs(text)
    domains = result.get("domain", [])
    assert "report.pdf" not in domains
    assert "script.py" not in domains


def test_extract_iocs_url_host_dedupe():
    """A host already captured in a URL must not also appear as a domain."""
    text = "Click http://evil.com/bad to see the payload"
    result = extractor_mod.extract_iocs(text)
    assert any(u.startswith("http://evil.com") for u in result.get("url", []))
    # evil.com is the URL host, so it should NOT also be in the domain list.
    assert "evil.com" not in result.get("domain", [])


def test_cli_text_flag_parses():
    """`enrich --text "blob"` round-trips through argparse."""
    parser = cli.build_parser()
    args = parser.parse_args(['enrich', '--text', 'saw 1.2.3.4 today'])
    assert args.command == 'enrich'
    assert args.text == 'saw 1.2.3.4 today'
    assert args.ioc is None
    assert args.file is None


def test_cli_stdin_dash_parses():
    """`enrich -` is accepted as a valid positional sentinel for stdin."""
    parser = cli.build_parser()
    args = parser.parse_args(['enrich', '-'])
    assert args.command == 'enrich'
    assert args.ioc == '-'
    assert args.file is None
    assert args.text is None


def test_urlhaus_csv_column_present():
    """The CSV column list includes urlhaus_threat for downstream pipelines."""
    assert 'urlhaus_threat' in output_mod.CSV_COLUMNS


def test_greynoise_csv_columns_present():
    """CSV exports include the GreyNoise classification + name columns."""
    assert 'greynoise_classification' in output_mod.CSV_COLUMNS
    assert 'greynoise_name' in output_mod.CSV_COLUMNS


def test_threatfox_csv_columns_present():
    """CSV exports include the ThreatFox threat_type + malware columns."""
    assert 'threatfox_threat_type' in output_mod.CSV_COLUMNS
    assert 'threatfox_malware' in output_mod.CSV_COLUMNS


def test_malwarebazaar_csv_columns_present():
    """CSV exports include the MalwareBazaar signature + file_type columns."""
    assert 'malwarebazaar_signature' in output_mod.CSV_COLUMNS
    assert 'malwarebazaar_file_type' in output_mod.CSV_COLUMNS

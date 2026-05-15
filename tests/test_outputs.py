"""Tests for STIX 2.1 and Markdown output formats."""

import json

from ioc_tool.core import output as output_mod


def _ip_result(score: int = 5) -> dict:
    return {
        "ioc": "8.8.8.8",
        "type": "ip",
        "final_score": score,
        "modules": {
            "VirusTotal": {
                "score": score,
                "data": {
                    "last_analysis_stats": {
                        "malicious": 5, "harmless": 60, "suspicious": 0, "undetected": 35,
                    },
                },
            },
        },
    }


def _domain_result(score: int = 85) -> dict:
    return {
        "ioc": "evil.example.com",
        "type": "domain",
        "final_score": score,
        "modules": {
            "URLhaus": {"score": 95, "data": {}},
            "Heuristics": {
                "score": 75,
                "data": {
                    "nrd": {"score": 75, "age_days": 12, "bucket": "nrd", "created": "2026-05-03"},
                    "dga": {
                        "score": 30, "entropy": 2.3, "longest_consonant_run": 3,
                        "label": "example", "bigram_improbability": 0.25,
                    },
                },
            },
        },
    }


# ---------------------------------------------------------------------------
# STIX 2.1
# ---------------------------------------------------------------------------


def test_stix_empty_input_returns_empty_bundle():
    bundle = json.loads(output_mod.to_stix([]))
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert bundle["objects"] == []


def test_stix_emits_indicator_per_supported_ioc():
    bundle = json.loads(output_mod.to_stix([_ip_result(), _domain_result()]))
    assert len(bundle["objects"]) == 2
    for indicator in bundle["objects"]:
        assert indicator["type"] == "indicator"
        assert indicator["spec_version"] == "2.1"
        assert indicator["pattern_type"] == "stix"
        assert indicator["id"].startswith("indicator--")


def test_stix_ipv4_pattern_shape():
    bundle = json.loads(output_mod.to_stix([_ip_result()]))
    pattern = bundle["objects"][0]["pattern"]
    assert pattern == "[ipv4-addr:value = '8.8.8.8']"


def test_stix_domain_pattern_shape():
    bundle = json.loads(output_mod.to_stix([_domain_result()]))
    pattern = bundle["objects"][0]["pattern"]
    assert pattern == "[domain-name:value = 'evil.example.com']"


def test_stix_hash_pattern_picks_algorithm():
    sample = {
        "ioc": "d41d8cd98f00b204e9800998ecf8427e",  # MD5
        "type": "hash",
        "final_score": 0,
        "modules": {},
    }
    bundle = json.loads(output_mod.to_stix([sample]))
    assert bundle["objects"][0]["pattern"] == "[file:hashes.'MD5' = 'd41d8cd98f00b204e9800998ecf8427e']"


def test_stix_unsupported_type_silently_dropped():
    """CVE has no observable equivalent in STIX 2.1 — should be omitted, not crash."""
    sample = {"ioc": "CVE-2024-1234", "type": "cve", "final_score": 80, "modules": {}}
    bundle = json.loads(output_mod.to_stix([sample]))
    assert bundle["objects"] == []


def test_stix_indicator_types_reflect_score():
    """Score >= 60 → 'malicious-activity'; lower → 'anomalous-activity' or 'unknown'."""
    malicious = json.loads(output_mod.to_stix([_domain_result(score=85)]))
    benign = json.loads(output_mod.to_stix([_ip_result(score=5)]))
    assert "malicious-activity" in malicious["objects"][0]["indicator_types"]
    assert "unknown" in benign["objects"][0]["indicator_types"]


def test_stix_indicator_id_is_stable():
    """Same IOC + type → same indicator UUID (idempotent re-enrichment)."""
    first = json.loads(output_mod.to_stix([_ip_result()]))
    second = json.loads(output_mod.to_stix([_ip_result()]))
    assert first["objects"][0]["id"] == second["objects"][0]["id"]


def test_stix_indicator_description_carries_score():
    bundle = json.loads(output_mod.to_stix([_domain_result()]))
    desc = bundle["objects"][0]["description"]
    assert "composite score: 85" in desc
    assert "Critical" in desc


def test_stix_labels_include_score_and_tier():
    bundle = json.loads(output_mod.to_stix([_domain_result()]))
    labels = bundle["objects"][0]["labels"]
    assert any(label.startswith("shadowscope:score:") for label in labels)
    assert any(label.startswith("shadowscope:tier:") for label in labels)


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def test_md_empty_input_renders_placeholder():
    md = output_mod.to_markdown([])
    assert "No IOCs" in md


def test_md_renders_ioc_header():
    md = output_mod.to_markdown([_ip_result()])
    assert "# ShadowScope Report" in md
    assert "`8.8.8.8`" in md
    assert "(type: ip)" in md


def test_md_score_banner_uses_correct_tier():
    md = output_mod.to_markdown([_domain_result(score=85)])
    assert "Critical" in md
    assert "85/100" in md


def test_md_includes_module_table():
    md = output_mod.to_markdown([_domain_result()])
    assert "| Source |" in md
    assert "URLhaus" in md
    assert "Heuristics" in md


def test_md_surfaces_heuristic_flags():
    md = output_mod.to_markdown([_domain_result()])
    assert "**Heuristics:**" in md
    assert "NRD: nrd" in md
    assert "DGA: score 30" in md


def test_md_includes_llm_verdict_when_summary_provided():
    md = output_mod.to_markdown([_ip_result()], include_summaries={0: "Benign Google DNS resolver."})
    assert "**LLM Verdict:**" in md
    assert "Benign Google DNS resolver." in md


def test_md_skips_llm_block_when_summary_none():
    md = output_mod.to_markdown([_ip_result()], include_summaries={0: None})
    assert "**LLM Verdict:**" not in md


def test_md_multiple_iocs_get_separators():
    md = output_mod.to_markdown([_ip_result(), _domain_result()])
    # Three '---' separators: top + after IOC 1 + after IOC 2
    assert md.count("---") >= 3


# ---------------------------------------------------------------------------
# Source agreement / consensus matrix
# ---------------------------------------------------------------------------


def test_consensus_empty_modules():
    summary = output_mod.consensus_summary({"modules": {}})
    assert summary["sources_total"] == 0
    assert summary["consensus"] == "none"


def test_consensus_excludes_info_only_modules():
    """Shodan, IPinfo, Heuristics, Allowlist, crt.sh shouldn't count as opinion sources."""
    result = {
        "modules": {
            "Shodan": {"score": 0, "data": {}},
            "IPinfo": {"score": 0, "data": {}},
            "Heuristics": {"score": 50, "data": {}},
            "Allowlist": {"score": 0, "data": {}},
            "crt.sh": {"score": 15, "data": {}},
            "VirusTotal": {"score": 0, "data": {}},
        }
    }
    summary = output_mod.consensus_summary(result)
    # Only VirusTotal counts — the rest are non-opinion.
    assert summary["sources_total"] == 1
    assert {r["source"] for r in summary["rows"]} == {"VirusTotal"}


def test_consensus_high_when_most_sources_flag():
    """≥70% flagged → high consensus."""
    result = {
        "modules": {
            "VirusTotal": {"score": 60, "data": {}},
            "AbuseIPDB": {"score": 50, "data": {}},
            "URLhaus": {"score": 80, "data": {}},
            "OTX": {"score": 0, "data": {}},
        }
    }
    summary = output_mod.consensus_summary(result)
    assert summary["sources_flagged"] == 3
    assert summary["sources_total"] == 4
    assert summary["consensus"] == "high"


def test_consensus_medium_when_split():
    """40-70% flagged → medium."""
    result = {
        "modules": {
            "VirusTotal": {"score": 60, "data": {}},
            "AbuseIPDB": {"score": 0, "data": {}},
            "URLhaus": {"score": 50, "data": {}},
            "OTX": {"score": 0, "data": {}},
        }
    }
    summary = output_mod.consensus_summary(result)
    assert summary["consensus"] == "medium"


def test_consensus_low_when_one_source_only():
    """<40% but >0 → low — the anti-false-positive bucket."""
    result = {
        "modules": {
            "VirusTotal": {"score": 50, "data": {}},
            "AbuseIPDB": {"score": 0, "data": {}},
            "URLhaus": {"score": 0, "data": {}},
            "OTX": {"score": 0, "data": {}},
            "ThreatFox": {"score": 0, "data": {}},
        }
    }
    summary = output_mod.consensus_summary(result)
    assert summary["sources_flagged"] == 1
    assert summary["consensus"] == "low"


def test_consensus_none_when_zero_flagged():
    result = {
        "modules": {
            "VirusTotal": {"score": 0, "data": {}},
            "AbuseIPDB": {"score": 0, "data": {}},
        }
    }
    summary = output_mod.consensus_summary(result)
    assert summary["consensus"] == "none"
    assert summary["sources_flagged"] == 0


def test_md_includes_consensus_block():
    """The Markdown renderer should surface the consensus tag for an IOC with sources."""
    md = output_mod.to_markdown([_domain_result()])
    assert "Source agreement" in md
    assert "consensus" in md.lower()


def test_md_skips_consensus_when_no_sources():
    md = output_mod.to_markdown([{"ioc": "x", "type": "ip", "final_score": 0, "modules": {}}])
    assert "Source agreement" not in md

"""Dashboard honesty fixes: GreyNoise suspicious, consensus, real fetch times, NVD status."""

from __future__ import annotations

from ioc_tool.core import database as _db
from ioc_tool.core import output as output_mod
from ioc_tool.core import score
from ioc_tool.web import api


def test_greynoise_suspicious_scores():
    assert score.calculate_greynoise_score({"classification": "suspicious"}) == 50
    assert score.calculate_greynoise_score({"classification": "malicious"}) == 90
    assert score.calculate_greynoise_score({"classification": "benign"}) == 0


def test_consensus_ignores_context_sources_and_faint_scores():
    result = {
        "unavailable": {"OTX": "timeout"},
        "modules": {
            "AbuseIPDB": {"score": 100}, "Pulsedive": {"score": 95}, "VirusTotal": {"score": 85},
            "URLscan": {"score": 30},            # "history exists" is not a flag
            "IPQS": {"score": 0},
            "Censys": {"score": 0}, "rDNS": {"score": 0}, "PDNS": {"score": 0},
            "Shodan": {"score": 0}, "IPinfo": {"score": 0}, "ASN": {"score": 0},
        },
    }
    s = output_mod.consensus_summary(result)
    assert {r["source"] for r in s["rows"]} == {"AbuseIPDB", "Pulsedive", "VirusTotal", "URLscan", "IPQS"}
    assert (s["sources_flagged"], s["sources_total"]) == (3, 5)
    assert s["consensus"] == "medium" and s["flag_threshold"] == 40
    assert s["sources_unavailable"] == 1


def test_ui_shape_carries_real_fetch_time_and_degraded(monkeypatch, tmp_path):
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "ioc.db"))
    _db.init_db()
    ioc_id = _db.add_or_update_ioc("203.0.113.50", "ip")
    _db.add_enrichment(ioc_id, "abuseipdb", {"abuseConfidenceScore": 100}, 100)
    shaped = api._to_ui_shape(
        {"ioc": "203.0.113.50", "type": "ip", "final_score": 90, "degraded": True,
         "unavailable": {"VirusTotal": "rate_limited"},
         "modules": {"AbuseIPDB": {"score": 100, "data": {"abuseConfidenceScore": 100}},
                     "TOR": {"score": 100, "data": {"is_tor": True}}}},
        prev_score=None,
    )
    assert shaped["degraded"] is True and shaped["unavailable"] == {"VirusTotal": "rate_limited"}
    assert shaped["modules"]["AbuseIPDB"]["fetched_at"].endswith("Z")
    assert "fetched_at" not in shaped["modules"]["TOR"]        # computed locally, never cached
    assert _db.get_latest_fetch_times(ioc_id).keys() == {"abuseipdb"}


def test_nvd_reports_key_state(monkeypatch):
    entry = next(s for s in api._SOURCE_REGISTRY if s["id"] == "NVD")
    assert entry["env"] == "NVD_API_KEY" and entry.get("anonymous_ok") is True

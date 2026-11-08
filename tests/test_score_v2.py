"""Composite score v2 — strongest weighted signal + corroboration.

Scenarios are the ones that exposed v1's dilution during the 2026-11 review.
"""

from __future__ import annotations

from ioc_tool.core import database as _db
from ioc_tool.core import score
from ioc_tool.core.score import calculate_final_risk as risk


def test_tor_exit_with_strong_reputation_is_critical():
    # Live 185.220.101.5 under v1: 57 "Medium". Two+ strong sources → bonus.
    scores = [
        ("AbuseIPDB", 100), ("TOR", 100), ("Pulsedive", 95), ("GreyNoise", 90),
        ("AbstractAPI", 70), ("OTX", 35), ("URLscan", 30), ("VirusTotal", 11),
        ("IPQS", 0), ("Shodan", 0), ("IPinfo", 0),
    ]
    assert risk(scores) == 100
    assert score.risk_tier(risk(scores)) == "Critical"


def test_feodo_listed_c2_is_critical_even_when_everything_else_is_quiet():
    scores = [("Feodo", 95)] + [(n, 0) for n in ("VirusTotal", "AbuseIPDB", "GreyNoise", "OTX", "URLscan", "URLhaus", "ThreatFox")]
    assert risk(scores) == 95          # v1 gave 14 "Safe"


def test_kev_alone_is_100():
    assert risk([("KEV", 100), ("NVD", 0), ("EPSS", 0)]) == 100


def test_clean_ip_stays_zero():
    assert risk([("VirusTotal", 0), ("AbuseIPDB", 0), ("GreyNoise", 0), ("IPQS", 0), ("OTX", 0)]) == 0
    assert risk([]) == 0


def test_quiet_popular_domain_stays_safe():
    # google.com-like: VT 1/92, URLscan "history exists" 30, WHOIS old 10.
    assert risk([("VirusTotal", 1), ("URLscan", 30), ("WHOIS", 10), ("OTX", 0)]) == 18
    assert score.risk_tier(18) == "Safe"


def test_single_weak_signal_caps_at_low():
    assert risk([("OTX", 35)]) == 25            # 35 * 0.7 → Low, never Medium alone
    assert risk([("AbstractAPI", 100)]) == 40   # tier-4 source alone caps at Medium floor


def test_two_strong_sources_get_corroboration_bonus():
    # EICAR: VT 88 (79.2) + OTX 90 (63) → both >= 50 → +10
    assert risk([("VirusTotal", 88), ("OTX", 90)]) == 89
    # one strong + one weak → no bonus
    assert risk([("VirusTotal", 88), ("OTX", 20)]) == 79


def test_monotone_more_evidence_never_lowers():
    base = [("AbuseIPDB", 100)]
    assert risk(base) == 90
    assert risk(base + [("GreyNoise", 0), ("URLscan", 0), ("OTX", 0)]) == 90
    assert risk(base + [("Pulsedive", 95)]) >= 90


def test_tor_alone_is_medium_not_high():
    assert risk([("TOR", 100)]) == 50
    assert score.risk_tier(50) == "Medium"


def test_legacy_bare_ints_and_junk():
    assert risk([20, 40, 60]) == 30
    assert risk([("VirusTotal", "n/a"), ("AbuseIPDB", None), ("OTX", 50)]) == 35
    assert risk([("Unknown Source", 100)]) == 50   # default weight 0.5


def test_clamped_to_100():
    assert risk([("KEV", 100), ("Feodo", 100), ("SSLBL", 100)]) == 100


def test_version_constant_exposed():
    assert score.SCORE_VERSION == 2


def test_score_history_rows_carry_version(monkeypatch, tmp_path):
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "ioc.db"))
    _db.init_db()
    conn = _db.get_db_connection()
    conn.execute("INSERT INTO iocs (value, type) VALUES ('198.51.100.9', 'ip')")
    conn.commit()
    ioc_id = conn.execute("SELECT id FROM iocs WHERE value = '198.51.100.9'").fetchone()["id"]
    conn.close()
    _db.update_last_score(ioc_id, 77, score.SCORE_VERSION)
    _db.update_last_score(ioc_id, 12)  # legacy caller: no version
    hist = _db.get_score_history(ioc_id)
    assert [(h["score"], h["score_version"]) for h in hist] == [(77, 2), (12, None)]


def test_init_db_migrates_old_score_history(monkeypatch, tmp_path):
    """A pre-v2 cache (no score_version column) must open and keep working."""
    import sqlite3
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.execute("CREATE TABLE score_history (id INTEGER PRIMARY KEY AUTOINCREMENT, ioc_id INTEGER NOT NULL, score INTEGER NOT NULL, recorded_at TIMESTAMP NOT NULL)")
    old.execute("INSERT INTO score_history (ioc_id, score, recorded_at) VALUES (1, 55, '2026-01-01 00:00:00')")
    old.commit()
    old.close()
    monkeypatch.setattr(_db, "DB_PATH", str(path))
    _db.init_db()
    assert _db.get_score_history(1) == [{"id": 1, "score": 55, "recorded_at": "2026-01-01 00:00:00", "score_version": None}]

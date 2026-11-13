"""abuse.ch YARAify hash lookup: client, summary, scoring, wiring. No network."""

from __future__ import annotations

import pytest

from ioc_tool.core import score
from ioc_tool.modules import yaraify

SHA256 = "de7fa65d5cd5314ba0ce6ab19a7dcd9853639a1152447457de7efb39a9ba1f46"

# Shape taken from the public API documentation (https://yaraify.abuse.ch/api/).
ANSWER = {
    "query_status": "ok",
    "data": {
        "metadata": {
            "file_size": 792372, "file_type_mime": "application/x-dosexec",
            "first_seen": "2022-01-22 19:24:01 UTC", "last_seen": "2022-01-23 14:52:44 UTC",
            "sightings": 11, "sha256_hash": SHA256, "imphash": None, "tlsh": None,
        },
        "tasks": [
            {
                "task_id": "1f3da23c", "clamav_results": ["PUA.Win.Packer.Upx-4", "Win.Dropper.Gh0stRAT-9789289-0"],
                "static_results": [
                    {"rule_name": "pe_imphash", "author": None, "description": None, "reference": None, "tlp": "WHITE"},
                    {"rule_name": "Skystars_Malware_Imphash", "author": "Skystars LightDefender", "description": "imphash", "tlp": "WHITE"},
                ],
                "unpack_results": [
                    {"unpacked_file_name": "10000000.dll", "unpacked_yara_matches": [
                        {"rule_name": "win_younglotus_auto", "author": "Detects win.younglotus.", "tlp": "WHITE"},
                        {"rule_name": "MALWARE_Win_Zegost", "reference": "ditekSHen", "tlp": "WHITE"},
                    ]},
                    "junk",
                ],
            },
            {   # second scan of the same file repeats the same matches
                "task_id": "e7cdd149", "clamav_results": ["PUA.Win.Packer.Upx-4", "Win.Dropper.Gh0stRAT-9789289-0"],
                "static_results": [{"rule_name": "PE_IMPHASH"}, {"rule_name": ""}, "junk"],
                "unpack_results": [],
            },
            "junk",
        ],
    },
}


class _Resp:
    def __init__(self, payload=None, status=200, bad_json=False):
        self.status_code = status
        self._payload = payload
        self._bad = bad_json

    def json(self):
        if self._bad:
            raise ValueError("not json")
        return self._payload


@pytest.fixture
def post(monkeypatch):
    calls = []

    def install(answer):
        def fake(source, url, **kwargs):
            calls.append((source, url, kwargs))
            return answer

        monkeypatch.setattr(yaraify.http, "post", fake)
        return calls

    return install


def test_request_shape_and_summary(post):
    calls = post(_Resp(ANSWER))
    out = yaraify.enrich_hash(SHA256)
    source, url, kwargs = calls[0]
    assert source == "yaraify" and url == "https://yaraify-api.abuse.ch/api/v1/"
    assert kwargs["json"] == {"query": "lookup_hash", "search_term": SHA256}
    assert kwargs["headers"] == {"Auth-Key": "test-auth-key"}

    assert out["sightings"] == 11 and out["scans"] == 2 and out["file_type_mime"] == "application/x-dosexec"
    assert out["first_seen"] == "2022-01-22 19:24:01 UTC"
    # De-duplicated across scans, case-insensitively; junk entries dropped.
    assert [r["rule_name"] for r in out["yara_rules"]] == [
        "pe_imphash", "Skystars_Malware_Imphash", "win_younglotus_auto", "MALWARE_Win_Zegost",
    ]
    assert out["yara_rule_count"] == 4
    assert out["yara_rules"][0] == {"rule_name": "pe_imphash", "unpacked": False, "tlp": "WHITE"}
    assert out["yara_rules"][2]["unpacked"] is True
    assert out["clamav"] == ["PUA.Win.Packer.Upx-4", "Win.Dropper.Gh0stRAT-9789289-0"]
    assert out["families"] == ["win.younglotus"] and out["family"] == "win.younglotus"
    # The summary is small: the raw per-task blob is not kept.
    assert "tasks" not in out and "metadata" not in out


@pytest.mark.parametrize(
    "answer",
    [
        None,
        _Resp(status=401),
        _Resp(status=500),
        _Resp(bad_json=True),
        _Resp({"query_status": "no_results"}),
        _Resp({"query_status": "ok", "data": []}),
        _Resp({"query_status": "ok", "data": {}}),
        _Resp(["not", "a", "dict"]),
    ],
)
def test_soft_fail(post, answer):
    post(answer)
    assert yaraify.enrich_hash(SHA256) is None


def test_no_request_without_the_abusech_key(post, monkeypatch):
    calls = post(_Resp(ANSWER))
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    assert yaraify.enrich_hash(SHA256) is None and calls == []


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (None, 0),
        ({}, 0),
        ({"yara_rules": [], "clamav": [], "families": []}, 0),                      # known, nothing matched
        ({"yara_rules": [{"rule_name": "pe_imphash"}, {"rule_name": "with_urls"}]}, 20),
        ({"clamav": ["PUA.Win.Packer.Upx-4"], "yara_rules": [{"rule_name": "pe_imphash"}]}, 40),
        ({"yara_rules": [{"rule_name": "MALWARE_Win_Zegost"}]}, 80),
        ({"yara_rules": [{"rule_name": "Windows_Trojan_Emotet_5528b3b0"}]}, 80),
        ({"yara_rules": [{"rule_name": "Skystars_Malware_Imphash"}]}, 20),          # "malware" inside a name is not enough
        ({"clamav": ["PUA.Win.Packer.Upx-4", "Win.Dropper.Gh0stRAT-9789289-0"]}, 85),
        ({"families": ["win.younglotus"], "clamav": []}, 90),
    ],
)
def test_score(data, expected):
    assert score.calculate_yaraify_score(data) == expected


def test_malpedia_rule_name_pattern():
    names = ["win_emotet_auto", "elf_mirai_auto", "win_cobalt_strike_w0", "pe_imphash", "win_auto", "MALWARE_Win_Zegost"]
    summary = yaraify.summarise({"metadata": {"sightings": 1}, "tasks": [{"static_results": [{"rule_name": n} for n in names]}]})
    assert summary["families"] == ["win.emotet", "elf.mirai", "win.cobalt_strike"]


def test_wired_into_weights_buckets_registry_and_enrichment():
    from ioc_tool.core import ratelimit
    from ioc_tool.web import api

    assert score.SOURCE_WEIGHTS["YARAify"] == 0.85
    assert "yaraify" in ratelimit._DEFAULT_BUCKETS
    assert ("yaraify", "YARAify") in api._CACHED_SOURCES
    entry = next(s for s in api._SOURCE_REGISTRY if s["id"] == "YARAify")
    assert entry["env"] == "ABUSECH_AUTH_KEY" and entry["types"] == ["hash"]
    detail = api._ui_detail("YARAify", 90, {"families": ["win.younglotus"], "clamav": ["A", "B"], "yara_rule_count": 4})
    assert detail == "family win.younglotus · ClamAV A +1 · 4 YARA rules"


def test_hash_enrichment_plans_yaraify_and_other_types_do_not(monkeypatch, tmp_path):
    from ioc_tool.core import database, enrich

    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "ioc.db"))
    database.init_db()
    for value, kind, expected in ((SHA256, "hash", True), ("203.0.113.10", "ip", False)):
        ioc_id = database.add_or_update_ioc(value, kind)
        tasks, _ = enrich._build_enrich_tasks(value, kind, ioc_id)
        names = [name for name, _ in tasks]
        for _, coro in tasks:
            coro.close()  # never awaited: we only inspect the plan
        assert ("YARAify" in names) is expected

"""OTX pulse lists must reach the dashboard as plain strings."""

from __future__ import annotations

from ioc_tool.web import _synthesis

_PULSES = {"pulse_info": {"pulses": [
    {
        "name": "Mirai wave",
        "malware_families": [
            {"id": "Mirai", "display_name": "Mirai", "target": None},
            {"id": "x", "display_name": "", "target": "/malware/Gafgyt"},
            "Mirai",
            None,
            42,
        ],
        "attack_ids": [
            {"id": "T1059", "name": "Command and Scripting Interpreter", "display_name": "T1059 - Command and Scripting Interpreter"},
            "T1105",
        ],
        "tags": ["botnet"],
    },
    {"name": "plain", "malware_families": ["Emotet"], "attack_ids": None},
]}}


def test_names_flattens_objects_strings_and_junk():
    assert _synthesis._names(_PULSES["pulse_info"]["pulses"][0]["malware_families"]) == ["Mirai", "x"]
    assert _synthesis._names(None) == [] and _synthesis._names("Mirai") == []
    assert _synthesis._names([{"id": "T1059", "display_name": "long"}], prefer="id") == ["T1059"]


def _assert_plain(campaigns):
    assert [c["name"] for c in campaigns] == ["Mirai wave", "plain"]
    assert campaigns[0]["malware_families"] == ["Mirai", "x"]
    assert campaigns[0]["attack_ids"] == ["T1059", "T1105"]
    assert campaigns[1]["malware_families"] == ["Emotet"] and campaigns[1]["attack_ids"] == []
    for c in campaigns:
        assert all(isinstance(v, str) for key in ("malware_families", "attack_ids") for v in c[key])


def test_domain_core_campaigns_are_strings():
    core = _synthesis.synth_core_domain({"OTX": {"score": 90, "data": _PULSES}})
    _assert_plain(core["campaigns"])


def test_hash_core_campaigns_are_strings():
    core = _synthesis.synth_core_hash({"OTX": {"score": 90, "data": _PULSES}})
    _assert_plain(core["campaigns"])

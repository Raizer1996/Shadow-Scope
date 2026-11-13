"""`.env` loading shared by CLI, REST and MCP entry points (core.envfile)."""

from __future__ import annotations

import os

import pytest

from ioc_tool.core import envfile, paths

KEYS = ("VT_API_KEY", "ABUSECH_AUTH_KEY", "OTX_API_KEY", "SHODAN_API_KEY", "CENSYS_API_KEY")


@pytest.fixture
def env(monkeypatch, tmp_path):
    for key in KEYS:
        monkeypatch.delenv(key, raising=False)
    target = tmp_path / ".env"

    def write(text, encoding="utf-8"):
        target.write_text(text, encoding=encoding)
        return str(target)

    yield write
    for key in KEYS:
        os.environ.pop(key, None)


def test_plain_file_loads_without_warnings(env):
    path = env("# keys\nVT_API_KEY=vt-secret\nOTX_API_KEY=\n")
    assert envfile.load(path) == []
    assert os.environ["VT_API_KEY"] == "vt-secret"


def test_empty_template_line_below_a_filled_one_no_longer_wins(env):
    # The reported case: key pasted near the top, the template's empty line left at the bottom.
    path = env("VT_API_KEY=vt-secret\nABUSECH_AUTH_KEY=abuse-secret\n\n# abuse.ch\nABUSECH_AUTH_KEY=\n")
    found = envfile.load(path)
    assert os.environ["ABUSECH_AUTH_KEY"] == "abuse-secret"
    assert len(found) == 1 and found == envfile.warnings()
    assert "ABUSECH_AUTH_KEY is set on lines 2, 5" in found[0] and "line 5) is empty" in found[0]
    assert "using the value from line 2" in found[0]
    # A warning names the key and line numbers, never the secret.
    assert "abuse-secret" not in found[0]


def test_two_different_values_keeps_dotenv_behaviour_but_says_so(env):
    path = env('OTX_API_KEY="first"\nexport OTX_API_KEY=second\n')
    found = envfile.load(path)
    assert os.environ["OTX_API_KEY"] == "second"
    assert "different values" in found[0] and "line 2" in found[0]
    assert "first" not in found[0] and "second" not in found[0]


def test_harmless_repeats_are_silent(env):
    path = env("SHODAN_API_KEY=\nSHODAN_API_KEY=\nCENSYS_API_KEY=same\nCENSYS_API_KEY=same\n# VT_API_KEY=commented\n")
    assert envfile.load(path) == []
    assert os.environ["CENSYS_API_KEY"] == "same" and "VT_API_KEY" not in os.environ


def test_real_environment_always_wins(env, monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "from-the-shell")
    path = env("ABUSECH_AUTH_KEY=from-file\nABUSECH_AUTH_KEY=\n")
    envfile.load(path)
    assert os.environ["ABUSECH_AUTH_KEY"] == "from-the-shell"


def test_bom_and_missing_file(env, tmp_path):
    path = env("VT_API_KEY=bom-secret\n", encoding="utf-8-sig")
    envfile.load(path)
    assert os.environ["VT_API_KEY"] == "bom-secret"
    assert envfile.load(str(tmp_path / "missing.env")) == [] and envfile.warnings() == []


def test_default_path_is_the_per_user_home(env, monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / ".env").write_text("VT_API_KEY=home-secret\n", encoding="utf-8")
    monkeypatch.setattr(paths, "env_file", lambda: str(home / ".env"))
    envfile.load()
    assert os.environ["VT_API_KEY"] == "home-secret"


def test_template_has_every_key_exactly_once_and_in_one_block():
    with open(paths.env_example_file(), encoding="utf-8") as fh:
        text = fh.read()
    assigned = envfile._assignments(text)
    assert {k: len(v) for k, v in assigned.items() if len(v) > 1} == {}
    for key in ("VT_API_KEY", "ABUSECH_AUTH_KEY", "PULSEDIVE_API_KEY", "CTLOGS_API_KEY", "CENSYS_API_KEY"):
        assert key in assigned
    # Keys are contiguous: no prose between the first and the last assignment.
    lines = [line_no for entries in assigned.values() for line_no, _ in entries]
    block = text.splitlines()[min(lines) - 1:max(lines)]
    assert all(envfile._ASSIGN.match(line) for line in block), "keep the key block free of comments and blank lines"

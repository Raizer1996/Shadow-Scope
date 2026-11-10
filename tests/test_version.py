"""One version string, surfaced everywhere."""

from __future__ import annotations

import re

from fastapi.testclient import TestClient

import ioc_tool
from ioc_tool.web import api

client = TestClient(api.app)


def test_version_is_semver():
    assert re.fullmatch(r"\d+\.\d+\.\d+", ioc_tool.__version__)


def test_api_uses_package_version(monkeypatch):
    monkeypatch.delenv("SHADOWSCOPE_API_TOKEN", raising=False)
    assert ioc_tool.__version__ == api.API_VERSION
    assert client.get("/health").json() == {"status": "ok", "version": ioc_tool.__version__}
    assert client.get("/").json()["version"] == ioc_tool.__version__


def test_ui_shell_injects_version():
    html = client.get("/ui").text
    assert f'window.SHADOWSCOPE_VERSION = "{ioc_tool.__version__}"' in html
    assert "v0.9.2" not in html

"""Config/data path resolution + Windows-friendly IOC file reading."""

import os
from pathlib import Path

from ioc_tool.core import paths
from ioc_tool.ui import cli


def test_home_override(monkeypatch, tmp_path):
    monkeypatch.setenv("SHADOWSCOPE_HOME", str(tmp_path))
    assert paths.home_dir() == str(tmp_path)
    assert paths.env_file() == os.path.join(str(tmp_path), ".env")


def test_checkout_uses_package_dir(monkeypatch):
    # Test suite runs from a source checkout, never from site-packages.
    monkeypatch.delenv("SHADOWSCOPE_HOME", raising=False)
    assert paths.home_dir() == str(paths.PACKAGE_DIR)


def test_installed_detection():
    assert paths._is_installed_package(Path("/x/venv/lib/python3.12/site-packages/ioc_tool"))
    assert paths._is_installed_package(Path("/usr/lib/python3/dist-packages/ioc_tool"))
    assert paths._is_installed_package(Path("C:/Users/a/venv/Lib/Site-Packages/ioc_tool"))
    assert not paths._is_installed_package(Path("/home/a/Shadow-Scope/ioc_tool"))


def test_installed_package_uses_user_dir(monkeypatch, tmp_path):
    monkeypatch.delenv("SHADOWSCOPE_HOME", raising=False)
    monkeypatch.setattr(paths, "_is_installed_package", lambda: True)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    home = paths.home_dir()
    assert home.startswith(str(tmp_path)) or "Application Support" in home
    assert "shadowscope" in home.lower()


def test_env_example_is_bundled():
    assert os.path.isfile(paths.env_example_file())


def test_read_utf16_ioc_file(tmp_path):
    # Windows PowerShell 5.1 `>` / Out-File default: UTF-16 LE with BOM.
    f = tmp_path / "iocs.txt"
    # write_bytes: write_text would turn "\n" into "\r\n" on Windows.
    f.write_bytes("8.8.8.8\r\nevil.com\r\n".encode("utf-16"))
    assert cli._read_text_lines(str(f)) == ["8.8.8.8", "evil.com"]


def test_read_utf8_bom_ioc_file(tmp_path):
    f = tmp_path / "iocs.txt"
    f.write_bytes(b"\xef\xbb\xbf1.2.3.4\nexample.org\n")
    assert cli._read_text_lines(str(f)) == ["1.2.3.4", "example.org"]


def test_read_plain_utf8_ioc_file(tmp_path):
    f = tmp_path / "iocs.txt"
    f.write_text("xn--80ak6aa92e.com\n", encoding="utf-8")
    assert cli._read_text_lines(str(f)) == ["xn--80ak6aa92e.com"]

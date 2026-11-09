"""Filesystem locations for the ``.env`` file and runtime data.

Two layouts are supported:

* **Source checkout / Docker** (``git clone`` or ``COPY ioc_tool``): config
  and data live inside the package dir — ``ioc_tool/.env`` and
  ``ioc_tool/data/``. This is the historical layout and stays the default
  so existing caches, compose volumes and docs keep working.
* **Installed package** (``pip`` / ``pipx`` / the Windows installer): the
  package sits in ``site-packages``, which is wiped on upgrade and may not
  be writable, so config + data move to a per-user directory:

  - Windows: ``%LOCALAPPDATA%\\ShadowScope``
  - macOS:   ``~/Library/Application Support/ShadowScope``
  - Linux:   ``$XDG_DATA_HOME/shadowscope`` (``~/.local/share/shadowscope``)

``SHADOWSCOPE_HOME`` overrides both. It is read from the real process
environment only — the ``.env`` file's location depends on it, so it
cannot be set from inside that file.
"""

from __future__ import annotations

import contextlib
import os
import sys
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent.parent


def _is_installed_package(package_dir: Path = PACKAGE_DIR) -> bool:
    parts = {p.lower() for p in package_dir.parts}
    return "site-packages" in parts or "dist-packages" in parts


def _user_data_root() -> str:
    if os.name == "nt":
        base = os.getenv("LOCALAPPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Local"
        )
        return os.path.join(base, "ShadowScope")
    if sys.platform == "darwin":
        return os.path.join(
            os.path.expanduser("~"), "Library", "Application Support", "ShadowScope"
        )
    base = os.getenv("XDG_DATA_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "share"
    )
    return os.path.join(base, "shadowscope")


def home_dir() -> str:
    """Directory holding ``.env`` and ``data/`` for this process."""
    override = os.getenv("SHADOWSCOPE_HOME")
    if override:
        return os.path.abspath(os.path.expanduser(override))
    if _is_installed_package():
        return _user_data_root()
    return str(PACKAGE_DIR)


def env_file() -> str:
    return os.path.join(home_dir(), ".env")


def env_example_file() -> str:
    """Bundled ``.env`` template (shipped as package data)."""
    return str(PACKAGE_DIR / ".env.example")


DATA_DIR = os.path.join(home_dir(), "data")


def ensure_data_dir() -> None:
    """Create ``DATA_DIR`` if missing. Never raises — callers soft-fail later."""
    with contextlib.suppress(OSError):
        os.makedirs(DATA_DIR, exist_ok=True)

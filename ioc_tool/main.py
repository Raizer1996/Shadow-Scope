import contextlib
import os
import sys

from dotenv import load_dotenv

from ioc_tool.core import paths
from ioc_tool.ui import cli


def _force_utf8_stdio() -> None:
    # Windows: redirected stdout (`--csv > report.csv`) defaults to the ANSI
    # code page (cp1252), which can't encode the sparkline blocks / glyphs
    # the CLI prints and raises UnicodeEncodeError. Console output is already
    # UTF-16 via the Windows console API, so this only affects pipes/files.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(OSError, ValueError):
                reconfigure(encoding="utf-8", errors="replace")


def main():
    if os.name == "nt":
        _force_utf8_stdio()

    # Load environment variables (ioc_tool/.env in a checkout, per-user
    # dir when installed — see core/paths.py)
    # utf-8-sig: Notepad's UTF-8-with-BOM would otherwise glue U+FEFF onto
    # the first key name and silently drop it.
    load_dotenv(paths.env_file(), encoding="utf-8-sig")
    paths.ensure_data_dir()

    # Run CLI
    try:
        cli.main()
    except KeyboardInterrupt:
        print("\n\n[!] ShadowScope connection terminated by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()

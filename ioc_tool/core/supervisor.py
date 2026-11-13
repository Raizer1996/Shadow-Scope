"""Keep the dashboard running, and optionally up to date — ``shadowscope supervise``.

Written for machines where the usual answers do not work: Task Scheduler
blocked by endpoint policy, PowerShell logon scripts blocked by execution
policy. One per-user autostart entry (``HKCU\\...\\Run`` on Windows) that
launches ``pythonw -m ioc_tool.main supervise`` needs no admin rights and
shows no window.

What it does:

1. Starts ``shadowscope serve`` and restarts it when it exits, backing off
   from 2 s to 60 s so a crash loop cannot spin the CPU.
2. Only when asked (``--update-hours N`` and ``--source <git checkout>``):
   every N hours, if the checkout is clean and behind its upstream, fast-
   forwards it, stops the server, ``pip install --upgrade`` s it and starts
   the server again. If the install fails the checkout is put back on the
   previous commit so the next cycle retries.
3. Logs to ``<home>/logs/supervisor.log`` (about 1 MB, one old file kept).
4. Runs once per user: a second copy sees the lock and exits.

Auto-update is **off by default**: it runs code fetched from the checkout's
remote, so it is something to switch on deliberately. It never touches a
checkout with local changes and never does anything but a fast-forward.
"""

from __future__ import annotations

import contextlib
import logging
import logging.handlers
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from typing import Any

from . import paths

LOG_BYTES = 1_000_000
BACKOFF_START = 2.0
BACKOFF_MAX = 60.0
HEALTHY_AFTER = 60.0
POLL_SECONDS = 5.0
CMD_TIMEOUT = 600

RunCmd = Callable[..., "subprocess.CompletedProcess[str]"]


def logs_dir() -> str:
    path = os.path.join(paths.home_dir(), "logs")
    os.makedirs(path, exist_ok=True)
    return path


def make_logger() -> logging.Logger:
    log = logging.getLogger("shadowscope.supervisor")
    if not log.handlers:
        handler = logging.handlers.RotatingFileHandler(
            os.path.join(logs_dir(), "supervisor.log"), maxBytes=LOG_BYTES, backupCount=1, encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        log.propagate = False
    return log


class SingleInstance:
    """Advisory lock on ``<home>/logs/supervisor.lock`` held for the process lifetime."""

    def __init__(self, path: str | None = None) -> None:
        self.path = path or os.path.join(logs_dir(), "supervisor.lock")
        self._fh: Any = None

    def acquire(self) -> bool:
        fh = open(self.path, "a+")  # noqa: SIM115 - kept open on purpose: the lock lives with the handle
        try:
            # sys.platform (not os.name) so type checkers narrow the platform-only modules.
            if sys.platform == "win32":
                import msvcrt

                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            fh.close()
            return False
        self._fh = fh
        return True

    def release(self) -> None:
        if self._fh is not None:
            with contextlib.suppress(OSError):
                self._fh.close()
            self._fh = None


def console_python() -> str:
    """``python.exe`` beside a ``pythonw.exe`` interpreter (pip and git need real stdio)."""
    exe = sys.executable
    folder, name = os.path.split(exe)
    if name.lower().startswith("pythonw"):
        candidate = os.path.join(folder, "python" + name[len("pythonw"):])
        if os.path.exists(candidate):
            return candidate
    return exe


def server_command(host: str, port: int) -> list[str]:
    return [sys.executable, "-m", "ioc_tool.main", "serve", "--host", host, "--port", str(port)]


def _run(args: list[str], *, cwd: str | None = None) -> subprocess.CompletedProcess[str]:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        args, cwd=cwd, capture_output=True, text=True, timeout=CMD_TIMEOUT, creationflags=flags, check=False,
    )


def is_checkout(source: str | None) -> bool:
    return bool(source) and os.path.isdir(os.path.join(str(source), ".git"))


def pip_spec(source: str, extras: str = "") -> str:
    extras = ",".join(e.strip() for e in extras.split(",") if e.strip())
    return f"{source}[{extras}]" if extras else source


def refresh_launchers(log: logging.Logger) -> None:
    """Copy the venv's console scripts into ``<home>/bin`` if the installer made one."""
    bin_dir = os.path.join(paths.home_dir(), "bin")
    scripts = os.path.dirname(console_python())
    if not os.path.isdir(bin_dir):
        return
    for name in os.listdir(bin_dir):
        src = os.path.join(scripts, name)
        if name.lower().startswith("shadowscope") and os.path.isfile(src):
            try:
                shutil.copy2(src, os.path.join(bin_dir, name))
            except OSError as exc:  # a running MCP server keeps its .exe locked
                log.warning("could not refresh %s (in use?): %s", name, exc)


def update_once(source: str, extras: str, log: logging.Logger, *, run_cmd: RunCmd = _run,
                stop_server: Callable[[], None] = lambda: None) -> str:
    """One update attempt. Returns what happened: a short word for the log and the tests.

    ``not-a-checkout`` · ``dirty`` · ``fetch-failed`` · ``current`` · ``pull-failed`` ·
    ``install-failed`` (checkout rolled back) · ``updated``.
    """
    if not is_checkout(source):
        log.info("auto-update skipped: %s is not a git checkout", source)
        return "not-a-checkout"

    def git(*args: str) -> subprocess.CompletedProcess[str]:
        return run_cmd(["git", "-C", source, *args])

    status = git("status", "--porcelain")
    if status.returncode != 0 or status.stdout.strip():
        log.info("auto-update skipped: checkout has local changes or git status failed")
        return "dirty"
    if git("fetch", "--quiet").returncode != 0:
        log.warning("auto-update: git fetch failed")
        return "fetch-failed"
    behind = git("rev-list", "--count", "HEAD..@{u}")
    if behind.returncode != 0 or behind.stdout.strip() in ("", "0"):
        return "current"
    previous = git("rev-parse", "HEAD").stdout.strip()
    if git("pull", "--ff-only", "--quiet").returncode != 0:
        log.warning("auto-update: fast-forward failed (history diverged?) — leaving the checkout alone")
        return "pull-failed"
    new = git("rev-parse", "HEAD").stdout.strip()
    log.info("auto-update: %s -> %s (%s commits), installing", previous[:7], new[:7], behind.stdout.strip())

    stop_server()
    install = run_cmd([console_python(), "-m", "pip", "install", "--disable-pip-version-check", "--quiet",
                       "--upgrade", pip_spec(source, extras)])
    if install.returncode != 0:
        tail = (install.stderr or install.stdout or "").strip().splitlines()[-3:]
        log.error("auto-update: pip install failed, rolling the checkout back to %s. %s", previous[:7], " | ".join(tail))
        if previous:
            git("reset", "--hard", "--quiet", previous)  # safe: the tree was clean before the pull
        return "install-failed"
    refresh_launchers(log)
    log.info("auto-update: now at %s", new[:7])
    return "updated"


def supervise(
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    update_hours: float = 0,
    source: str | None = None,
    extras: str = "",
    popen: Callable[..., Any] = subprocess.Popen,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    run_cmd: RunCmd = _run,
    max_starts: int | None = None,
    log: logging.Logger | None = None,
) -> int:
    """Run until interrupted. Returns 0, or 3 when another supervisor already holds the lock."""
    log = log or make_logger()
    lock = SingleInstance()
    if not lock.acquire():
        log.info("another supervisor is already running — exiting")
        return 3

    child: Any = None

    def stop_server() -> None:
        nonlocal child
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=15)
            except Exception:  # noqa: BLE001 - whatever went wrong, make sure it is gone
                child.kill()
        child = None

    update_every = update_hours * 3600 if update_hours and update_hours > 0 and source else 0
    next_update = clock() if update_every else None
    backoff = BACKOFF_START
    starts = 0
    log.info("supervisor started (pid %s) — serving http://%s:%s, auto-update %s",
             os.getpid(), host, port, f"every {update_hours} h from {source}" if update_every else "off")
    try:
        while max_starts is None or starts < max_starts:
            if next_update is not None and clock() >= next_update:
                with contextlib.suppress(Exception):
                    update_once(str(source), extras, log, run_cmd=run_cmd, stop_server=stop_server)
                next_update = clock() + update_every

            server_log = open(os.path.join(logs_dir(), "server.log"), "ab")  # noqa: SIM115
            if server_log.tell() > LOG_BYTES:
                server_log.truncate(0)
            started = clock()
            child = popen(server_command(host, port), stdout=server_log, stderr=subprocess.STDOUT,
                          stdin=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            starts += 1
            log.info("server started (pid %s)", getattr(child, "pid", "?"))

            while child is not None and child.poll() is None:
                sleep(POLL_SECONDS)
                if next_update is not None and clock() >= next_update:
                    with contextlib.suppress(Exception):
                        update_once(str(source), extras, log, run_cmd=run_cmd, stop_server=stop_server)
                    next_update = clock() + update_every
            server_log.close()

            if child is None:  # stopped on purpose for an update: start again at once
                backoff = BACKOFF_START
                continue
            ran = clock() - started
            if ran >= HEALTHY_AFTER:
                backoff = BACKOFF_START  # it was up for a while: this is a fresh failure, not a crash loop
            delay, backoff = backoff, min(BACKOFF_MAX, backoff * 2)
            log.warning("server exited with code %s after %.0f s — restarting in %.0f s", child.returncode, ran, delay)
            child = None
            sleep(delay)
    except KeyboardInterrupt:
        log.info("supervisor stopping")
    finally:
        stop_server()
        lock.release()
    return 0

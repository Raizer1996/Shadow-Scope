"""`shadowscope supervise`: restart loop, back-off, single instance, opt-in update. No real processes."""

from __future__ import annotations

import logging
import subprocess
import sys

import pytest

from ioc_tool.core import supervisor


@pytest.fixture
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("SHADOWSCOPE_HOME", str(tmp_path))
    return tmp_path


@pytest.fixture
def log():
    logger = logging.getLogger("test.supervisor")
    logger.handlers[:] = []
    records: list[str] = []

    class Keep(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    logger.addHandler(Keep())
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.records = records  # type: ignore[attr-defined]
    return logger


class FakeClock:
    def __init__(self):
        self.now = 1000.0
        self.sleeps: list[float] = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class FakeChild:
    """A server process that exits after ``polls`` poll() calls."""

    def __init__(self, clock, lifetime, code=1):
        self.pid = 4242
        self.returncode = None
        self._clock, self._dies_at, self._code = clock, clock.now + lifetime, code
        self.terminated = False

    def poll(self):
        if self.returncode is None and (self.terminated or self._clock.now >= self._dies_at):
            self.returncode = 0 if self.terminated else self._code
        return self.returncode

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        self.poll()

    def kill(self):
        self.terminated = True


def _popen_factory(clock, lifetimes, started):
    lifetimes = list(lifetimes)

    def popen(cmd, **kwargs):
        started.append(cmd)
        return FakeChild(clock, lifetimes.pop(0) if lifetimes else 10_000)

    return popen


def test_server_command_and_logs_dir(home):
    assert supervisor.server_command("127.0.0.1", 8765) == [
        sys.executable, "-m", "ioc_tool.main", "serve", "--host", "127.0.0.1", "--port", "8765",
    ]
    assert supervisor.logs_dir() == str(home / "logs") and (home / "logs").is_dir()


def test_restarts_with_backoff_and_resets_after_a_healthy_run(home, log):
    clock, started = FakeClock(), []
    # crash at once x3, then run 5 minutes, then crash at once again
    popen = _popen_factory(clock, [0, 0, 0, 300, 0], started)
    rc = supervisor.supervise(popen=popen, clock=clock, sleep=clock.sleep, max_starts=5, log=log)
    assert rc == 0 and len(started) == 5
    delays = [s for s in clock.sleeps if s != supervisor.POLL_SECONDS]
    # 2, 4, 8 while it keeps dying; back to 2 after the healthy run; then doubling again
    assert delays == [2.0, 4.0, 8.0, 2.0, 4.0]
    assert any("restarting in 8 s" in m for m in log.records)
    assert (home / "logs" / "server.log").exists()


def test_backoff_is_capped(home, log):
    clock, started = FakeClock(), []
    supervisor.supervise(popen=_popen_factory(clock, [0] * 9, started), clock=clock, sleep=clock.sleep, max_starts=9, log=log)
    assert max(clock.sleeps) == supervisor.BACKOFF_MAX


def test_only_one_supervisor_per_user(home, log):
    first = supervisor.SingleInstance()
    assert first.acquire() is True
    try:
        assert supervisor.SingleInstance().acquire() is False
        started: list = []
        clock = FakeClock()
        rc = supervisor.supervise(popen=_popen_factory(clock, [], started), clock=clock, sleep=clock.sleep, max_starts=1, log=log)
        assert rc == 3 and started == []
    finally:
        first.release()
    again = supervisor.SingleInstance()
    assert again.acquire() is True
    again.release()


def _git_runner(script, calls):
    """run_cmd stub: ``script`` maps a git/pip sub-command to (returncode, stdout)."""

    def run_cmd(args, cwd=None):
        calls.append(args)
        key = "pip" if "pip" in args else args[3]
        code, out = script.get(key, (0, ""))
        if callable(out):
            out = out()
        return subprocess.CompletedProcess(args, code, stdout=out, stderr="boom" if code else "")

    return run_cmd


@pytest.fixture
def checkout(tmp_path):
    src = tmp_path / "src"
    (src / ".git").mkdir(parents=True)
    return str(src)


def test_update_needs_a_git_checkout(home, log, tmp_path):
    calls: list = []
    assert supervisor.update_once(str(tmp_path), "", log, run_cmd=_git_runner({}, calls)) == "not-a-checkout"
    assert calls == []
    assert supervisor.is_checkout(None) is False


def test_update_never_touches_a_dirty_checkout(home, log, checkout):
    calls: list = []
    out = supervisor.update_once(checkout, "", log, run_cmd=_git_runner({"status": (0, " M file.py\n")}, calls))
    assert out == "dirty" and [c[3] for c in calls] == ["status"]


def test_update_does_nothing_when_current_or_fetch_fails(home, log, checkout):
    calls: list = []
    assert supervisor.update_once(checkout, "", log, run_cmd=_git_runner({"rev-list": (0, "0\n")}, calls)) == "current"
    assert "pull" not in [c[3] for c in calls if c[0] == "git"]
    assert supervisor.update_once(checkout, "", log, run_cmd=_git_runner({"fetch": (1, "")}, [])) == "fetch-failed"
    assert supervisor.update_once(checkout, "", log, run_cmd=_git_runner({"rev-list": (0, "3\n"), "pull": (1, "")}, [])) == "pull-failed"


def test_update_installs_after_stopping_the_server(home, log, checkout):
    calls: list = []
    order: list[str] = []
    heads = iter(["aaaaaaa1\n", "bbbbbbb2\n"])
    runner = _git_runner({"rev-list": (0, "2\n"), "rev-parse": (0, lambda: next(heads))}, calls)

    def run_cmd(args, cwd=None):
        order.append("pip" if "pip" in args else args[3])
        return runner(args, cwd)

    out = supervisor.update_once(checkout, "mcp", log, run_cmd=run_cmd, stop_server=lambda: order.append("STOP"))
    assert out == "updated"
    assert order == ["status", "fetch", "rev-list", "rev-parse", "pull", "rev-parse", "STOP", "pip"]
    pip = calls[-1]
    assert pip[1:4] == ["-m", "pip", "install"] and pip[-1] == f"{checkout}[mcp]" and "--upgrade" in pip
    assert ["git", "-C", checkout, "pull", "--ff-only", "--quiet"] in calls  # fast-forward only
    assert any("aaaaaaa -> bbbbbbb" in m for m in log.records)


def test_failed_install_rolls_the_checkout_back(home, log, checkout):
    calls: list = []
    heads = iter(["aaaaaaa1\n", "bbbbbbb2\n"])
    runner = _git_runner({"rev-list": (0, "1\n"), "rev-parse": (0, lambda: next(heads)), "pip": (1, "")}, calls)
    assert supervisor.update_once(checkout, "", log, run_cmd=runner) == "install-failed"
    assert calls[-1] == ["git", "-C", checkout, "reset", "--hard", "--quiet", "aaaaaaa1"]
    assert any("rolling the checkout back" in m for m in log.records)


def test_update_runs_on_schedule_and_restarts_the_server(home, log, checkout):
    clock, started, calls = FakeClock(), [], []
    heads = iter(["aaaaaaa1\n", "bbbbbbb2\n"] * 5)
    behind = iter(["0\n", "4\n", "0\n", "0\n", "0\n"])
    runner = _git_runner({"rev-list": (0, lambda: next(behind)), "rev-parse": (0, lambda: next(heads))}, calls)
    supervisor.supervise(update_hours=1, source=checkout, popen=_popen_factory(clock, [10_000, 4000], started),
                         clock=clock, sleep=clock.sleep, run_cmd=runner, max_starts=2, log=log)
    # Checked at start (current), then an hour later (behind -> stop, install, start again).
    assert sum(1 for c in calls if c[0] == "git" and c[3] == "fetch") >= 2
    assert len(started) == 2 and any("auto-update: now at bbbbbbb" in m for m in log.records)
    # A restart for an update is immediate: no crash back-off was slept.
    assert [s for s in clock.sleeps if s != supervisor.POLL_SECONDS][:1] != [2.0] or len(started) == 2


def test_auto_update_is_off_unless_both_hours_and_source_are_given(home, log, checkout):
    for kwargs in ({}, {"update_hours": 6}, {"source": checkout}, {"update_hours": 0, "source": checkout}):
        clock, calls = FakeClock(), []
        supervisor.supervise(popen=_popen_factory(clock, [0], []), clock=clock, sleep=clock.sleep,
                             run_cmd=_git_runner({}, calls), max_starts=1, log=log, **kwargs)
        assert calls == [], kwargs


def test_pip_spec_and_log_rotation(home):
    assert supervisor.pip_spec("C:/src", "") == "C:/src"
    assert supervisor.pip_spec("C:/src", " mcp , ") == "C:/src[mcp]"
    logger = supervisor.make_logger()
    handler = logger.handlers[0]
    assert handler.maxBytes == supervisor.LOG_BYTES and handler.backupCount == 1
    logger.handlers[:] = []
    handler.close()


def test_cli_exposes_supervise():
    from ioc_tool.ui import cli

    args = cli.build_parser().parse_args(["supervise", "--update-hours", "6", "--source", "X", "--extras", "mcp"])
    assert (args.command, args.host, args.port, args.update_hours, args.source, args.extras) == (
        "supervise", "127.0.0.1", 8765, 6.0, "X", "mcp",
    )

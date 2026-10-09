"""Run one local command against a directory we control: no shell, scrubbed environment, timeout, bounded output.

This is not a sandbox. It removes the easy ways a command could reach beyond the fixture directory (shell expansion, the
caller's environment and credentials, a hung process, unbounded output) and states the rest plainly: network isolation
must come from the machine the probes run on (a sandbox clone or a runner with egress blocked). See SECURITY.md, W3.
"""

from __future__ import annotations

import os
import shlex
import signal
import subprocess
import tempfile
from dataclasses import dataclass

try:  # POSIX only; where it is missing the limits are simply not applied
    import resource
except ImportError:  # pragma: no cover
    resource = None  # type: ignore[assignment]

KEEP_ENV = ("PATH", "LANG", "LC_ALL", "TZ")
MAX_OUTPUT = 64 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class RunResult:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    error: str | None = None  # the command could not be run at all


def split_command(cmd: str) -> list[str]:
    """Split with shlex (never a shell). Tokens that name an existing path are made absolute, because the command runs
    in a scratch directory. Bare names are left alone so a planted file in the working directory is never picked up."""
    if not isinstance(cmd, str) or not cmd.strip():
        raise ValueError("an empty command")
    out = []
    for token in shlex.split(cmd):
        if os.sep in token and os.path.exists(token):
            token = os.path.abspath(token)
        out.append(token)
    return out


def scrubbed_env(home: str) -> dict[str, str]:
    env = {k: os.environ[k] for k in KEEP_ENV if k in os.environ}
    env.update({
        "HOME": home, "TMPDIR": home,
        # Best effort for proxy-aware clients; not a boundary. Neutral names on purpose: nothing in the environment or in the
        # scratch directory names says "this is a canary run", so a gate has no cheap way to behave differently under test.
        "http_proxy": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9", "no_proxy": "",
    })
    return env


def _limits() -> None:  # runs in the child between fork and exec
    if resource is not None:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE_BYTES, MAX_FILE_BYTES))


def _read(fh) -> str:
    fh.seek(0)
    return fh.read(MAX_OUTPUT).decode("utf-8", "replace")


def run_command(argv: list[str], *, timeout: float, scratch: str | None = None) -> RunResult:
    with tempfile.TemporaryDirectory(prefix="run-") as home:
        cwd = scratch or home
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            try:
                proc = subprocess.Popen(
                    argv, cwd=cwd, env=scrubbed_env(home), stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                    start_new_session=True, preexec_fn=_limits if resource is not None else None)
            except (OSError, ValueError) as exc:
                return RunResult(None, "", "", error=f"could not start: {type(exc).__name__}")
            timed_out = False
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    proc.kill()
                proc.wait()
            try:  # nothing the command started may outlive it
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            return RunResult(proc.returncode, _read(out), _read(err), timed_out=timed_out)

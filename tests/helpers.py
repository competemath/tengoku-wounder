import contextlib
import os
import shlex
import sys
import tempfile

from wounder import canary
from wounder.canary import GateResult
from wounder.records import PRODUCER

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS_DIR = os.path.join(ROOT, "corpus")
HEAD = "a" * 40
NOW = "2026-10-09T00:00:00Z"
CASE = {"repo": "competemath/tengoku-sandbox", "head_sha": HEAD, "class": "gate"}
PY = shlex.quote(sys.executable)


def corpus():
    return canary.load_corpus(CORPUS_DIR)


def producer():
    return dict(PRODUCER)


def repro(case_id):
    return f"python3 -m wounder run-canaries --corpus corpus --reference-gate --repo r --head {HEAD} --class gate --only {case_id} --out rerun"


def run_all(gate, entries=None):
    return canary.run_canaries(entries or corpus(), gate, CASE, producer(), NOW, repro)


class PerfectGate:
    """Test double that knows the answers (a real gate never does: it is shown only the files)."""

    def __init__(self, entries):
        self.answers = {tuple(sorted(e["files"].items())): e["expected"] == "accept" for e in entries}

    def __call__(self, case):
        return GateResult(self.answers[tuple(sorted(case["files"].items()))], [])


class AcceptAll:
    def __call__(self, case):
        return GateResult(True, [])


class RejectAll:
    def __call__(self, case):
        return GateResult(False, ["no"])


class ErroringGate:
    def __call__(self, case):
        return GateResult(False, ["boom"], error=True)


class RaisingGate:
    def __call__(self, case):
        raise RuntimeError("the gate under test blew up")


class Recorder:
    """Records every case it is shown, accepts everything."""

    def __init__(self):
        self.seen = []

    def __call__(self, case):
        self.seen.append(case)
        return GateResult(True, [])


@contextlib.contextmanager
def in_root():
    old = os.getcwd()
    os.chdir(ROOT)
    try:
        yield
    finally:
        os.chdir(old)


@contextlib.contextmanager
def tmpdir():
    with tempfile.TemporaryDirectory() as d:
        yield d


def write_script(directory, name, body):
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    return path

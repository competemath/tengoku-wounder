"""Sensitivity probes: does the statement-fidelity check notice a small change of meaning?

The pipeline asks a check, the *oracle*, whether a formalized statement still means the same as the original. A good check
says "different" to every near miss (mutate.py). If it says "equivalent" to one, it is insensitive to that class of change,
and a statement that drifted in that way would pass. One record is emitted per probe run; the failing operators are named.

The oracle is the pipeline's own check, supplied by the caller; nothing here calls out to anything. A toy oracle ships for
the tests and for trying the harness: whitespace-normalised string equality.
"""

from __future__ import annotations

import os
import tempfile
from typing import Callable

from vendor.juridicator_evidence import make_evidence, sha256_text

from .mutate import near_misses
from .records import check_command, truncate
from .runner import run_command, split_command

Oracle = Callable[[str, str], bool]
DEFAULT_LIMIT = 50


def toy_oracle(original: str, variant: str) -> bool:
    """Equivalent only if equal after collapsing whitespace. Strict, so it passes the probe; it proves nothing about a real check."""
    return " ".join(original.split()) == " ".join(variant.split())


class CommandOracle:
    """Wraps a command as an oracle: it is run as `cmd <dir>` where <dir> holds `original.txt` and `variant.txt`.
    Exit 0 means equivalent, exit 1 means different; anything else (a crash, a timeout) is an error, which the probe
    reports as inconclusive."""

    def __init__(self, cmd: str, timeout: float = 60.0):
        self.argv = split_command(cmd)
        self.timeout = timeout

    def __call__(self, original: str, variant: str) -> bool:
        with tempfile.TemporaryDirectory(prefix="oracle-") as directory:
            for name, text in (("original.txt", original), ("variant.txt", variant)):
                with open(os.path.join(directory, name), "w", encoding="utf-8") as fh:
                    fh.write(text)
            r = run_command(self.argv + [directory], timeout=self.timeout)
        if r.error or r.timed_out or r.returncode not in (0, 1) or "Traceback (most recent call last)" in r.stderr:
            raise RuntimeError("the oracle command did not give a verdict")
        return r.returncode == 0


def sensitivity_probe(statement: str, oracle: Oracle, case: dict, producer: dict, created: str, cmd: str,
                      limit: int = DEFAULT_LIMIT) -> dict:
    """One `mechanical.sensitivity` record. fail: the oracle called a near miss equivalent (operators named).
    pass: it told every near miss apart. inconclusive: the oracle raised, or there was nothing to test."""
    check_command(cmd)
    probes = near_misses(statement, limit)
    insensitive: list[str] = []
    error: str | None = None
    tested = 0
    for op, variant in probes:
        try:
            equivalent = oracle(statement, variant)
        except Exception as exc:  # an oracle that breaks is not a pass
            error = type(exc).__name__
            break
        tested += 1
        if equivalent:
            insensitive.append(op)
    sid = sha256_text(statement)[:12]
    if error is not None:
        outcome = "inconclusive"
        claim = f"Sensitivity of the fidelity check on statement {sid}: the check failed after {tested} of {len(probes)} probes, so nothing is shown"
    elif not probes:
        outcome = "inconclusive"
        claim = f"Sensitivity of the fidelity check on statement {sid}: no near miss could be generated, so nothing was tested"
    elif insensitive:
        outcome = "fail"
        names = ", ".join(insensitive[:5]) + (f" and {len(insensitive) - 5} more" if len(insensitive) > 5 else "")
        claim = f"The fidelity check called {len(insensitive)} of {len(probes)} near misses of statement {sid} equivalent: insensitive to {names}"
    else:
        outcome = "pass"
        claim = f"The fidelity check told all {len(probes)} near misses of statement {sid} apart from the original"
    return make_evidence(
        case=case, producer=producer, kind="mechanical.sensitivity", claim=truncate(claim, 300), outcome=outcome,
        verifiability="mechanical", created=created, subject={"declaration": f"statement:{sid}"},
        reproduce={"command": cmd},
        details={"statement": truncate(statement, 400), "probes": len(probes), "tested": tested,
                 "insensitive_operators": insensitive[:40], "oracle_error": error,
                 "operators_tried": [op for op, _ in probes][:60]})

"""Small helpers every producer module shares: who the wounder is, how a case is referenced, how a manifest is built.

Everything goes through the vendored contract (vendor/juridicator_evidence.py). `created` is always passed in, never read
from a clock here, so a run can be repeated byte for byte.
"""

from __future__ import annotations

import re
from typing import Any

from vendor.juridicator_evidence import HEX64, MAX_COMMAND, SHA40, make_evidence, sha256_text

PRODUCER = {"role": "wounder", "name": "tengoku-wounder", "identity": "tengoku-wounder"}
SAFE_ID = re.compile(r"^[a-z0-9_]{1,60}$")


class BadInput(ValueError):
    """Input the wounder refuses to work with. The CLI turns it into exit code 2."""


def case_ref(repo: str, head_sha: str, cls: str) -> dict:
    if not isinstance(repo, str) or not repo.strip():
        raise BadInput("repo is missing")
    if not isinstance(head_sha, str) or not SHA40.match(head_sha):
        raise BadInput("head must be a 40-hex commit")
    if not isinstance(cls, str) or not cls.strip():
        raise BadInput("class is missing")
    return {"repo": repo, "head_sha": head_sha, "class": cls}


def check_command(command: str) -> str:
    """A reproduce command must exist and fit the contract; fail loudly here rather than emit an invalid record."""
    if not isinstance(command, str) or not command.strip():
        raise BadInput("a reproduce command is required")
    if len(command) > MAX_COMMAND:
        raise BadInput(f"the reproduce command is longer than {MAX_COMMAND} characters; shorten the paths or use files")
    return command


def manifest_declared(*, case: dict, producer: dict, created: str, checks: list[str], extra: dict[str, Any] | None = None,
                      claim: str | None = None) -> dict:
    """`manifest.declared` (CONTRACT.md rule 3): the kinds this producer promises to report, written BEFORE running."""
    details: dict[str, Any] = {"checks": sorted(set(checks))}
    details.update(extra or {})
    return make_evidence(
        case=case, producer=producer, kind="manifest.declared",
        claim=claim or "The wounder declares the checks it will run and promises to report every one: " + ", ".join(sorted(set(checks))),
        outcome="pass", verifiability="attested", created=created, details=details)


def truncate(text: Any, limit: int) -> str:
    """Printable, single-line, bounded. Everything a gate or a proposer says goes through this before it is stored."""
    s = "".join(" " if (ord(c) < 32 or ord(c) == 127) else c for c in str(text))
    s = " ".join(s.split())
    return s if len(s) <= limit else s[: max(0, limit - 3)] + "..."


__all__ = ["BadInput", "HEX64", "PRODUCER", "SAFE_ID", "case_ref", "check_command", "manifest_declared", "sha256_text", "truncate"]

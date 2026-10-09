"""Evidence records: the single contract between tengoku-wounder, tengoku-praiser and tengoku-juridicator.

Standard library only, no imports from the rest of this package, so the other two repositories can vendor this
file byte for byte (see docs/CONTRACT.md). Do not edit a vendored copy: change it here, then refresh the copies.

An evidence record is one claim about one case, with the means to check it. The rule the whole design leans on:
a record that says it is `mechanical` or `reproducible` must carry the command that reproduces it, and a
record that cannot be re-run is only ever `attested` or `judgment`, which the judge treats as weak by construction.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

SCHEMA = "tengoku-evidence/1"
OUTCOMES = ("pass", "fail", "inconclusive", "not_run")
# How far a claim can be checked by someone who does not trust its author:
#   mechanical   a deterministic tool the judge could re-run itself (a proof checker, a linter)
#   reproducible re-runnable but expensive or seeded (a fuzz run, a rebuild comparison, a statistic over a public ledger)
#   attested     a statement by a party, not re-runnable (who wrote it, with which model): shown, never decisive
#   judgment     an opinion by an AI or a human reviewer
VERIFIABILITY = ("mechanical", "reproducible", "attested", "judgment")
ROLES = ("wounder", "praiser", "tooling", "author-system", "judge-ai", "human")
AI_ROLES = ("none", "proposer", "reviewer")
KIND_HEADS = VERIFIABILITY + ("manifest",)

SHA40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
KIND = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)+$")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
MAX_CLAIM = 300
MAX_DETAILS_BYTES = 8192
MAX_COMMAND = 1000


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def compute_id(body: dict) -> str:
    """The identity of a record is the hash of everything in it except the id itself."""
    return "sha256:" + sha256_text(canonical_json({k: v for k, v in body.items() if k != "id"}))


def make_evidence(
    *,
    case: dict,
    producer: dict,
    kind: str,
    claim: str,
    outcome: str,
    verifiability: str,
    created: str,
    subject: dict | None = None,
    reproduce: dict | None = None,
    ai: dict | None = None,
    details: dict | None = None,
) -> dict:
    """Build a record and stamp its id. `created` is passed in (never read from a clock here) so builds are repeatable."""
    body = {
        "schema": SCHEMA,
        "case": dict(case),
        "producer": dict(producer),
        "kind": kind,
        "claim": claim,
        "outcome": outcome,
        "verifiability": verifiability,
        "subject": subject,
        "reproduce": reproduce,
        "ai": ai if ai is not None else {"used": False, "role": "none"},
        "created": created,
        "details": details or {},
    }
    body["id"] = compute_id(body)
    return body


def _text(value: Any, name: str, errors: list[str], *, maximum: int = 200, required: bool = True) -> None:
    if value is None or value == "":
        if required:
            errors.append(f"{name} is missing")
        return
    if not isinstance(value, str):
        errors.append(f"{name} is not a string")
    elif len(value) > maximum:
        errors.append(f"{name} is longer than {maximum}")
    elif CONTROL.search(value):
        errors.append(f"{name} contains a control character")


def validate(ev: Any) -> list[str]:
    """Every reason this record is not acceptable as evidence. An empty list means it is well formed (not that it is true)."""
    if not isinstance(ev, dict):
        return ["not an object"]
    errors: list[str] = []
    if ev.get("schema") != SCHEMA:
        errors.append(f"schema is not {SCHEMA}")
    case = ev.get("case")
    if not isinstance(case, dict):
        errors.append("case is missing")
    else:
        _text(case.get("repo"), "case.repo", errors)
        if not isinstance(case.get("head_sha"), str) or not SHA40.match(case["head_sha"]):
            errors.append("case.head_sha is not a 40-hex commit")
        _text(case.get("class"), "case.class", errors, maximum=40)
    producer = ev.get("producer")
    if not isinstance(producer, dict):
        errors.append("producer is missing")
    else:
        if producer.get("role") not in ROLES:
            errors.append("producer.role is not a known role")
        _text(producer.get("name"), "producer.name", errors, maximum=80)
        _text(producer.get("identity"), "producer.identity", errors, maximum=120)
    kind = ev.get("kind")
    if not isinstance(kind, str) or not KIND.match(kind):
        errors.append("kind is not a dotted lowercase name")
    claim = ev.get("claim")
    _text(claim, "claim", errors, maximum=MAX_CLAIM)
    if ev.get("outcome") not in OUTCOMES:
        errors.append("outcome is not one of " + "/".join(OUTCOMES))
    verifiability = ev.get("verifiability")
    if verifiability not in VERIFIABILITY:
        errors.append("verifiability is not one of " + "/".join(VERIFIABILITY))
    if isinstance(kind, str) and KIND.match(kind):
        head = kind.split(".")[0]
        if head not in KIND_HEADS:
            errors.append("the first part of kind is not one of " + "/".join(KIND_HEADS))
        elif head == "manifest":
            if verifiability != "attested":
                errors.append("a manifest is a declaration, so it is attested")
        elif head != verifiability:
            errors.append("the first part of kind must equal verifiability")
    if verifiability in ("mechanical", "reproducible"):
        repro = ev.get("reproduce")
        if not isinstance(repro, dict) or not isinstance(repro.get("command"), str) or not repro["command"].strip():
            errors.append("a mechanical or reproducible record must say how to reproduce it")
        elif len(repro["command"]) > MAX_COMMAND:
            errors.append("reproduce.command is too long")
    subject = ev.get("subject")
    if subject is not None:
        if not isinstance(subject, dict):
            errors.append("subject is not an object")
        else:
            for key in ("module", "declaration"):
                if key in subject:
                    _text(subject[key], f"subject.{key}", errors, maximum=300)
    ai = ev.get("ai")
    if not isinstance(ai, dict) or not isinstance(ai.get("used"), bool) or ai.get("role") not in AI_ROLES:
        errors.append("ai must say whether AI was used and in which role")
    elif ai["used"]:
        if ai["role"] == "none":
            errors.append("ai.used is true but ai.role is none")
        _text(ai.get("model"), "ai.model", errors, maximum=120)
        if ai.get("prompt_sha256") is not None and not (isinstance(ai["prompt_sha256"], str) and HEX64.match(ai["prompt_sha256"])):
            errors.append("ai.prompt_sha256 is not a sha-256")
        if ai.get("family") is not None:
            _text(ai["family"], "ai.family", errors, maximum=60)
    elif ai.get("role") != "none":
        errors.append("ai.used is false but ai.role is not none")
    _text(ev.get("created"), "created", errors, maximum=40)
    details = ev.get("details")
    if not isinstance(details, dict):
        errors.append("details is not an object")
    elif len(canonical_json(details).encode("utf-8")) > MAX_DETAILS_BYTES:
        errors.append("details is larger than " + str(MAX_DETAILS_BYTES) + " bytes")
    if isinstance(ev.get("id"), str):
        if ev["id"] != compute_id(ev):
            errors.append("id does not match the content")
    else:
        errors.append("id is missing")
    return errors

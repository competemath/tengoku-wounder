"""Canaries: the planted-defect regression suite for our own acceptance gate.

A canary is a tiny fixture with a known verdict. Each one documents a defect *category* (an axiom slipped in, a sorry, a
statement that drifted from its source...) with the smallest example that shows it, or a known-good case, so that a gate
which has quietly stopped working, or started blocking everything, is noticed. The corpus is human-curated (CODEOWNERS);
nothing here reads a machine-proposed case (see ai_boundary.py and docs/ADVERSARIAL-SCOPE.md).

The gate under test is shown only the files of a case. It is never shown the expected verdict, the category or the id,
so it cannot answer from the label.

Outcome per canary: pass when the gate did what `expected` says; FAIL when a planted-bad case was accepted OR a known-good
case was rejected; inconclusive when the gate itself errored (a crash or a timeout is never a pass).
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from typing import Callable, Iterable, Protocol

from vendor.juridicator_evidence import canonical_json, make_evidence, sha256_text

from .records import BadInput, PRODUCER, SAFE_ID, check_command, manifest_declared, truncate
from .runner import RunResult, run_command, split_command

CATEGORIES = (
    "axiom_declared",
    "axiom_via_metaprogram",
    "sorry_present",
    "sorry_hidden_in_term",
    "native_decide_used",
    "unsafe_or_implemented_by",
    "vacuous_hypotheses",
    "statement_type_drift",
    "shadowed_name",
    "duplicate_statement",
    "comment_hidden_directive",
    "known_good",
)
# Categories whose correct verdict is "accept": over-blocking is a defect of the gate too.
ACCEPT_CATEGORIES = frozenset({"comment_hidden_directive", "known_good"})
CASE_KEYS = frozenset({"id", "category", "description", "expected", "why", "files"})
FILE_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,60}\.lean$")
MAX_FILES = 4
MAX_SOURCE = 2000
MAX_TEXT = 300
BAD_SOURCE_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")  # newline and tab are fine in source
DEFAULT_TIMEOUT = 60.0


class CorpusError(BadInput):
    pass


# ---------------------------------------------------------------- corpus

def validate_case(entry: object, *, source: str = "") -> dict:
    """Return the entry if it is a well-formed corpus case; raise CorpusError otherwise. Strict on purpose: unknown keys
    (for example the markers of a machine-proposed case) are refused, so a proposal cannot be copied in unreviewed."""
    where = f" ({source})" if source else ""
    if not isinstance(entry, dict):
        raise CorpusError("a corpus case is not an object" + where)
    extra = set(entry) - CASE_KEYS
    missing = CASE_KEYS - set(entry)
    if extra or missing:
        raise CorpusError(f"corpus case keys wrong{where}: extra {sorted(extra)}, missing {sorted(missing)}")
    if not isinstance(entry["id"], str) or not SAFE_ID.match(entry["id"]):
        raise CorpusError("id must be lowercase letters, digits and underscores" + where)
    if entry["category"] not in CATEGORIES:
        raise CorpusError(f"category {entry['category']!r} is not a known category" + where)
    if entry["expected"] not in ("reject", "accept"):
        raise CorpusError("expected must be reject or accept" + where)
    want = "accept" if entry["category"] in ACCEPT_CATEGORIES else "reject"
    if entry["expected"] != want:
        raise CorpusError(f"category {entry['category']} must expect {want}" + where)
    for key in ("description", "why"):
        value = entry[key]
        if not isinstance(value, str) or not value.strip() or len(value) > MAX_TEXT or not value.isprintable():
            raise CorpusError(f"{key} must be one printable line of at most {MAX_TEXT} characters" + where)
    files = entry["files"]
    if not isinstance(files, dict) or not files or len(files) > MAX_FILES:
        raise CorpusError(f"files must be 1 to {MAX_FILES} named sources" + where)
    for name, text in files.items():
        if not isinstance(name, str) or not FILE_NAME.match(name):
            raise CorpusError(f"file name {name!r} is not a plain .lean name" + where)
        if not isinstance(text, str) or not text.strip() or len(text) > MAX_SOURCE or BAD_SOURCE_CHARS.search(text):
            raise CorpusError(f"file {name} must be non-empty text of at most {MAX_SOURCE} characters" + where)
    return entry


def case_digest(entry: dict) -> str:
    return sha256_text(canonical_json(entry))


def corpus_digest(corpus: Iterable[dict]) -> str:
    return sha256_text(canonical_json(sorted(case_digest(c) for c in corpus)))


def load_corpus(*directories: str) -> list[dict]:
    """Every `*.json` directly inside the given directories (not recursive), validated, sorted by id. Several directories
    let a private held-out slice sit beside the public corpus. The quarantine directory `proposed` is refused by name."""
    if not directories:
        raise CorpusError("no corpus directory given")
    out: dict[str, dict] = {}
    for directory in directories:
        real = os.path.realpath(directory)
        if "proposed" in real.split(os.sep):
            raise CorpusError("the proposed/ quarantine is never a corpus: promote a case by hand first")
        if not os.path.isdir(real):
            raise CorpusError(f"{directory} is not a directory")
        for name in sorted(os.listdir(real)):
            if not name.endswith(".json"):
                continue
            path = os.path.join(real, name)
            try:
                with open(path, encoding="utf-8") as fh:
                    entry = json.load(fh)
            except (OSError, ValueError) as exc:
                raise CorpusError(f"{path}: unreadable ({type(exc).__name__})") from exc
            validate_case(entry, source=name)
            if name != entry["id"] + ".json":
                raise CorpusError(f"{name}: the file name must be the case id")
            if entry["id"] in out:
                raise CorpusError(f"duplicate case id {entry['id']}")
            out[entry["id"]] = entry
    if not out:
        raise CorpusError("the corpus is empty")
    return [out[k] for k in sorted(out)]


# ---------------------------------------------------------------- gates

@dataclass
class GateResult:
    accepted: bool
    reasons: list[str] = field(default_factory=list)
    error: bool = False  # the gate itself failed to give a verdict: inconclusive, never a pass


class Gate(Protocol):
    def __call__(self, case: dict) -> GateResult: ...


def gate_view(entry: dict) -> dict:
    """What the gate under test is allowed to see of a case: its files, nothing else."""
    return {"files": dict(entry["files"])}


class CommandGate:
    """Writes the case files into a fresh directory and runs `cmd <directory>`. Exit 0 accepts, nonzero rejects.
    A timeout, a start failure, a signal, exit 126/127, or a Python traceback on stderr is an error (inconclusive), not a
    rejection: a crashing gate must never look like a gate that caught a bad case."""

    def __init__(self, cmd: str, timeout: float = DEFAULT_TIMEOUT):
        self.cmd = cmd
        self.argv = split_command(cmd)
        self.timeout = timeout

    def __call__(self, case: dict) -> GateResult:
        with tempfile.TemporaryDirectory(prefix="case-") as directory:
            for name, text in case["files"].items():
                if not FILE_NAME.match(name):
                    return GateResult(False, ["refused to write an unsafe file name"], error=True)
                with open(os.path.join(directory, name), "w", encoding="utf-8") as fh:
                    fh.write(text)
            result = run_command(self.argv + [directory], timeout=self.timeout)
        return interpret(result, self.timeout)


def interpret(result: RunResult, timeout: float) -> GateResult:
    if result.error:
        return GateResult(False, [result.error], error=True)
    if result.timed_out:
        return GateResult(False, [f"gate timed out after {timeout:g}s"], error=True)
    code = result.returncode
    if code is None or code < 0 or code in (126, 127):
        return GateResult(False, [f"gate could not run to a verdict (exit {code})"], error=True)
    if "Traceback (most recent call last)" in result.stderr:
        return GateResult(False, ["gate crashed (traceback on stderr)"], error=True)
    if code == 0:
        return GateResult(True, [])
    lines = [truncate(line, 200) for line in (result.stdout + "\n" + result.stderr).splitlines() if line.strip()]
    return GateResult(False, lines[:5] or [f"gate exited {code}"])


def strip_comments(text: str) -> str:
    """Remove `--` line comments, nested `/- -/` block comments and string-literal contents (kept as empty strings)."""
    out: list[str] = []
    i, n, depth = 0, len(text), 0
    while i < n:
        two = text[i:i + 2]
        if depth:
            if two == "/-":
                depth += 1
                i += 2
            elif two == "-/":
                depth -= 1
                i += 2
            else:
                i += 1
        elif two == "/-":
            depth = 1
            i += 2
        elif two == "--":
            while i < n and text[i] != "\n":
                i += 1
        elif text[i] == '"':
            out.append('"')
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
            out.append('"')
            i += 1
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


class ReferenceTextGate:
    """A deliberately simple text-level gate, used as the test double: strip comments, reject a whole-word `axiom`,
    `sorry`, `native_decide`, `unsafe` or `implemented_by`. Its misses (tests/test_canary.py) are the point: they show what
    a purely textual gate cannot see and why the semantic checks exist."""

    FORBIDDEN = ("axiom", "sorry", "native_decide", "unsafe", "implemented_by")

    def __call__(self, case: dict) -> GateResult:
        reasons = []
        for name in sorted(case["files"]):
            code = strip_comments(case["files"][name])
            for word in self.FORBIDDEN:
                if re.search(rf"(?<![\w'.]){word}(?![\w'])", code):
                    reasons.append(f"{name}: forbidden word {word}")
        return GateResult(not reasons, reasons)


# ---------------------------------------------------------------- running

Reproduce = Callable[[str], str] | str


def reproduce_command(cmd_for_reproduce: Reproduce, case_id: str) -> str:
    """The exact wounder line that reruns just this case. A string may contain `{id}`; a callable gets the id."""
    command = cmd_for_reproduce(case_id) if callable(cmd_for_reproduce) else str(cmd_for_reproduce).replace("{id}", case_id)
    return check_command(command)


def manifest_for(case: dict, producer: dict, created: str, corpus: list[dict]) -> dict:
    """CONTRACT.md rule 3: declare what will be reported BEFORE running anything."""
    ids = [c["id"] for c in corpus]
    return manifest_declared(
        case=case, producer=producer, created=created, checks=["mechanical.canary"],
        claim=f"The wounder declares {len(ids)} planted-defect canaries and promises to report every one",
        extra={"canary_count": len(ids), "case_ids": ids[:100], "corpus_sha256": corpus_digest(corpus),
               # juridicator rule R9 (CONTRACT.md rule 8): every one of these subjects must be reported, not just the kind
               "expected": [{"kind": "mechanical.canary", "subject": {"declaration": i}} for i in ids[:60]]})


def judge(entry: dict, result: GateResult) -> tuple[str, str]:
    """(outcome, claim). The two ways to fail are the two ways a gate can be wrong."""
    cid, cat = entry["id"], entry["category"]
    if result.error:
        return "inconclusive", f"Canary {cid} ({cat}): the gate gave no verdict, so nothing is shown"
    if entry["expected"] == "reject":
        if result.accepted:
            return "fail", f"Canary {cid} ({cat}): the gate ACCEPTED a planted defect it should reject"
        return "pass", f"Canary {cid} ({cat}): the gate rejected the planted defect, as it should"
    if result.accepted:
        return "pass", f"Canary {cid} ({cat}): the gate accepted the known-good case, as it should"
    return "fail", f"Canary {cid} ({cat}): the gate REJECTED a known-good case (over-blocking)"


def run_canaries(corpus: list[dict], gate: Gate, case: dict, producer: dict, created: str, cmd_for_reproduce: Reproduce,
                 on_record: Callable[[dict], None] | None = None) -> list[dict]:
    """One `mechanical.canary` record per corpus case, in corpus order. A gate that raises is an error, not a pass."""
    records = []
    for entry in corpus:
        validate_case(entry)
        try:
            result = gate(gate_view(entry))
            if not isinstance(result, GateResult):
                raise TypeError("a gate must return GateResult")
        except Exception as exc:  # the gate under test is not trusted to behave
            result = GateResult(False, [f"gate raised {type(exc).__name__}"], error=True)
        outcome, claim = judge(entry, result)
        record = make_evidence(
            case=case, producer=producer, kind="mechanical.canary", claim=claim, outcome=outcome,
            verifiability="mechanical", created=created, subject={"declaration": entry["id"]},
            reproduce={"command": reproduce_command(cmd_for_reproduce, entry["id"])},
            details={"category": entry["category"], "expected": entry["expected"], "gate_accepted": result.accepted,
                     "gate_error": result.error, "gate_reasons": [truncate(r, 200) for r in result.reasons[:5]],
                     "case_sha256": case_digest(entry)})
        records.append(record)
        if on_record:
            on_record(record)
    return records


def canary_run(corpus: list[dict], gate: Gate, case: dict, producer: dict, created: str, cmd_for_reproduce: Reproduce,
               on_record: Callable[[dict], None] | None = None) -> list[dict]:
    """The manifest first, then the canaries."""
    manifest = manifest_for(case, producer, created, corpus)
    if on_record:
        on_record(manifest)
    return [manifest] + run_canaries(corpus, gate, case, producer, created, cmd_for_reproduce, on_record)


def missing_cases(corpus: list[dict], records: Iterable[dict]) -> list[str]:
    """Corpus ids with no reported canary. The juridicator's manifest check works per kind, not per case, so a run that
    reports only some canaries must be caught here, by the wounder, before it publishes (SECURITY.md, W5)."""
    done = {r["subject"]["declaration"] for r in records
            if r.get("kind") == "mechanical.canary" and isinstance(r.get("subject"), dict)
            and r["outcome"] in ("pass", "fail", "inconclusive")}
    return [c["id"] for c in corpus if c["id"] not in done]


def default_producer() -> dict:
    return dict(PRODUCER)

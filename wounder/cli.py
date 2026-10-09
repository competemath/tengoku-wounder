"""Command line. Exit 0 when the evidence was written, 2 for bad input. A failed canary is evidence, never a crash:
the exit code does not change because the gate under test was found wanting.

  python3 -m wounder run-canaries --corpus corpus --gate-cmd "<cmd>" --repo R --head SHA --class gate --out DIR
  python3 -m wounder sensitivity --statement-file F --oracle toy --repo R --head SHA --class gate --out DIR
  python3 -m wounder manifest --checks mechanical.canary --repo R --head SHA --class gate --out DIR
  python3 -m wounder lottery select --salt-file F --head SHA --tier 1
  python3 -m wounder promote proposed/<file>.json --reviewed-by NAME
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import shlex
import sys
from collections import Counter

from vendor.juridicator_evidence import KIND, validate

from . import ai_boundary, canary, sampler
from .records import BadInput, PRODUCER, case_ref, check_command, manifest_declared
from .sensitivity import CommandOracle, sensitivity_probe, toy_oracle

WOUNDER_KINDS = ("mechanical.canary", "mechanical.sensitivity", "reproducible.fuzz")
PY = "python3 -m wounder"


def _now() -> str:  # the one place a clock is read: the edge of the program, never the library
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Writer:
    """Writes numbered evidence files into an empty (or new) directory, in the order given: the manifest comes first."""

    def __init__(self, directory: str):
        os.makedirs(directory, exist_ok=True)
        if os.listdir(directory):
            raise BadInput(f"output directory {directory} is not empty")
        self.directory, self.n = directory, 0

    def complete(self, note: str) -> None:
        """A `COMPLETE` file (not evidence, no .json) says the run finished; a directory without it is not to be published."""
        with open(os.path.join(self.directory, "COMPLETE"), "x", encoding="utf-8") as fh:
            fh.write(note + "\n")

    def write(self, record: dict) -> str:
        problems = validate(record)
        if problems:  # never emit a record the judge would ignore
            raise BadInput("refusing to write an invalid record: " + "; ".join(problems[:3]))
        tail = record["kind"].replace(".", "-")
        if record.get("subject") and record["subject"].get("declaration"):
            tail += "-" + "".join(c if c.isalnum() or c in "_-" else "_" for c in record["subject"]["declaration"])[:60]
        name = f"{self.n:02d}-{tail}.json"
        with open(os.path.join(self.directory, name), "x", encoding="utf-8") as fh:
            json.dump(record, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.write("\n")
        self.n += 1
        return name


def _case_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--repo", required=True)
    p.add_argument("--head", required=True, help="the 40-hex commit the evidence is about")
    p.add_argument("--class", dest="cls", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--created", help="timestamp for the records (default: now)")


def _run_canaries(a: argparse.Namespace) -> int:
    case = case_ref(a.repo, a.head, a.cls)
    corpus = canary.load_corpus(*a.corpus)
    if a.only:
        corpus = [c for c in corpus if c["id"] in set(a.only)]
        if len(corpus) != len(set(a.only)):
            raise BadInput("--only names a case that is not in the corpus")
    if bool(a.gate_cmd) == bool(a.reference_gate):
        raise BadInput("give exactly one of --gate-cmd or --reference-gate")
    if a.gate_cmd:
        gate, gate_part = canary.CommandGate(a.gate_cmd, a.timeout), "--gate-cmd " + shlex.quote(a.gate_cmd)
    else:
        gate, gate_part = canary.ReferenceTextGate(), "--reference-gate"
    corpus_part = " ".join("--corpus " + shlex.quote(d) for d in a.corpus)
    template = (f"{PY} run-canaries {corpus_part} {gate_part} --repo {shlex.quote(a.repo)} --head {a.head} "
                f"--class {shlex.quote(a.cls)} --only {{id}} --out rerun")
    check_command(template.replace("{id}", "x" * 60))
    writer = Writer(a.out)
    created = a.created or _now()
    records = canary.run_canaries if a.no_manifest else canary.canary_run
    out = records(corpus, gate, case, dict(PRODUCER), created, template, writer.write)
    left = canary.missing_cases(corpus, out)
    if left:  # cannot happen in a normal run; if it does, the directory is left without COMPLETE
        raise BadInput("canaries not reported: " + ", ".join(left))
    writer.complete(f"records={writer.n} corpus_sha256={canary.corpus_digest(corpus)}")
    counts = Counter(r["outcome"] for r in out if r["kind"] == "mechanical.canary")
    print(json.dumps({"written": writer.n, "directory": a.out, **{k: counts.get(k, 0) for k in ("pass", "fail", "inconclusive")}}))
    return 0


def _sensitivity(a: argparse.Namespace) -> int:
    case = case_ref(a.repo, a.head, a.cls)
    if bool(a.statement) == bool(a.statement_file):
        raise BadInput("give exactly one of --statement or --statement-file")
    if a.statement_file:
        try:
            with open(a.statement_file, encoding="utf-8") as fh:
                statement = fh.read().strip()
        except OSError as exc:
            raise BadInput(f"statement file unreadable ({type(exc).__name__})") from exc
        source = "--statement-file " + shlex.quote(a.statement_file)
    else:
        statement, source = a.statement, "--statement " + shlex.quote(a.statement)
    if a.oracle_cmd and a.oracle:
        raise BadInput("give either --oracle toy or --oracle-cmd, not both")
    oracle = CommandOracle(a.oracle_cmd, a.timeout) if a.oracle_cmd else toy_oracle
    oracle_part = "--oracle-cmd " + shlex.quote(a.oracle_cmd) if a.oracle_cmd else "--oracle toy"
    cmd = check_command(f"{PY} sensitivity {source} {oracle_part} --repo {shlex.quote(a.repo)} --head {a.head} "
                        f"--class {shlex.quote(a.cls)} --limit {a.limit} --out rerun")
    writer = Writer(a.out)
    created = a.created or _now()
    producer = dict(PRODUCER)
    writer.write(manifest_declared(case=case, producer=producer, created=created, checks=["mechanical.sensitivity"]))
    record = sensitivity_probe(statement, oracle, case, producer, created, cmd, a.limit)
    writer.write(record)
    writer.complete(f"records={writer.n}")
    print(json.dumps({"written": writer.n, "directory": a.out, "outcome": record["outcome"]}))
    return 0


def _manifest(a: argparse.Namespace) -> int:
    case = case_ref(a.repo, a.head, a.cls)
    for kind in a.checks:
        if not KIND.match(kind) or kind not in WOUNDER_KINDS:
            raise BadInput(f"{kind!r} is not a kind the wounder may declare: {', '.join(WOUNDER_KINDS)}")
    writer = Writer(a.out)
    writer.write(manifest_declared(case=case, producer=dict(PRODUCER), created=a.created or _now(), checks=a.checks))
    writer.complete(f"records={writer.n} (manifest only)")
    print(json.dumps({"written": writer.n, "directory": a.out}))
    return 0


def _read_salt(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError as exc:
        raise BadInput(f"salt file unreadable ({type(exc).__name__})") from exc


def _lottery(a: argparse.Namespace) -> int:
    try:
        if a.action == "new-salt":
            salt = sampler.new_salt()
            fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(salt + "\n")
            print(json.dumps({"commitment": sampler.commit_salt(salt), "salt_file": a.out}))
            return 0
        salt = _read_salt(a.salt_file)
        if a.action == "commit":
            print(json.dumps({"commitment": sampler.commit_salt(salt)}))
            return 0
        if a.commitment and not sampler.verify_salt(a.commitment, salt):
            raise BadInput("the salt does not match the published commitment")
        rates = tuple(float(x) for x in a.rates.split(",")) if a.rates else sampler.DEFAULT_RATES
        tier = sampler.clamp_tier(a.tier)
        print(json.dumps({"head": a.head, "tier": tier, "rate": sampler.effective_rate(tier, rates),
                          "selected": sampler.select_for_audit(a.head, salt, tier, rates)}))
        return 0
    except (ValueError, TypeError, OSError) as exc:
        raise BadInput(str(exc)) from exc


def _promote(a: argparse.Namespace) -> int:
    dest = ai_boundary.promote(a.path, a.corpus, reviewed_by=a.reviewed_by, new_id=a.new_id)
    print(json.dumps({"promoted_to": dest, "reviewed_by": a.reviewed_by}))
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="wounder", description="Quality assurance for our own acceptance gate.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run-canaries", help="run the planted-defect canaries against a gate we control")
    r.add_argument("--corpus", action="append", required=True, help="a corpus directory; repeat to add a private held-out slice")
    r.add_argument("--gate-cmd", help="the gate under test; the case directory is appended as the last argument")
    r.add_argument("--reference-gate", action="store_true", help="use the built-in text-level reference gate")
    r.add_argument("--only", action="append", help="run just this case id (repeatable)")
    r.add_argument("--timeout", type=float, default=canary.DEFAULT_TIMEOUT)
    r.add_argument("--no-manifest", action="store_true", help="the manifest was already declared by `manifest`")
    _case_args(r)
    r.set_defaults(fn=_run_canaries)

    s = sub.add_parser("sensitivity", help="probe the statement-fidelity check with near-miss variants")
    s.add_argument("--statement")
    s.add_argument("--statement-file")
    s.add_argument("--oracle", choices=["toy"], help="the built-in whitespace-equality oracle (the default when no --oracle-cmd is given)")
    s.add_argument("--oracle-cmd", help="a command run as `cmd <dir>` with original.txt and variant.txt; exit 0 = equivalent, 1 = different")
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--timeout", type=float, default=60.0)
    _case_args(s)
    s.set_defaults(fn=_sensitivity)

    m = sub.add_parser("manifest", help="declare, before running, the checks that will be reported")
    m.add_argument("--checks", nargs="+", required=True)
    _case_args(m)
    m.set_defaults(fn=_manifest)

    lot = sub.add_parser("lottery", help="audit sampling with a committed salt")
    ls = lot.add_subparsers(dest="action", required=True)
    n = ls.add_parser("new-salt")
    n.add_argument("--out", required=True)
    c = ls.add_parser("commit")
    c.add_argument("--salt-file", required=True)
    sel = ls.add_parser("select")
    sel.add_argument("--salt-file", required=True)
    sel.add_argument("--head", required=True)
    sel.add_argument("--tier", type=int, required=True)
    sel.add_argument("--commitment")
    sel.add_argument("--rates", help="four comma-separated rates; default 0.05,0.20,0.50,1.00")
    lot.set_defaults(fn=_lottery)

    pr = sub.add_parser("promote", help="a person moves a reviewed proposed case into the corpus")
    pr.add_argument("path")
    pr.add_argument("--reviewed-by", required=True)
    pr.add_argument("--corpus", default="corpus")
    pr.add_argument("--new-id")
    pr.set_defaults(fn=_promote)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (BadInput, canary.CorpusError) as exc:
        print(f"wounder: bad input: {exc}", file=sys.stderr)
        return 2
    except (ValueError, FileExistsError) as exc:
        print(f"wounder: bad input: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

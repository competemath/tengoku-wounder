"""Mutation check for the wounder's own tests: break key lines one at a time and confirm the suite notices.

    python3 scripts/mutation_check.py            # run every mutation, exit 1 if any survives
    python3 scripts/mutation_check.py --list
    python3 scripts/mutation_check.py --only budget --jobs 4

Each mutation is applied to a throw-away copy of the repository (the working tree is never touched), the test suite is
run there, and the mutation is KILLED if the suite fails (or hangs) and SURVIVES if it still passes. A survivor means a
behaviour no test pins down: add a test, do not delete the mutation. A mutation whose target text cannot be found exactly
once is reported as stale, because the code moved and the check no longer checks what it says.

The sibling tengoku-juridicator checkout, if present, is used by the integration tests inside the copies too.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IGNORE = shutil.ignore_patterns(".git", "__pycache__", ".mutation-work", "out", "*.pyc")
TIMEOUT = 300

# (name, file, exact text to find once, replacement)
MUTATIONS: list[tuple[str, str, str, str]] = [
    # --- the canary verdicts: the three ways a harness can lie
    ("canary: a gate error counts as a pass", "wounder/canary.py",
     'return "inconclusive", f"Canary {cid} ({cat}): the gate gave no verdict',
     'return "pass", f"Canary {cid} ({cat}): the gate gave no verdict'),
    ("canary: a known-good case being rejected does not count", "wounder/canary.py",
     'return "fail", f"Canary {cid} ({cat}): the gate REJECTED a known-good case (over-blocking)"',
     'return "pass", f"Canary {cid} ({cat}): the gate REJECTED a known-good case (over-blocking)"'),
    ("canary: a planted defect being accepted does not count", "wounder/canary.py",
     'return "fail", f"Canary {cid} ({cat}): the gate ACCEPTED a planted defect it should reject"',
     'return "pass", f"Canary {cid} ({cat}): the gate ACCEPTED a planted defect it should reject"'),
    ("canary: a gate that raises is not flagged as an error", "wounder/canary.py",
     'result = GateResult(False, [f"gate raised {type(exc).__name__}"], error=True)',
     'result = GateResult(False, [f"gate raised {type(exc).__name__}"], error=False)'),
    ("canary: a crashing command gate looks like a rejection", "wounder/canary.py",
     'if "Traceback (most recent call last)" in result.stderr:', 'if False:'),
    ("canary: death by signal looks like a rejection", "wounder/canary.py",
     'if code is None or code < 0 or code in (126, 127):', 'if code is None or code in (126, 127):'),
    ("canary: exit 127 looks like a rejection", "wounder/canary.py",
     'if code is None or code < 0 or code in (126, 127):', 'if code is None or code < 0:'),
    ("canary: the gate is shown the expected verdict", "wounder/canary.py",
     'return {"files": dict(entry["files"])}', 'return {"files": dict(entry["files"]), "expected": entry["expected"]}'),
    ("canary: unknown keys are allowed in a corpus case", "wounder/canary.py", "    if extra or missing:", "    if missing:"),
    ("canary: the proposed/ quarantine can be loaded as a corpus", "wounder/canary.py",
     'if "proposed" in real.split(os.sep):', "if False:"),
    ("canary: a category may expect the wrong verdict", "wounder/canary.py",
     '    if entry["expected"] != want:', "    if False:"),
    ("canary: file names are not checked before writing", "wounder/canary.py",
     "                if not FILE_NAME.match(name):\n                    return GateResult",
     "                if False:\n                    return GateResult"),
    ("canary: reference gate matches inside longer identifiers (after)", "wounder/canary.py",
     "(?<![\\w'.]){word}(?![\\w'])", "(?<![\\w'.]){word}"),
    ("canary: reference gate matches inside longer identifiers (before)", "wounder/canary.py",
     "(?<![\\w'.]){word}(?![\\w'])", "{word}(?![\\w'])"),
    ("canary: nested block comments are not tracked", "wounder/canary.py",
     '            if two == "/-":\n                depth += 1', '            if two == "/-":\n                depth += 0'),
    ("canary: line comments are not stripped", "wounder/canary.py",
     '        elif two == "--":', '        elif False:'),
    ("canary: a not_run canary counts as reported", "wounder/canary.py",
     'and r["outcome"] in ("pass", "fail", "inconclusive")}', 'and True}'),
    ("canary: the manifest declares nothing", "wounder/canary.py", 'checks=["mechanical.canary"]', "checks=[]"),
    ("canary: the manifest is not emitted first", "wounder/canary.py", "        on_record(manifest)", "        pass"),
    ("canary: reproduce command does not name the case", "wounder/canary.py",
     '.replace("{id}", case_id)', '.replace("{id}", "x")'),
    ("canary: subjects are not distinct per case", "wounder/canary.py",
     'subject={"declaration": entry["id"]}', 'subject=None'),
    ("canary: details keep unbounded gate output", "wounder/canary.py",
     '"gate_reasons": [truncate(r, 200) for r in result.reasons[:5]]', '"gate_reasons": [r for r in result.reasons]'),
    # --- the sampler
    ("sampler: the tier is ignored", "wounder/sampler.py", "float(rates[t])", "float(rates[0])"),
    ("sampler: tier 3 is not always selected", "wounder/sampler.py", "if clamp_tier(tier) == 3:", "if False:"),
    ("sampler: no floor on the rate", "wounder/sampler.py", "max(RATE_FLOOR, float(rates[t]))", "max(0.0, float(rates[t]))"),
    ("sampler: the tier is not clamped", "wounder/sampler.py", "return max(0, min(3, tier))", "return tier"),
    ("sampler: the salt is not used", "wounder/sampler.py", "hmac.new(_salt_bytes(salt), head_sha.encode", "hmac.new(b'x' * 16, head_sha.encode"),
    ("sampler: any commitment verifies", "wounder/sampler.py",
     "hmac.compare_digest(expected, commitment.strip().lower())", "True"),
    ("sampler: selection is not below-rate but at-or-below-one", "wounder/sampler.py",
     "return draw(head_sha, salt) < effective_rate(tier, rates)", "return draw(head_sha, salt) <= 1.0"),
    # --- the budget
    ("budget: spend is persisted before the checks", "wounder/budget.py",
     '            rounds = state["rounds"].get(case_key, 0)\n',
     '            rounds = state["rounds"].get(case_key, 0)\n            state["spent"] += cost\n            self._save(state)\n            state["spent"] -= cost\n'),
    ("budget: the daily cap is exclusive", "wounder/budget.py",
     'if state["spent"] + cost > self.daily_cap:', 'if state["spent"] + cost >= self.daily_cap:'),
    ("budget: the round cap is off by one", "wounder/budget.py",
     "if rounds + 1 > self.per_case_rounds:", "if rounds > self.per_case_rounds:"),
    ("budget: the reservation is not persisted", "wounder/budget.py",
     "            self._save(state)  # persisted before the caller is allowed to act", "            pass"),
    ("budget: a new day keeps yesterday's spend", "wounder/budget.py",
     'return {"day": self.day, "spent": 0.0, "rounds": dict(rounds)}', 'return {"day": self.day, "spent": float(spent), "rounds": dict(rounds)}'),
    ("budget: a new day forgets each case's rounds", "wounder/budget.py",
     'return {"day": self.day, "spent": 0.0, "rounds": dict(rounds)}', 'return {"day": self.day, "spent": 0.0, "rounds": {}}'),
    ("budget: NaN costs are allowed", "wounder/budget.py", "not math.isfinite(value) or ", ""),
    ("budget: an unreadable state file resets to zero", "wounder/budget.py",
     "        except FileNotFoundError:", "        except (FileNotFoundError, ValueError):"),
    ("budget: a day going backwards is accepted", "wounder/budget.py", "        if self.day < day:", "        if False:"),
    ("budget: a refused attempt is still counted as a round", "wounder/budget.py",
     '            if rounds + 1 > self.per_case_rounds:\n',
     '            state["rounds"][case_key] = rounds + 1\n            self._save(state)\n            if rounds + 1 > self.per_case_rounds:\n'),
    # --- the AI boundary
    ("ai: the tools == () assertion is dropped", "wounder/ai_boundary.py", "    if tools != ():", "    if False:"),
    ("ai: the marker check is skipped (any JSON in the reply is read)", "wounder/ai_boundary.py",
     "obj = mk.extract(raw, marker)", 'obj = json.loads(raw[raw.find("{"):]) if "{" in raw else None'),
    ("ai: the first marker is trusted, whatever its value", "wounder/ai_boundary.py",
     "obj = mk.extract(raw, marker)", "obj = mk.extract(raw, mk.MARKER_RE.findall(raw)[0]) if mk.MARKER_RE.search(raw) else None"),
    ("ai: the budget is not reserved", "wounder/ai_boundary.py",
     "    budget.reserve(case_key, cost)  # raises BudgetExceeded before anything is asked", "    pass"),
    ("ai: variants are not deduplicated", "wounder/ai_boundary.py", "or _norm(item) in seen:", "or False:"),
    ("ai: marker-like text is allowed in a variant", "wounder/ai_boundary.py",
     "or mk.has_marker_like_text(item) or _norm", "or _norm"),
    ("ai: a variant may equal the original", "wounder/ai_boundary.py", "seen = {_norm(statement)}", "seen = set()"),
    ("ai: no cap on the number of variants", "wounder/ai_boundary.py", "        if len(out.variants) >= cap:", "        if False:"),
    ("ai: non-printable variants are allowed", "wounder/ai_boundary.py", "and item.isprintable())", "and True)"),
    ("ai: a huge reply is read", "wounder/ai_boundary.py", "    if len(raw) > MAX_REPLY:", "    if False:"),
    ("ai: the statement is not checked for marker-shaped text", "wounder/ai_boundary.py",
     "    if mk.has_marker_like_text(statement):", "    if False:"),
    ("ai: candidates may be written outside a proposed/ directory", "wounder/ai_boundary.py",
     'if os.path.basename(os.path.realpath(proposed_dir)) != "proposed":\n        raise BadInput("candidates', 'if False:\n        raise BadInput("candidates'),
    ("ai: a candidate with the wrong verdict for its category is kept", "wounder/ai_boundary.py",
     "            validate_case(body)\n        except CorpusError:", "            pass\n        except CorpusError:"),
    ("ai: promote needs no reviewer", "wounder/ai_boundary.py",
     "    if not isinstance(reviewed_by, str) or not reviewed_by.strip():", "    if False:"),
    ("ai: promote takes a file that is not marked proposed", "wounder/ai_boundary.py",
     'or entry.get("status") != "proposed":', "or False:"),
    ("ai: promote takes files from anywhere", "wounder/ai_boundary.py",
     '    if os.path.basename(os.path.dirname(real)) != "proposed":', "    if False:"),
    ("ai: promote overwrites an existing case", "wounder/ai_boundary.py",
     'with open(dest, "x", encoding="utf-8") as fh:', 'with open(dest, "w", encoding="utf-8") as fh:'),
    # --- the generators and the probe
    ("mutate: nat_to_int writes the wrong type", "wounder/mutate.py", '.replace("ℕ", "ℤ")', '.replace("ℕ", "ℝ")'),
    ("mutate: near misses are not deduplicated", "wounder/mutate.py", "or _norm(variant) in seen:", "or False:"),
    ("mutate: the limit is ignored", "wounder/mutate.py", "        if len(out) >= limit:", "        if False:"),
    ("mutate: a variant equal to the statement is allowed", "wounder/mutate.py",
     "seen = {statement, _norm(statement)}", "seen = set()"),
    ("mutate: counting is not left to right", "wounder/mutate.py",
     "    for index, m in enumerate(pattern.finditer(text)):", "    for index, m in enumerate(reversed(list(pattern.finditer(text)))):"),
    ("mutate: arrows count as comparisons", "wounder/mutate.py", "(?<![-=<|$*>;])", "(?<![=<|$*>;])"),
    ("sensitivity: an equivalent verdict is not recorded", "wounder/sensitivity.py",
     "        if equivalent:\n            insensitive.append(op)", "        if False:\n            insensitive.append(op)"),
    ("sensitivity: an oracle error is forgotten", "wounder/sensitivity.py", "error = type(exc).__name__", "error = None"),
    ("sensitivity: nothing to test passes", "wounder/sensitivity.py", "    elif not probes:", "    elif False:"),
    ("sensitivity: the reproduce command is not required", "wounder/sensitivity.py", "    check_command(cmd)\n", ""),
    # --- running commands and the command line
    ("runner: the environment is not scrubbed", "wounder/runner.py",
     "env = {k: os.environ[k] for k in KEEP_ENV if k in os.environ}", "env = dict(os.environ)"),
    ("runner: output is unbounded", "wounder/runner.py", "return fh.read(MAX_OUTPUT)", "return fh.read()"),
    ("runner: a bare name found in the directory is made absolute", "wounder/runner.py",
     "        if os.sep in token and os.path.exists(token):", "        if os.path.exists(token):"),
    ("cli: a failed canary makes the exit code nonzero", "wounder/cli.py",
     'for k in ("pass", "fail", "inconclusive")}}))\n    return 0',
     'for k in ("pass", "fail", "inconclusive")}}))\n    return 1 if counts.get("fail") else 0'),
    ("cli: an existing output directory is overwritten into", "wounder/cli.py", "        if os.listdir(directory):", "        if False:"),
    ("cli: an invalid record is written anyway", "wounder/cli.py", "        if problems:  # never emit", "        if False:  # never emit"),
    ("cli: the COMPLETE marker is written before the run is complete", "wounder/cli.py",
     '    left = canary.missing_cases(corpus, out)\n    if left:', '    left = []\n    if left:'),
    ("cli: the manifest may declare kinds the wounder does not own", "wounder/cli.py",
     "if not KIND.match(kind) or kind not in WOUNDER_KINDS:", "if not KIND.match(kind):"),
    ("cli: a commitment mismatch is ignored", "wounder/cli.py",
     "if a.commitment and not sampler.verify_salt(a.commitment, salt):", "if False:"),
    ("vendor: the pin check always passes", "scripts/sync_contract.py", "    return [] if actual == expected else", "    return [] if True else"),
]


def copy_tree(dest: str) -> None:
    shutil.copytree(ROOT, dest, ignore=IGNORE, dirs_exist_ok=True)


def run_suite(directory: str) -> tuple[int | None, str]:
    env = dict(os.environ)
    sibling = os.environ.get("TENGOKU_JURIDICATOR_PATH") or os.path.join(os.path.dirname(ROOT), "tengoku-juridicator")
    env["TENGOKU_JURIDICATOR_PATH"] = sibling
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        p = subprocess.run([sys.executable, "-W", "error::ResourceWarning", "-m", "unittest", "discover", "-s", "tests", "-f"],
                           cwd=directory, env=env, capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return None, "the suite hung"
    return p.returncode, (p.stdout + p.stderr)[-600:]


def try_mutation(item: tuple[str, str, str, str]) -> tuple[str, str, str]:
    """(status, name, note) with status killed / SURVIVED / stale."""
    name, rel, old, new = item
    with tempfile.TemporaryDirectory(prefix="wounder-mut-") as d:
        copy_tree(d)
        path = os.path.join(d, rel)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        if text.count(old) != 1:
            return "stale", name, f"target found {text.count(old)} times in {rel}"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text.replace(old, new))
        code, tail = run_suite(d)
        if code is None:
            return "killed", name, "hung"
        if code != 0:
            return "killed", name, ""
        return "SURVIVED", name, ""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--only", help="run only mutations whose name contains this text")
    ap.add_argument("--jobs", type=int, default=4)
    args = ap.parse_args(argv)
    chosen = [m for m in MUTATIONS if not args.only or args.only in m[0]]
    if args.list:
        for name, rel, _, _ in chosen:
            print(f"{rel}: {name}")
        return 0
    with tempfile.TemporaryDirectory(prefix="wounder-base-") as d:
        copy_tree(d)
        code, tail = run_suite(d)
    if code != 0:
        print("the unmodified suite does not pass; fix that first\n" + tail)
        return 2
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        for status, name, note in pool.map(try_mutation, chosen):
            print(f"{status:9} {name}" + (f"  ({note})" if note else ""), flush=True)
            results.append(status)
    killed, survived, stale = results.count("killed"), results.count("SURVIVED"), results.count("stale")
    print(f"\n{len(results)} mutations: {killed} killed, {survived} survived, {stale} stale")
    return 0 if not survived and not stale else 1


if __name__ == "__main__":
    sys.exit(main())

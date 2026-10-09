import contextlib
import io
import json
import os
import shlex
import stat
import subprocess
import sys
import unittest

from vendor.juridicator_evidence import validate
from wounder import cli
from tests.helpers import HEAD, PY, ROOT, in_root, tmpdir, write_script

BASE = ["--repo", "competemath/tengoku-sandbox", "--head", HEAD, "--class", "gate", "--created", "2026-10-09T00:00:00Z"]


def canary_result():
    from wounder.canary import GateResult
    return GateResult(True, [])


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with in_root(), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as exc:   # argparse errors
            code = exc.code
    return code, out.getvalue(), err.getvalue()


def read_dir(directory):
    names = sorted(n for n in os.listdir(directory) if n.endswith(".json"))
    out = []
    for n in names:
        with open(os.path.join(directory, n), encoding="utf-8") as fh:
            out.append(json.load(fh))
    return names, out


class RunCanaries(unittest.TestCase):
    def test_writes_manifest_first_then_one_record_per_case_and_exits_zero(self):
        with tmpdir() as d:
            out = os.path.join(d, "o")
            code, stdout, _ = run("run-canaries", "--corpus", "corpus", "--reference-gate", *BASE, "--out", out)
            self.assertEqual(code, 0)
            self.assertIn("COMPLETE", os.listdir(out))
            names, records = read_dir(out)
            self.assertTrue(names[0].startswith("00-manifest"))
            self.assertEqual(records[0]["kind"], "manifest.declared")
            self.assertEqual({r["kind"] for r in records[1:]}, {"mechanical.canary"})
            self.assertEqual(len(records), 16)
            for r in records:
                self.assertEqual(validate(r), [])
            summary = json.loads(stdout)
            self.assertEqual(summary["written"], 16)
            self.assertEqual(summary["pass"] + summary["fail"] + summary["inconclusive"], 15)

    def test_a_failing_canary_never_makes_the_exit_code_nonzero(self):
        with tmpdir() as d:
            code, stdout, _ = run("run-canaries", "--corpus", "corpus", "--reference-gate", *BASE, "--out", os.path.join(d, "o"))
            self.assertEqual(code, 0)
            self.assertGreater(json.loads(stdout)["fail"], 0, "the reference gate misses several planted defects")

    def test_a_gate_that_errors_still_exits_zero_with_inconclusive_evidence(self):
        with tmpdir() as d:
            crash = write_script(d, "crash.py", "raise SystemExit(127)\n")
            code, stdout, _ = run("run-canaries", "--corpus", "corpus", "--gate-cmd", f"{PY} {shlex.quote(crash)}", *BASE, "--out", os.path.join(d, "o"))
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(stdout)["inconclusive"], 15)

    def test_bad_input_exits_two(self):
        with tmpdir() as d:
            o = os.path.join(d, "o")
            good = ["--corpus", "corpus", "--reference-gate", *BASE, "--out", o]
            cases = {
                "bad head": ["run-canaries", "--corpus", "corpus", "--reference-gate", "--repo", "r", "--head", "xyz", "--class", "gate", "--out", o],
                "no gate": ["run-canaries", "--corpus", "corpus", *BASE, "--out", o],
                "two gates": ["run-canaries", *good, "--gate-cmd", "true"],
                "missing corpus": ["run-canaries", "--corpus", os.path.join(d, "nope"), "--reference-gate", *BASE, "--out", o],
                "proposed as corpus": ["run-canaries", "--corpus", "proposed", "--reference-gate", *BASE, "--out", o],
                "unknown only": ["run-canaries", *good, "--only", "no_such_case"],
                "overlong command": ["run-canaries", "--corpus", "corpus", "--gate-cmd", "x " * 600, *BASE, "--out", o],
            }
            for label, argv in cases.items():
                code, _, err = run(*argv)
                self.assertEqual(code, 2, label)
                self.assertIn("bad input", err, label)
            self.assertFalse(os.path.exists(o) and os.listdir(o), "nothing is written for bad input")

    def test_a_run_that_dies_midway_leaves_no_complete_marker(self):
        from unittest import mock
        with tmpdir() as d:
            out = os.path.join(d, "o")
            with mock.patch("wounder.canary.ReferenceTextGate.__call__", side_effect=[canary_result(), KeyboardInterrupt()]):
                with self.assertRaises(KeyboardInterrupt):
                    run("run-canaries", "--corpus", "corpus", "--reference-gate", *BASE, "--out", out)
            self.assertNotIn("COMPLETE", os.listdir(out))
            self.assertTrue(os.listdir(out), "the manifest was written before anything ran")

    def test_a_non_empty_output_directory_is_refused(self):
        with tmpdir() as d:
            open(os.path.join(d, "stale.json"), "w").close()
            code, _, err = run("run-canaries", "--corpus", "corpus", "--reference-gate", *BASE, "--out", d)
            self.assertEqual(code, 2)
            self.assertIn("not empty", err)

    def test_only_runs_just_that_case_and_the_reproduce_command_round_trips(self):
        with tmpdir() as d:
            code, _, _ = run("run-canaries", "--corpus", "corpus", "--reference-gate", *BASE, "--out", os.path.join(d, "full"))
            self.assertEqual(code, 0)
            _, records = read_dir(os.path.join(d, "full"))
            target = [r for r in records if r["subject"] and r["subject"]["declaration"] == "axiom_via_metaprogram"][0]
            argv = shlex.split(target["reproduce"]["command"])
            self.assertEqual(argv[:3], ["python3", "-m", "wounder"])
            argv = argv[3:]
            argv[argv.index("rerun")] = os.path.join(d, "again")
            code, _, _ = run(*argv, "--created", "2026-10-09T00:00:00Z")
            self.assertEqual(code, 0)
            _, again = read_dir(os.path.join(d, "again"))
            canaries = [r for r in again if r["kind"] == "mechanical.canary"]
            self.assertEqual(len(canaries), 1)
            self.assertEqual(canaries[0], target, "the reproduced record is the same record")

    def test_reproduce_command_with_a_gate_command_keeps_it_quoted(self):
        with tmpdir() as d:
            ok = write_script(d, "ok.py", "raise SystemExit(0)\n")
            gate = f"{PY} {shlex.quote(ok)}"
            code, _, _ = run("run-canaries", "--corpus", "corpus", "--gate-cmd", gate, *BASE, "--only", "sorry_present", "--out", os.path.join(d, "o"))
            self.assertEqual(code, 0)
            _, records = read_dir(os.path.join(d, "o"))
            argv = shlex.split(records[1]["reproduce"]["command"])
            self.assertEqual(argv[argv.index("--gate-cmd") + 1], gate)

    def test_no_manifest_flag_omits_it(self):
        with tmpdir() as d:
            code, _, _ = run("run-canaries", "--corpus", "corpus", "--reference-gate", "--no-manifest", "--only", "sorry_present", *BASE, "--out", os.path.join(d, "o"))
            self.assertEqual(code, 0)
            _, records = read_dir(os.path.join(d, "o"))
            self.assertEqual([r["kind"] for r in records], ["mechanical.canary"])


class WriterGuards(unittest.TestCase):
    def test_the_writer_refuses_a_record_the_judge_would_ignore(self):
        from wounder.records import BadInput
        with tmpdir() as d:
            w = cli.Writer(os.path.join(d, "o"))
            with self.assertRaises(BadInput):
                w.write({"schema": "nope"})
            self.assertEqual(os.listdir(os.path.join(d, "o")), [])

    def test_a_run_that_did_not_report_every_canary_gets_no_complete_marker_and_exits_two(self):
        from unittest import mock
        with tmpdir() as d:
            out = os.path.join(d, "o")
            with mock.patch("wounder.canary.canary_run", return_value=[]):
                code, _, err = run("run-canaries", "--corpus", "corpus", "--reference-gate", *BASE, "--out", out)
            self.assertEqual(code, 2)
            self.assertIn("not reported", err)
            self.assertNotIn("COMPLETE", os.listdir(out))


class Sensitivity(unittest.TestCase):
    STATEMENT = "theorem foo (a b : ℕ) (h : a ≤ b) : a < b + 1"

    def test_toy_oracle_run_writes_manifest_and_a_passing_probe(self):
        with tmpdir() as d:
            code, stdout, _ = run("sensitivity", "--statement", self.STATEMENT, "--oracle", "toy", *BASE, "--out", os.path.join(d, "o"))
            self.assertEqual(code, 0)
            names, records = read_dir(os.path.join(d, "o"))
            self.assertEqual([r["kind"] for r in records], ["manifest.declared", "mechanical.sensitivity"])
            self.assertEqual(records[0]["details"]["checks"], ["mechanical.sensitivity"])
            self.assertEqual(records[1]["outcome"], "pass")
            self.assertEqual(json.loads(stdout)["outcome"], "pass")
            for r in records:
                self.assertEqual(validate(r), [])

    def test_a_lax_oracle_command_is_caught_and_still_exits_zero(self):
        with tmpdir() as d:
            yes = write_script(d, "yes.py", "raise SystemExit(0)\n")
            code, stdout, _ = run("sensitivity", "--statement", self.STATEMENT, "--oracle-cmd", f"{PY} {shlex.quote(yes)}", *BASE,
                                  "--out", os.path.join(d, "o"))
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(stdout)["outcome"], "fail")

    def test_statement_from_a_file_and_bad_input(self):
        with tmpdir() as d:
            f = os.path.join(d, "s.txt")
            with open(f, "w", encoding="utf-8") as fh:
                fh.write(self.STATEMENT + "\n")
            code, _, _ = run("sensitivity", "--statement-file", f, *BASE, "--out", os.path.join(d, "o"))
            self.assertEqual(code, 0)
            for argv in (["sensitivity", *BASE, "--out", os.path.join(d, "p")],
                         ["sensitivity", "--statement", "x", "--statement-file", f, *BASE, "--out", os.path.join(d, "q")],
                         ["sensitivity", "--statement-file", os.path.join(d, "missing"), *BASE, "--out", os.path.join(d, "r")],
                         ["sensitivity", "--statement", "x" * 1200, *BASE, "--out", os.path.join(d, "s")],
                         ["sensitivity", "--statement", "x", "--oracle-cmd", "true", "--oracle", "toy", *BASE, "--out", os.path.join(d, "t")]):
                code, _, _ = run(*argv)
                self.assertEqual(code, 2, argv)


class ManifestCommand(unittest.TestCase):
    def test_declares_only_kinds_the_wounder_may_report(self):
        with tmpdir() as d:
            code, _, _ = run("manifest", "--checks", "mechanical.canary", "mechanical.sensitivity", *BASE, "--out", os.path.join(d, "o"))
            self.assertEqual(code, 0)
            _, records = read_dir(os.path.join(d, "o"))
            self.assertEqual(records[0]["details"]["checks"], ["mechanical.canary", "mechanical.sensitivity"])
            self.assertEqual(validate(records[0]), [])
            for bad in ("mechanical.kernel_check", "attested.x", "canary"):
                code, _, _ = run("manifest", "--checks", bad, *BASE, "--out", os.path.join(d, "bad"))
                self.assertEqual(code, 2, bad)


class Lottery(unittest.TestCase):
    def test_new_salt_commit_select_round_trip(self):
        with tmpdir() as d:
            salt = os.path.join(d, "salt")
            code, out, _ = run("lottery", "new-salt", "--out", salt)
            self.assertEqual(code, 0)
            commitment = json.loads(out)["commitment"]
            self.assertEqual(stat.S_IMODE(os.stat(salt).st_mode), 0o600)
            code, out, _ = run("lottery", "commit", "--salt-file", salt)
            self.assertEqual(json.loads(out)["commitment"], commitment)
            code, out, _ = run("lottery", "select", "--salt-file", salt, "--head", HEAD, "--tier", "3", "--commitment", commitment)
            self.assertEqual(code, 0)
            self.assertTrue(json.loads(out)["selected"])
            code, out, _ = run("lottery", "select", "--salt-file", salt, "--head", HEAD, "--tier", "1")
            self.assertIn(json.loads(out)["selected"], (True, False))
            self.assertEqual(json.loads(out)["rate"], 0.2)

    def test_wrong_commitment_bad_head_and_existing_salt_file_exit_two(self):
        with tmpdir() as d:
            salt = os.path.join(d, "salt")
            run("lottery", "new-salt", "--out", salt)
            self.assertEqual(run("lottery", "select", "--salt-file", salt, "--head", HEAD, "--tier", "1", "--commitment", "0" * 64)[0], 2)
            self.assertEqual(run("lottery", "select", "--salt-file", salt, "--head", "nothex", "--tier", "1")[0], 2)
            self.assertEqual(run("lottery", "new-salt", "--out", salt)[0], 2, "never overwrite a salt")
            self.assertEqual(run("lottery", "commit", "--salt-file", os.path.join(d, "missing"))[0], 2)

    def test_custom_rates_respect_the_floor(self):
        with tmpdir() as d:
            salt = os.path.join(d, "salt")
            run("lottery", "new-salt", "--out", salt)
            code, out, _ = run("lottery", "select", "--salt-file", salt, "--head", HEAD, "--tier", "0", "--rates", "0,0.1,0.2,1")
            self.assertEqual(json.loads(out)["rate"], 0.02)


class PromoteCommand(unittest.TestCase):
    def test_promote_needs_a_reviewer_and_a_proposed_file(self):
        with tmpdir() as d:
            f = os.path.join(d, "x.json")
            open(f, "w").close()
            self.assertEqual(run("promote", f, "--reviewed-by", "someone", "--corpus", os.path.join(d, "c"))[0], 2)
            self.assertEqual(run("promote", f)[0], 2)


class AsAProgram(unittest.TestCase):
    def test_python_dash_m_wounder_runs_and_exit_codes_hold(self):
        with tmpdir() as d:
            r = subprocess.run([sys.executable, "-m", "wounder", "run-canaries", "--corpus", "corpus", "--reference-gate", *BASE,
                                "--out", os.path.join(d, "o")], cwd=ROOT, capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 0, r.stderr)
            r = subprocess.run([sys.executable, "-m", "wounder", "run-canaries", "--corpus", "nope", "--reference-gate", *BASE,
                                "--out", os.path.join(d, "o2")], cwd=ROOT, capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 2)


class NoNetworkInTheCode(unittest.TestCase):
    def test_no_module_imports_a_network_library_or_calls_an_ai_service(self):
        import re
        banned = re.compile(r"^\s*(?:import|from)\s+(socket|urllib|http|requests|ssl|ftplib|smtplib|anthropic|openai)\b", re.M)
        root = os.path.join(ROOT, "wounder")
        for name in sorted(os.listdir(root)):
            if name.endswith(".py"):
                with open(os.path.join(root, name), encoding="utf-8") as fh:
                    self.assertIsNone(banned.search(fh.read()), name)


if __name__ == "__main__":
    unittest.main()

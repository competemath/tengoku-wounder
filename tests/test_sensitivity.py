import os
import shlex
import unittest

from vendor.juridicator_evidence import validate
from wounder import sensitivity as sens
from wounder.mutate import near_misses
from tests.helpers import CASE, NOW, PY, producer, tmpdir, write_script

S = "theorem foo (a b : ℕ) (h : a ≤ b) : ∀ x : ℕ, x + a ≤ x + b"
CMD = "python3 -m wounder sensitivity --statement-file s.txt --oracle toy --repo r --head " + "a" * 40 + " --class gate --out rerun"


def probe(oracle, statement=S, **kw):
    return sens.sensitivity_probe(statement, oracle, CASE, producer(), NOW, CMD, **kw)


class Oracles(unittest.TestCase):
    def test_toy_oracle_is_whitespace_normalised_equality(self):
        self.assertTrue(sens.toy_oracle("a  ≤ b", "a ≤  b"))
        self.assertFalse(sens.toy_oracle("a ≤ b", "a < b"))


class Probe(unittest.TestCase):
    def test_a_strict_oracle_passes(self):
        r = probe(sens.toy_oracle)
        self.assertEqual(r["outcome"], "pass")
        self.assertEqual(validate(r), [])
        self.assertEqual(r["kind"], "mechanical.sensitivity")
        self.assertEqual(r["verifiability"], "mechanical")
        self.assertEqual(r["reproduce"]["command"], CMD)
        self.assertEqual(r["details"]["probes"], len(near_misses(S, 50)))
        self.assertEqual(r["details"]["insensitive_operators"], [])

    def test_a_lax_oracle_that_ignores_nat_versus_int_is_caught_and_named(self):
        lax = lambda o, v: o.replace("ℤ", "ℕ") == v.replace("ℤ", "ℕ")
        r = probe(lax)
        self.assertEqual(r["outcome"], "fail")
        self.assertEqual(r["details"]["insensitive_operators"], ["nat_to_int"])
        self.assertIn("nat_to_int", r["claim"])
        self.assertEqual(validate(r), [])

    def test_a_lax_oracle_that_ignores_strictness_is_caught(self):
        lax = lambda o, v: o.replace("<", "≤") == v.replace("<", "≤")
        r = probe(lax)
        self.assertEqual(r["outcome"], "fail")
        self.assertTrue(any(op.startswith("le_lt_toggle") for op in r["details"]["insensitive_operators"]))

    def test_an_oracle_that_says_equivalent_to_everything_fails_every_probe(self):
        r = probe(lambda o, v: True)
        self.assertEqual(r["outcome"], "fail")
        self.assertEqual(len(r["details"]["insensitive_operators"]), r["details"]["probes"])
        self.assertLessEqual(len(r["claim"]), 300)

    def test_a_lax_oracle_that_ignores_dropped_hypotheses_is_caught(self):
        lax = lambda o, v: o.split(":", 1)[1].split(")")[-1] == v.split(":", 1)[1].split(")")[-1] if "(h" not in v else False
        r = probe(lax)
        self.assertEqual(r["outcome"], "fail")
        self.assertIn("drop_hypothesis:0", r["details"]["insensitive_operators"])

    def test_an_oracle_that_raises_is_inconclusive_not_a_pass(self):
        def broken(o, v):
            raise RuntimeError("the fidelity check crashed")

        r = probe(broken)
        self.assertEqual(r["outcome"], "inconclusive")
        self.assertEqual(r["details"]["oracle_error"], "RuntimeError")
        self.assertEqual(validate(r), [])

    def test_a_failure_part_way_is_inconclusive_even_if_earlier_probes_were_fine(self):
        calls = []

        def flaky(o, v):
            calls.append(v)
            if len(calls) > 2:
                raise TimeoutError
            return False

        r = probe(flaky)
        self.assertEqual(r["outcome"], "inconclusive")
        self.assertEqual(r["details"]["tested"], 2)

    def test_nothing_to_test_is_inconclusive_not_a_vacuous_pass(self):
        r = probe(sens.toy_oracle, statement="theorem t : p")
        self.assertEqual(r["outcome"], "inconclusive")

    def test_limit_caps_the_probes(self):
        r = probe(sens.toy_oracle, limit=3)
        self.assertEqual(r["details"]["probes"], 3)

    def test_a_missing_reproduce_command_is_refused(self):
        with self.assertRaises(ValueError):
            sens.sensitivity_probe(S, sens.toy_oracle, CASE, producer(), NOW, "")

    def test_subject_identifies_the_statement(self):
        a, b = probe(sens.toy_oracle), probe(sens.toy_oracle, statement=S + " ∧ 1 < 2")
        self.assertNotEqual(a["subject"], b["subject"])
        self.assertEqual(a, probe(sens.toy_oracle))

    def test_no_ai_is_recorded_because_none_is_used(self):
        self.assertEqual(probe(sens.toy_oracle)["ai"], {"used": False, "role": "none"})


class CommandOracleTests(unittest.TestCase):
    def test_exit_codes_map_to_equivalent_different_and_error(self):
        with tmpdir() as d:
            script = write_script(d, "o.py",
                                  "import os, sys\nd = sys.argv[-1]\n"
                                  "a = open(os.path.join(d, 'original.txt'), encoding='utf-8').read()\n"
                                  "b = open(os.path.join(d, 'variant.txt'), encoding='utf-8').read()\n"
                                  "if 'BOOM' in b:\n    raise SystemExit(5)\n"
                                  "sys.exit(0 if a == b else 1)\n")
            o = sens.CommandOracle(f"{PY} {shlex.quote(script)}")
            self.assertTrue(o("x ≤ y", "x ≤ y"))
            self.assertFalse(o("x ≤ y", "x < y"))
            with self.assertRaises(RuntimeError):
                o("x", "BOOM")
            crash = write_script(d, "c.py", "raise ValueError\n")
            with self.assertRaises(RuntimeError):
                sens.CommandOracle(f"{PY} {shlex.quote(crash)}")("a", "b")

    def test_probe_with_a_command_oracle_that_always_says_equivalent_fails(self):
        with tmpdir() as d:
            script = write_script(d, "yes.py", "import sys\nsys.exit(0)\n")
            r = probe(sens.CommandOracle(f"{PY} {shlex.quote(script)}"))
            self.assertEqual(r["outcome"], "fail")

    def test_probe_with_a_command_oracle_that_cannot_run_is_inconclusive(self):
        r = probe(sens.CommandOracle("definitely-not-a-real-command-xyz"))
        self.assertEqual(r["outcome"], "inconclusive")


if __name__ == "__main__":
    unittest.main()

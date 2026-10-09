"""Against the real juridicator, when a checkout is next door (`../tengoku-juridicator`, or $TENGOKU_JURIDICATOR_PATH).
In CI there is no sibling, so these skip cleanly. Nothing here changes the juridicator; it is only imported and run."""

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

from tests.helpers import (CASE, HEAD, NOW, ROOT, AcceptAll, ErroringGate, PerfectGate, RejectAll, corpus, producer, repro, run_all)
from wounder import canary, cli
from wounder.canary import ReferenceTextGate
from wounder.sensitivity import sensitivity_probe, toy_oracle

SIBLING = os.environ.get("TENGOKU_JURIDICATOR_PATH") or os.path.join(os.path.dirname(ROOT), "tengoku-juridicator")
HAVE = os.path.isfile(os.path.join(SIBLING, "juridicator", "statute.py"))

if HAVE:
    sys.path.append(SIBLING)  # last, so our own `tests` package is never shadowed by the sibling's
    from juridicator.evidence import validate as j_validate
    from juridicator.statute import decide


def judge(records, case=CASE):
    return decide(case, records, None, standing={"gate_health": "ACCEPT"})


@unittest.skipUnless(HAVE, "no sibling tengoku-juridicator checkout")
class AgainstTheJuridicator(unittest.TestCase):
    def full_run(self, gate):
        return canary.canary_run(corpus(), gate, CASE, producer(), NOW, repro)

    def test_every_record_the_wounder_emits_validates_under_the_juridicators_validate(self):
        everything = self.full_run(ReferenceTextGate())
        everything.append(sensitivity_probe("theorem foo (a b : ℕ) (h : a ≤ b) : a < b + 1", toy_oracle, CASE, producer(), NOW, "python3 -m wounder sensitivity"))
        everything.append(sensitivity_probe("theorem foo (a b : ℕ) : a < b", lambda o, v: True, CASE, producer(), NOW, "python3 -m wounder sensitivity"))
        everything.append(sensitivity_probe("theorem t : p", toy_oracle, CASE, producer(), NOW, "python3 -m wounder sensitivity"))
        for r in everything:
            self.assertEqual(j_validate(r), [], r["claim"])

    def test_records_written_by_the_cli_validate_too(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "o")
            old = os.getcwd()
            os.chdir(ROOT)
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(cli.main(["run-canaries", "--corpus", "corpus", "--reference-gate", "--repo", CASE["repo"],
                                               "--head", HEAD, "--class", "gate", "--out", out]), 0)
            finally:
                os.chdir(old)
            for name in sorted(n for n in os.listdir(out) if n.endswith('.json')):
                with open(os.path.join(out, name), encoding="utf-8") as fh:
                    self.assertEqual(j_validate(json.load(fh)), [], name)

    def test_a_healthy_canary_run_for_a_gate_class_case_is_accepted(self):
        v = judge(self.full_run(PerfectGate(corpus())))
        self.assertEqual(v["decision"], "ACCEPT", v["reasons"])
        self.assertEqual(v["ignored_evidence"], [])

    def test_one_planted_defect_accepted_by_the_gate_rejects_the_gate_case(self):
        perfect = PerfectGate(corpus())
        bad = {tuple(sorted(e["files"].items())) for e in corpus() if e["id"] == "axiom_via_metaprogram"}

        def gate(case):
            r = perfect(case)
            return canary.GateResult(True, []) if tuple(sorted(case["files"].items())) in bad else r

        records = self.full_run(gate)
        failing = [r for r in records if r["outcome"] == "fail"]
        self.assertEqual([r["subject"]["declaration"] for r in failing], ["axiom_via_metaprogram"])
        v = judge(records)
        self.assertEqual(v["decision"], "REJECT", v["reasons"])
        self.assertTrue(any(r["rule"] == "R1" for r in v["reasons"]))

    def test_the_text_only_reference_gate_is_rejected_because_of_what_it_cannot_see(self):
        v = judge(self.full_run(ReferenceTextGate()))
        self.assertEqual(v["decision"], "REJECT")

    def test_rejecting_a_known_good_case_also_rejects_the_gate_case(self):
        perfect = PerfectGate(corpus())
        good = {tuple(sorted(e["files"].items())) for e in corpus() if e["id"] == "good_add_comm"}
        records = self.full_run(lambda case: canary.GateResult(False, ["no"]) if tuple(sorted(case["files"].items())) in good else perfect(case))
        self.assertEqual(judge(records)["decision"], "REJECT")

    def test_an_accept_everything_gate_and_a_reject_everything_gate_are_both_rejected(self):
        self.assertEqual(judge(self.full_run(AcceptAll()))["decision"], "REJECT")
        self.assertEqual(judge(self.full_run(RejectAll()))["decision"], "REJECT")

    def test_a_manifest_with_no_canaries_reported_holds_the_case_through_R9(self):
        manifest = canary.manifest_for(CASE, producer(), NOW, corpus())
        v = judge([manifest])
        self.assertEqual(v["decision"], "HOLD", v["reasons"])
        self.assertTrue(any(r["rule"] == "R9" for r in v["reasons"]))
        self.assertIn("mechanical.canary", v["missing"])

    def test_a_declared_run_that_reported_only_not_run_also_holds(self):
        manifest = canary.manifest_for(CASE, producer(), NOW, corpus())
        records = [r for r in run_all(PerfectGate(corpus()))]
        for r in records:
            r["outcome"] = "not_run"
        from vendor.juridicator_evidence import compute_id
        for r in records:
            r["id"] = compute_id(r)
        v = judge([manifest] + records)
        self.assertEqual(v["decision"], "HOLD")
        self.assertTrue(any(r["rule"] == "R9" for r in v["reasons"]))

    def test_a_gate_that_errors_on_everything_holds_the_case(self):
        v = judge(self.full_run(ErroringGate()))
        self.assertEqual(v["decision"], "HOLD", v["reasons"])
        self.assertTrue(any(r["rule"] == "R3" for r in v["reasons"]))

    def test_a_gate_that_errors_on_one_case_holds_the_case(self):
        """Statute R12 (version 2): a crash on one planted defect is not a pass, and the case is held for a re-run."""
        perfect = PerfectGate(corpus())
        target = tuple(sorted(next(e for e in corpus() if e["id"] == "sorry_present")["files"].items()))
        records = self.full_run(lambda case: canary.GateResult(False, ["boom"], error=True) if tuple(sorted(case["files"].items())) == target else perfect(case))
        v = judge(records)
        self.assertEqual(v["decision"], "HOLD", v["reasons"])
        self.assertTrue(any(r["rule"] == "R12" for r in v["reasons"]))
        self.assertEqual(sum(r["outcome"] == "inconclusive" for r in records), 1)
        self.assertEqual(canary.missing_cases(corpus(), [r for r in records if r["outcome"] != "inconclusive"]), ["sorry_present"])

    def test_an_incomplete_report_holds_the_case_by_subject(self):
        """Statute R9 (version 2): the manifest lists every canary subject, so 14 of 15 is a hold, not an accept."""
        records = self.full_run(PerfectGate(corpus()))
        partial = records[:-1]
        self.assertEqual(canary.missing_cases(corpus(), partial), [corpus()[-1]["id"]])
        v = judge(partial)
        self.assertEqual(v["decision"], "HOLD", v["reasons"])
        self.assertTrue(any(r["rule"] == "R9" for r in v["reasons"]))

    def test_a_manifest_alone_never_yields_acceptance_whoever_signs_it(self):
        """Producer identity is only a string today (juridicator SECURITY.md R5); a declaration with no results is a hold."""
        other = canary.manifest_for(CASE, dict(producer(), identity="someone-else"), NOW, corpus())
        self.assertEqual(judge([other])["decision"], "HOLD")

    def test_vendored_contract_equals_the_siblings_current_contract(self):
        with open(os.path.join(ROOT, "vendor", "juridicator_evidence.py"), "rb") as a, \
                open(os.path.join(SIBLING, "juridicator", "evidence.py"), "rb") as b:
            self.assertEqual(a.read(), b.read(), "the contract moved: run scripts/sync_contract.py --from ../tengoku-juridicator")

    def test_the_juridicator_command_line_agrees(self):
        with tempfile.TemporaryDirectory() as d:
            case_path = os.path.join(d, "case.json")
            with open(case_path, "w") as fh:
                json.dump(CASE, fh)
            for gate, code in ((PerfectGate(corpus()), 0), (AcceptAll(), 12)):
                evdir = os.path.join(d, f"ev{code}")
                os.makedirs(evdir)
                for i, r in enumerate(self.full_run(gate)):
                    with open(os.path.join(evdir, f"{i:02d}.json"), "w", encoding="utf-8") as fh:
                        json.dump(r, fh)
                p = subprocess.run([sys.executable, "-m", "juridicator", "judge", "--case", case_path, "--evidence", evdir],
                                   cwd=SIBLING, capture_output=True, text=True, timeout=60)
                self.assertEqual(p.returncode, code, p.stdout[-400:] + p.stderr)


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(HAVE, "no sibling tengoku-juridicator checkout")
class LotteryOnTheRealLedger(unittest.TestCase):
    def test_commit_verdicts_reveal_through_the_real_hash_chained_ledger(self):
        from juridicator.ledger import Ledger
        from wounder import sampler
        from wounder.lottery_book import audit_plan

        salt = "q" * 32
        with tempfile.TemporaryDirectory() as d:
            ledger = Ledger(os.path.join(d, "ledger.jsonl"))
            ledger.append("lottery_commit", {"commitment": sampler.commit_salt(salt)})
            heads = [format(i, "040x") for i in range(1, 60)]
            for h in heads:
                ledger.append("verdict", {"decision": "ACCEPT", "tier": 1, "case": {"head_sha": h}})
            ledger.append("lottery_reveal", {"salt": salt})
            self.assertEqual(ledger.verify(), (True, None))
            plan = audit_plan(ledger.entries())
        self.assertEqual(plan["problems"], [])
        self.assertEqual(plan["must_audit"], sorted(h for h in heads if sampler.select_for_audit(h, salt, 1)))

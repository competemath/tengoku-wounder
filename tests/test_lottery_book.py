import json
import os
import tempfile
import unittest
import contextlib
import io

from wounder import sampler
from wounder.cli import main
from wounder.lottery_book import audit_plan

SALT = "z" * 32
H = [format(i, "040x") for i in range(1, 400)]


def verdict(seq, head, tier=1, decision="ACCEPT"):
    return {"seq": seq, "kind": "verdict", "body": {"decision": decision, "tier": tier, "case": {"head_sha": head}}}


def commit(seq, salt=SALT):
    return {"seq": seq, "kind": "lottery_commit", "body": {"commitment": sampler.commit_salt(salt)}}


def reveal(seq, salt=SALT):
    return {"seq": seq, "kind": "lottery_reveal", "body": {"salt": salt}}


class Plan(unittest.TestCase):
    def test_selection_matches_the_sampler_once_revealed(self):
        entries = [commit(0)] + [verdict(i + 1, h) for i, h in enumerate(H[:300])] + [reveal(301)]
        plan = audit_plan(entries)
        self.assertEqual(plan["problems"], [])
        want = sorted(h for h in H[:300] if sampler.select_for_audit(h, SALT, 1))
        self.assertEqual(plan["must_audit"], want)
        self.assertTrue(0 < len(want) < 300)

    def test_nothing_is_decided_before_the_reveal(self):
        plan = audit_plan([commit(0), verdict(1, H[0])])
        self.assertEqual(plan["must_audit"], [])
        self.assertEqual(plan["pending"], [H[0]])

    def test_a_verdict_outside_any_batch_must_be_audited(self):
        plan = audit_plan([verdict(0, H[0], tier=0)])
        self.assertEqual(plan["must_audit"], [H[0]])
        self.assertEqual(len(plan["unbatched"]), 1)

    def test_a_verdict_after_the_reveal_is_unbatched_not_sampled_with_the_known_salt(self):
        plan = audit_plan([commit(0), verdict(1, H[0]), reveal(2), verdict(3, H[1], tier=0)])
        self.assertIn(H[1], plan["must_audit"])
        self.assertEqual([c["head_sha"] for c in plan["unbatched"]], [H[1]])

    def test_a_wrong_salt_is_a_problem_and_its_cases_are_audited(self):
        plan = audit_plan([commit(0), verdict(1, H[0], tier=0), reveal(2, salt="y" * 32)])
        self.assertTrue(plan["problems"])
        self.assertEqual(plan["must_audit"], [H[0]])

    def test_two_commits_in_a_row_and_a_stray_reveal_are_reported(self):
        self.assertTrue(audit_plan([commit(0), commit(1)])["problems"])
        self.assertTrue(audit_plan([reveal(0)])["problems"])

    def test_tier_three_is_always_selected_and_other_decisions_are_not_sampled(self):
        plan = audit_plan([commit(0), verdict(1, H[0], tier=3), verdict(2, H[1], decision="HOLD"), reveal(3)])
        self.assertEqual(plan["must_audit"], [H[0]])

    def test_malformed_commit_and_verdict_are_ignored_with_a_note(self):
        plan = audit_plan([{"seq": 0, "kind": "lottery_commit", "body": {"commitment": "short"}},
                           {"seq": 1, "kind": "verdict", "body": {"decision": "ACCEPT", "case": {}}}])
        self.assertEqual(len(plan["problems"]), 2)

    def test_cli_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            led = os.path.join(d, "l.jsonl")
            with open(led, "w", encoding="utf-8") as fh:
                for e in [commit(0), verdict(1, H[0], tier=3), reveal(2)]:
                    fh.write(json.dumps(e) + "\n")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = main(["lottery", "plan", "--ledger", led])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out.getvalue())["must_audit"], [H[0]])
            salt = os.path.join(d, "s")
            with open(salt, "w", encoding="utf-8") as fh:
                fh.write(SALT)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                main(["lottery", "commit-body", "--salt-file", salt])
            self.assertEqual(json.loads(out.getvalue()), {"commitment": sampler.commit_salt(SALT)})


if __name__ == "__main__":
    unittest.main()

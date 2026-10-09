import json
import os
import unittest
from unittest import mock

from tests.helpers import tmpdir
from wounder.budget import Budget, BudgetError, BudgetExceeded

DAY = "2026-10-09"


class BudgetTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tmpdir()
        self.dir = self._tmp.__enter__()
        self.path = os.path.join(self.dir, "budget.json")

    def tearDown(self):
        self._tmp.__exit__(None, None, None)

    def make(self, cap=10, rounds=3, day=DAY):
        return Budget(self.path, cap, rounds, day=day)

    def state(self):
        with open(self.path, encoding="utf-8") as fh:
            return json.load(fh)

    def test_reserve_records_spend_and_rounds(self):
        b = self.make()
        self.assertEqual(b.reserve("case-1", 2.5), {"spent_today": 2.5, "case_rounds": 1})
        b.reserve("case-1", 1)
        self.assertEqual(b.spent_today(), 3.5)
        self.assertEqual(b.rounds("case-1"), 2)
        self.assertEqual(b.rounds("other"), 0)

    def test_exceeding_the_daily_cap_raises_before_spending_anything(self):
        b = self.make(cap=5)
        b.reserve("a", 4)
        before = self.state()
        with self.assertRaises(BudgetExceeded):
            b.reserve("b", 1.5)
        self.assertEqual(self.state(), before, "a refused reservation must change nothing on disk")
        self.assertEqual(b.spent_today(), 4)
        self.assertEqual(b.rounds("b"), 0, "a refused attempt is not a round")

    def test_spending_exactly_the_cap_is_allowed_and_the_next_cent_is_not(self):
        b = self.make(cap=5)
        b.reserve("a", 5)
        with self.assertRaises(BudgetExceeded):
            b.reserve("a2", 0.01)

    def test_per_case_round_cap(self):
        b = self.make(cap=100, rounds=2)
        b.reserve("c", 1)
        b.reserve("c", 1)
        before = self.state()
        with self.assertRaises(BudgetExceeded):
            b.reserve("c", 1)
        self.assertEqual(self.state(), before)
        b.reserve("another-case", 1)  # other cases are unaffected

    def test_free_attempts_still_count_as_rounds(self):
        b = self.make(rounds=2)
        b.reserve("c", 0)
        b.reserve("c", 0)
        with self.assertRaises(BudgetExceeded):
            b.reserve("c", 0)
        self.assertEqual(b.spent_today(), 0)

    def test_zero_caps_allow_nothing(self):
        with self.assertRaises(BudgetExceeded):
            self.make(cap=0).reserve("c", 1)
        with self.assertRaises(BudgetExceeded):
            Budget(os.path.join(self.dir, "b2.json"), 10, 0, day=DAY).reserve("c", 1)

    def test_the_reservation_is_on_disk_before_reserve_returns(self):
        b = self.make()
        real_save = b._save
        seen = []

        def spying_save(state):
            real_save(state)
            seen.append(self.state())

        b._save = spying_save
        b.reserve("c", 3)
        self.assertEqual(seen[0]["spent"], 3)
        self.assertEqual(seen[0]["rounds"], {"c": 1})

    def test_if_persisting_fails_the_action_is_not_allowed(self):
        b = self.make()
        b.reserve("c", 1)
        with mock.patch.object(Budget, "_save", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                b.reserve("c", 1)
        self.assertEqual(self.state()["spent"], 1, "the failed reservation left no trace")
        self.assertEqual(b.rounds("c"), 1)

    def test_a_crash_after_reserving_is_remembered_by_a_new_process(self):
        self.make().reserve("c", 4)          # the "process" ends here, before the action happened
        again = self.make()
        self.assertEqual(again.spent_today(), 4)
        self.assertEqual(again.rounds("c"), 1)

    def test_two_handles_on_one_file_do_not_double_spend(self):
        a, b = self.make(cap=5), self.make(cap=5)
        a.reserve("x", 3)
        with self.assertRaises(BudgetExceeded):
            b.reserve("y", 3)

    def test_a_new_day_resets_spend(self):
        self.make(cap=5, rounds=9).reserve("c", 5)
        tomorrow = self.make(cap=5, rounds=9, day="2026-10-10")
        self.assertEqual(tomorrow.spent_today(), 0)
        tomorrow.reserve("c", 5)           # a whole new allowance
        self.assertEqual(self.state()["day"], "2026-10-10")

    def test_a_new_day_does_not_give_a_case_more_rounds(self):
        yesterday = self.make(cap=100, rounds=2)
        yesterday.reserve("c", 1)
        yesterday.reserve("c", 1)
        tomorrow = self.make(cap=100, rounds=2, day="2026-10-10")
        self.assertEqual(tomorrow.rounds("c"), 2)
        with self.assertRaises(BudgetExceeded):
            tomorrow.reserve("c", 1)

    def test_same_day_does_not_reset(self):
        self.make(cap=5).reserve("c", 5)
        with self.assertRaises(BudgetExceeded):
            self.make(cap=5).reserve("d", 1)

    def test_a_day_that_goes_backwards_is_refused(self):
        self.make(day="2026-10-10").reserve("c", 1)
        with self.assertRaises(BudgetError):
            self.make(day="2026-10-09")

    def test_the_day_must_be_supplied_as_a_date_string(self):
        for bad in ("", "today", "2026-1-1", None, 20261009):
            with self.assertRaises(BudgetError):
                Budget(self.path, 10, 3, day=bad)

    def test_the_clock_is_never_read(self):
        import time
        import datetime
        with mock.patch.object(time, "time", side_effect=AssertionError("clock read")), \
                mock.patch.object(datetime, "datetime", side_effect=AssertionError("clock read")):
            b = self.make()
            b.reserve("c", 1)

    def test_an_unreadable_or_malformed_state_fails_closed(self):
        for text in ("not json", "[]", json.dumps({"day": DAY, "spent": -1, "rounds": {}}),
                     json.dumps({"day": DAY, "spent": 0, "rounds": {"c": -2}}), json.dumps({"day": DAY})):
            with open(self.path, "w", encoding="utf-8") as fh:
                fh.write(text)
            with self.assertRaises(BudgetError, msg=text):
                self.make()

    def test_bad_costs_and_keys_are_refused(self):
        b = self.make()
        for cost in (-1, float("nan"), float("inf"), True, "1", None):
            with self.assertRaises(BudgetError, msg=repr(cost)):
                b.reserve("c", cost)
        for key in ("", None, 5, "x" * 500):
            with self.assertRaises(BudgetError):
                b.reserve(key, 1)
        self.assertEqual(b.spent_today(), 0)

    def test_bad_construction_is_refused(self):
        for cap, rounds in ((-1, 3), (float("nan"), 3), (True, 3), (10, -1), (10, 1.5), (10, True)):
            with self.assertRaises(BudgetError):
                Budget(self.path, cap, rounds, day=DAY)

    def test_state_file_is_never_left_half_written(self):
        b = self.make()
        b.reserve("c", 1)
        self.assertEqual([n for n in os.listdir(self.dir) if n.startswith(".budget-")], [])


if __name__ == "__main__":
    unittest.main()

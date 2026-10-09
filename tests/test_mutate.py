import unittest

from wounder import mutate as m

S = "theorem foo (a b : ℕ) (h : a ≤ b) (h2 : 0 < a) : ∀ x : ℕ, x + a ≤ x + b → ∃ y, y < 10"


class Operators(unittest.TestCase):
    def test_nat_to_int_and_real_replace_every_nat(self):
        self.assertEqual(m.nat_to_int("(a b : ℕ) : ∀ x : ℕ, x = x"), "(a b : ℤ) : ∀ x : ℤ, x = x")
        self.assertEqual(m.nat_to_int("(a : Nat) : a = a"), "(a : Int) : a = a")
        self.assertEqual(m.nat_to_real("(a : ℕ)"), "(a : ℝ)")
        self.assertEqual(m.nat_to_real("(a : Nat)"), "(a : Real)")
        self.assertIsNone(m.nat_to_int("(a : ℤ)"))
        self.assertIsNone(m.nat_to_int("Nat.succ n = n + 1"), "a qualified name is not the type")

    def test_le_lt_toggle_picks_the_kth_comparison_left_to_right(self):
        self.assertEqual(m.le_lt_toggle("a ≤ b ∧ c < d", 0), "a < b ∧ c < d")
        self.assertEqual(m.le_lt_toggle("a ≤ b ∧ c < d", 1), "a ≤ b ∧ c ≤ d")
        self.assertEqual(m.le_lt_toggle("a <= b", 0), "a < b")
        self.assertEqual(m.le_lt_toggle("a ≥ b ∧ c > d", 0), "a > b ∧ c > d")
        self.assertIsNone(m.le_lt_toggle("a ≤ b", 1))
        self.assertIsNone(m.le_lt_toggle("a = b", 0))

    def test_arrows_and_tactic_syntax_are_not_comparisons(self):
        for text in ("p -> q", "fun x => x", "h <- foo", "a <;> b", "x |>.f", "f <$> g", "f <*> g", "p → q"):
            self.assertIsNone(m.le_lt_toggle(text, 0), text)
            self.assertIsNone(m.flip_direction(text), text)

    def test_drop_hypothesis_removes_the_ith_named_binder_only(self):
        self.assertEqual(m.drop_hypothesis(S, 0), "theorem foo (a b : ℕ) (h2 : 0 < a) : ∀ x : ℕ, x + a ≤ x + b → ∃ y, y < 10")
        self.assertEqual(m.drop_hypothesis(S, 1), "theorem foo (a b : ℕ) (h : a ≤ b) : ∀ x : ℕ, x + a ≤ x + b → ∃ y, y < 10")
        self.assertIsNone(m.drop_hypothesis(S, 2))
        self.assertIsNone(m.drop_hypothesis("theorem t (a : ℕ) : a = a", 0))
        self.assertEqual(m.drop_hypothesis("theorem t (h : p) : q", 0), "theorem t : q")

    def test_binders_in_the_conclusion_are_not_hypotheses(self):
        self.assertIsNone(m.drop_hypothesis("theorem t : ∀ (h : p), q", 0))
        self.assertEqual(m.hypothesis_spans("theorem t (h1 h2 : p) (x : (h : q)) : r").__len__(), 1)

    def test_swap_quantifier(self):
        self.assertEqual(m.swap_quantifier("∀ x, ∃ y, p", 0), "∃ x, ∃ y, p")
        self.assertEqual(m.swap_quantifier("∀ x, ∃ y, p", 1), "∀ x, ∀ y, p")
        self.assertIsNone(m.swap_quantifier("∃! x, p", 0), "unique existence is not swapped")
        self.assertIsNone(m.swap_quantifier("p", 0))

    def test_shift_literal(self):
        self.assertEqual(m.shift_literal("x < 10 ∧ y < 3", 0, 1), "x < 11 ∧ y < 3")
        self.assertEqual(m.shift_literal("x < 10 ∧ y < 3", 1, -1), "x < 10 ∧ y < 2")
        self.assertIsNone(m.shift_literal("x < 0", 0, -1), "never below zero")
        self.assertIsNone(m.shift_literal("h1 < x_2", 0, 1), "digits inside names are not literals")
        self.assertIsNone(m.shift_literal("x < 1.5", 0, 1), "decimals are left alone")
        self.assertIsNone(m.shift_literal("x < 10", 3, 1))

    def test_flip_direction_prefers_the_conclusion(self):
        self.assertEqual(m.flip_direction("theorem t (h : a ≤ b) : c < d"), "theorem t (h : a ≤ b) : c > d")
        self.assertEqual(m.flip_direction("theorem t (h : a ≤ b) : c = d"), "theorem t (h : a ≥ b) : c = d")
        self.assertEqual(m.flip_direction("a ≤ b"), "a ≥ b")
        self.assertIsNone(m.flip_direction("a = b"))

    def test_hypothesis_scan_ignores_assignments(self):
        self.assertEqual(m.head_colon("theorem t (h : p) : q := by simp"), len("theorem t (h : p) "))
        self.assertEqual(m.head_colon("def f := 1"), -1)


class OperatorIds(unittest.TestCase):
    def test_ids_are_stable_and_apply_by_id(self):
        ids = m.operator_ids(S)
        self.assertEqual(ids[:2], ["nat_to_int", "nat_to_real"])
        self.assertEqual(ids[-1], "flip_direction")
        self.assertIn("le_lt_toggle:3", ids)
        self.assertIn("shift_literal:1:-1", ids)
        for op in ids:
            self.assertEqual(m.apply_operator(S, op), m.apply_operator(S, op))
        self.assertEqual(m.apply_operator(S, "le_lt_toggle:1"), m.le_lt_toggle(S, 1))
        self.assertEqual(m.apply_operator(S, "shift_literal:1:1"), m.shift_literal(S, 1, 1))

    def test_malformed_ids_do_not_apply(self):
        for bad in ("nope", "le_lt_toggle", "le_lt_toggle:x", "le_lt_toggle:-1", "shift_literal:1", "nat_to_int:3", ""):
            self.assertIsNone(m.apply_operator(S, bad), bad)


class NearMisses(unittest.TestCase):
    def test_every_variant_differs_and_none_repeat(self):
        out = m.near_misses(S, 100)
        variants = [v for _, v in out]
        self.assertTrue(all(v != S for v in variants))
        self.assertEqual(len(variants), len(set(variants)))
        self.assertEqual(len(out), len({op for op, _ in out}))

    def test_order_is_deterministic(self):
        self.assertEqual(m.near_misses(S, 100), m.near_misses(S, 100))
        self.assertEqual([op for op, _ in m.near_misses(S, 100)][:3], ["nat_to_int", "nat_to_real", "le_lt_toggle:0"])

    def test_limit_is_a_prefix(self):
        full = m.near_misses(S, 100)
        self.assertEqual(m.near_misses(S, 4), full[:4])
        self.assertEqual(m.near_misses(S, 0), [])

    def test_duplicates_are_removed(self):
        # two operators that produce the same text: only the first is kept
        out = m.near_misses("a ≤ b", 100)
        variants = [v for _, v in out]
        self.assertEqual(len(variants), len(set(variants)))

    def test_two_operators_that_produce_the_same_text_give_one_variant(self):
        out = m.near_misses("theorem t (h : p) (h : p) : q", 100)      # dropping either copy gives the same statement
        self.assertEqual(out, [("drop_hypothesis:0", "theorem t (h : p) : q")])

    def test_a_variant_equal_to_the_statement_up_to_spacing_is_never_returned(self):
        from unittest import mock
        with mock.patch.object(m, "apply_operator", side_effect=lambda s, op: s if op == "nat_to_int" else "  " + s.replace(" ", "  ")):
            self.assertEqual(m.near_misses("theorem t : p", 10), [])

    def test_whitespace_only_changes_are_not_near_misses(self):
        out = m.near_misses("theorem t (h : p) : q", 100)
        self.assertEqual([op for op, _ in out], ["drop_hypothesis:0"])

    def test_a_statement_nothing_applies_to_gives_nothing(self):
        self.assertEqual(m.near_misses("theorem t : p", 10), [])

    def test_bad_arguments(self):
        for stmt in ("", "   ", None):
            with self.assertRaises(ValueError):
                m.near_misses(stmt, 5)
        with self.assertRaises(ValueError):
            m.near_misses(S, -1)
        with self.assertRaises(ValueError):
            m.near_misses(S, True)


if __name__ == "__main__":
    unittest.main()

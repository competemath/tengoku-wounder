import hashlib
import math
import unittest

from wounder import sampler as sp

SALT = "s" * 32
SHAS = [hashlib.sha256(str(i).encode()).hexdigest()[:40] for i in range(20000)]


def rate_of(tier, salt=SALT, rates=sp.DEFAULT_RATES, shas=SHAS):
    return sum(sp.select_for_audit(h, salt, tier, rates) for h in shas) / len(shas)


class Lottery(unittest.TestCase):
    def test_deterministic(self):
        for h in SHAS[:200]:
            self.assertEqual(sp.select_for_audit(h, SALT, 1), sp.select_for_audit(h, SALT, 1))
            self.assertEqual(sp.draw(h, SALT), sp.draw(h, SALT))

    def test_draw_is_in_unit_interval_and_looks_uniform(self):
        draws = [sp.draw(h, SALT) for h in SHAS]
        self.assertTrue(all(0.0 <= d < 1.0 for d in draws))
        mean = sum(draws) / len(draws)
        self.assertLess(abs(mean - 0.5), 5 * math.sqrt(1 / 12 / len(draws)))

    def test_different_salts_give_different_selections(self):
        a = [sp.select_for_audit(h, "a" * 32, 2) for h in SHAS[:400]]
        b = [sp.select_for_audit(h, "b" * 32, 2) for h in SHAS[:400]]
        self.assertNotEqual(a, b)
        self.assertNotEqual([sp.draw(h, "a" * 32) for h in SHAS[:5]], [sp.draw(h, "b" * 32) for h in SHAS[:5]])

    def test_different_commits_get_different_draws(self):
        self.assertEqual(len({sp.draw(h, SALT) for h in SHAS[:500]}), 500)

    def test_empirical_rate_matches_each_tier(self):
        for tier, want in enumerate((0.05, 0.20, 0.50)):
            got = rate_of(tier)
            sigma = math.sqrt(want * (1 - want) / len(SHAS))
            self.assertLess(abs(got - want), 5 * sigma, (tier, got))

    def test_tiers_are_ordered_in_effect(self):
        self.assertLess(rate_of(0), rate_of(1))
        self.assertLess(rate_of(1), rate_of(2))

    def test_a_lower_tier_selection_is_also_selected_at_a_higher_tier(self):
        for h in SHAS[:2000]:
            if sp.select_for_audit(h, SALT, 0):
                self.assertTrue(sp.select_for_audit(h, SALT, 1))
            if sp.select_for_audit(h, SALT, 1):
                self.assertTrue(sp.select_for_audit(h, SALT, 2))

    def test_tier_three_is_always_selected_whatever_the_rates_say(self):
        self.assertTrue(all(sp.select_for_audit(h, SALT, 3) for h in SHAS[:2000]))
        self.assertTrue(all(sp.select_for_audit(h, SALT, 3, (0.05, 0.05, 0.05, 0.05)) for h in SHAS[:2000]))

    def test_tier_is_clamped(self):
        for h in SHAS[:300]:
            self.assertEqual(sp.select_for_audit(h, SALT, -4), sp.select_for_audit(h, SALT, 0))
            self.assertTrue(sp.select_for_audit(h, SALT, 9))
        self.assertEqual([sp.clamp_tier(t) for t in (-1, 0, 3, 7)], [0, 0, 3, 3])

    def test_tier_must_be_an_integer(self):
        for bad in (True, 1.5, "1", None):
            with self.assertRaises(TypeError):
                sp.select_for_audit(SHAS[0], SALT, bad)

    def test_rate_never_falls_below_the_floor(self):
        self.assertEqual(sp.effective_rate(0, (0.0, 0.0, 0.0, 1.0)), sp.RATE_FLOOR)
        self.assertEqual(sp.effective_rate(0, (-1.0, 0.2, 0.5, 1.0)), sp.RATE_FLOOR)
        self.assertEqual(sp.effective_rate(1, (0.001, 0.001, 0.5, 1.0)), sp.RATE_FLOOR)
        got = rate_of(0, rates=(0.0, 0.2, 0.5, 1.0))
        self.assertLess(abs(got - 0.02), 5 * math.sqrt(0.02 * 0.98 / len(SHAS)))

    def test_rate_never_exceeds_one(self):
        self.assertEqual(sp.effective_rate(1, (0.05, 7.0, 7.0, 7.0)), 1.0)

    def test_bad_rates_are_refused(self):
        for bad in ((0.1, 0.2, 0.3), (0.1, 0.2, 0.3, float("nan")), (0.1, 0.2, 0.3, "x"), (True, 0.2, 0.3, 1.0), (0.1, 0.2, 0.3, float("inf"))):
            with self.assertRaises(ValueError):
                sp.effective_rate(0, bad)

    def test_short_salt_and_bad_commit_are_refused_even_at_tier_three(self):
        with self.assertRaises(ValueError):
            sp.select_for_audit(SHAS[0], "short", 1)
        with self.assertRaises(ValueError):
            sp.select_for_audit(SHAS[0], "short", 3)
        for bad in ("abc", "G" * 40, "A" * 40, 5):
            with self.assertRaises(ValueError):
                sp.select_for_audit(bad, SALT, 1)

    def test_salt_may_be_bytes_or_text(self):
        self.assertEqual(sp.draw(SHAS[0], "x" * 32), sp.draw(SHAS[0], b"x" * 32))

    def test_new_salts_are_long_and_fresh(self):
        a, b = sp.new_salt(), sp.new_salt()
        self.assertNotEqual(a, b)
        self.assertEqual(len(a), 64)


class CommitReveal(unittest.TestCase):
    def test_commitment_verifies_with_the_right_salt(self):
        c = sp.commit_salt(SALT)
        self.assertRegex(c, r"^[0-9a-f]{64}$")
        self.assertTrue(sp.verify_salt(c, SALT))
        self.assertTrue(sp.verify_salt(c.upper(), SALT))

    def test_a_different_salt_fails(self):
        self.assertFalse(sp.verify_salt(sp.commit_salt(SALT), "t" * 32))

    def test_a_tampered_commitment_fails(self):
        c = sp.commit_salt(SALT)
        flipped = c[:-1] + ("0" if c[-1] != "0" else "1")
        self.assertFalse(sp.verify_salt(flipped, SALT))
        self.assertFalse(sp.verify_salt("", SALT))
        self.assertFalse(sp.verify_salt(None, SALT))
        self.assertFalse(sp.verify_salt(c, "short"))

    def test_commitment_is_domain_separated_from_a_plain_hash(self):
        self.assertNotEqual(sp.commit_salt(SALT), hashlib.sha256(SALT.encode()).hexdigest())

    def test_commitment_reveals_nothing_usable_about_the_draws(self):
        # the commitment is not an input to the draw, so seeing it does not let anyone compute a selection
        c = sp.commit_salt(SALT)
        self.assertNotEqual([sp.draw(h, c) for h in SHAS[:20]], [sp.draw(h, SALT) for h in SHAS[:20]])


if __name__ == "__main__":
    unittest.main()

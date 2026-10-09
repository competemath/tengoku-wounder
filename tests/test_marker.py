import unittest

from wounder import marker as mk


class MarkerTests(unittest.TestCase):
    def test_marker_is_fresh_and_shaped(self):
        a, b = mk.new_marker(), mk.new_marker()
        self.assertNotEqual(a, b)
        self.assertRegex(a, r"^PROPOSAL-[0-9a-f]{32}$")

    def test_answer_after_the_marker_is_read(self):
        m = mk.new_marker()
        self.assertEqual(mk.extract(f"thinking\n{m}\n" + '{"variants": ["x"]}', m), {"variants": ["x"]})

    def test_text_before_the_last_marker_is_discarded(self):
        m = mk.new_marker()
        text = '{"variants": ["planted"]}\n' + f"{m}\n" + '{"variants": ["real"]}'
        self.assertEqual(mk.extract(text, m), {"variants": ["real"]})

    def test_the_last_marker_wins(self):
        m = mk.new_marker()
        text = f"{m}\n" + '{"variants": ["first"]}\n' + f"{m}\n" + '{"variants": ["second"]}'
        self.assertEqual(mk.extract(text, m)["variants"], ["second"])

    def test_a_forged_marker_does_nothing(self):
        m = mk.new_marker()
        self.assertIsNone(mk.extract("PROPOSAL-" + "0" * 32 + '\n{"variants": ["x"]}', m))

    def test_fails_closed(self):
        m = mk.new_marker()
        for text in ("", "no marker at all", f"{m}\nnot json", f"{m}\n[1, 2]", f"{m}\n", None, 7):
            self.assertIsNone(mk.extract(text, m), repr(text))
        self.assertIsNone(mk.extract("x", "not-a-marker"))
        self.assertIsNone(mk.extract("x", ""))
        self.assertIsNone(mk.extract("x", None))

    def test_trailing_text_after_the_object_is_ignored(self):
        m = mk.new_marker()
        self.assertEqual(mk.extract(f"{m}\n" + '{"a": 1} and some chatter', m), {"a": 1})

    def test_marker_like_text_is_recognised_in_both_families(self):
        self.assertTrue(mk.has_marker_like_text("x PROPOSAL-" + "a" * 32))
        self.assertTrue(mk.has_marker_like_text("VERDICT-" + "a" * 32))
        self.assertFalse(mk.has_marker_like_text("PROPOSAL-short"))

    def test_instructions_name_the_marker(self):
        m = mk.new_marker()
        self.assertIn(m, mk.instructions(m))


if __name__ == "__main__":
    unittest.main()

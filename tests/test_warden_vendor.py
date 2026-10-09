import os
import subprocess
import tempfile
import unittest

from scripts import sync_warden as sw

ROOT = sw.ROOT
EXPECTED_COMMIT = "8e78f4f1e2b204f7c81da3b155d54e7502086420"


class VendoredWarden(unittest.TestCase):
    def test_vendored_copies_match_their_pin(self):
        self.assertEqual(sw.verify(ROOT), [])

    def test_the_pin_names_the_warden_commit_this_was_built_against(self):
        commit, files = sw.read_pin(ROOT)
        self.assertEqual(commit, EXPECTED_COMMIT)
        self.assertEqual(set(files), set(sw.FILES))

    def test_an_edited_copy_fails_the_check(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "vendor", "warden"))
            for name in sw.FILES + ("PIN",):
                with open(os.path.join(ROOT, "vendor", "warden", name), "rb") as fh:
                    data = fh.read()
                with open(os.path.join(d, "vendor", "warden", name), "wb") as fh:
                    fh.write(data + (b"# tampered\n" if name == "verdict.py" else b""))
            problems = sw.verify(d)
            self.assertEqual(len(problems), 1)
            self.assertIn("verdict.py", problems[0])

    def test_an_unpinned_extra_file_or_a_missing_pin_fails(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIn("pin unreadable", sw.verify(d)[0])
            os.makedirs(os.path.join(d, "vendor", "warden"))
            for name in sw.FILES + ("PIN",):
                with open(os.path.join(ROOT, "vendor", "warden", name), "rb") as fh:
                    data = fh.read()
                with open(os.path.join(d, "vendor", "warden", name), "wb") as fh:
                    fh.write(data)
            open(os.path.join(d, "vendor", "warden", "extra.py"), "w").close()
            self.assertIn("unpinned files", sw.verify(d)[0])

    def test_sync_copies_byte_for_byte_and_refuses_a_dirty_checkout(self):
        try:
            subprocess.run(["git", "--version"], check=True, capture_output=True)
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("git not available")
        with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as dst:
            os.makedirs(os.path.join(src, "warden"))
            for name in sw.FILES:
                with open(os.path.join(src, "warden", name), "wb") as fh:
                    fh.write(("# " + name + " é\r\n").encode("utf-8"))
            run = lambda *a: subprocess.run(["git", "-C", src, "-c", "user.name=t", "-c", "user.email=t@example.com", *a],
                                            check=True, capture_output=True, text=True)
            run("init", "-q")
            run("add", ".")
            run("commit", "-q", "-m", "x")
            head = run("rev-parse", "HEAD").stdout.strip()
            self.assertEqual(sw.sync(src, dst)["commit"], head)
            self.assertEqual(sw.verify(dst), [])
            with open(os.path.join(src, "warden", "verdict.py"), "ab") as fh:
                fh.write(b"# dirty\n")
            with self.assertRaises(SystemExit):
                sw.sync(src, dst)

    def test_the_copies_equal_a_sibling_warden_checkout_when_there_is_one(self):
        sibling = os.path.join(os.path.dirname(ROOT), "tengoku-warden", "warden")
        if not os.path.isdir(sibling):
            self.skipTest("no sibling tengoku-warden checkout")
        try:
            head = subprocess.run(["git", "-C", sibling, "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("sibling is not a git checkout")
        if head != EXPECTED_COMMIT:
            self.skipTest("sibling warden is at another commit")
        for name in sw.FILES:
            with open(os.path.join(sibling, name), "rb") as a, open(os.path.join(ROOT, "vendor", "warden", name), "rb") as b:
                self.assertEqual(a.read(), b.read(), name)

    def test_vendor_import_path_works_and_the_gates_use_the_pinned_copies(self):
        import sys

        from wounder import agentsec
        w = agentsec.warden()
        self.assertIs(sys.modules["warden"], sys.modules["vendor.warden"])
        self.assertIs(sys.modules["warden.envscrub"], w.envscrub)
        self.assertEqual(agentsec.pin_commit(), EXPECTED_COMMIT)
        # envscrub asks warden.secretscan lazily; it must get the vendored copy (and so find the secret)
        token = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7"
        self.assertTrue(w.envscrub._secretscan_says_secret(token))


if __name__ == "__main__":
    unittest.main()

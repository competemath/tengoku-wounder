import hashlib
import os
import subprocess
import tempfile
import unittest

from scripts import sync_contract as sc
from tests.helpers import ROOT

EXPECTED_SHA = "ddccbc97eef67c9e9dec395541c60b3e9de9956c88d486ecff36fad9ce6bc93e"
EXPECTED_COMMIT = "3e70f62fc20081cd820d08c03828eaabfb0e2153"


class VendoredContract(unittest.TestCase):
    def test_vendored_copy_matches_its_pin(self):
        self.assertEqual(sc.verify(ROOT), [])

    def test_the_pin_names_the_juridicator_commit_this_was_built_against(self):
        self.assertEqual(sc.read_pin(ROOT), (EXPECTED_SHA, EXPECTED_COMMIT))

    def test_pin_file_is_exactly_the_documented_line(self):
        with open(os.path.join(ROOT, "vendor", "EVIDENCE.sha256"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), f"{EXPECTED_SHA}  juridicator/evidence.py  # tengoku-juridicator {EXPECTED_COMMIT}\n")

    def test_edited_vendored_copy_fails_the_check(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "vendor"))
            for name in ("juridicator_evidence.py", "EVIDENCE.sha256"):
                with open(os.path.join(ROOT, "vendor", name), "rb") as fh:
                    data = fh.read()
                with open(os.path.join(d, "vendor", name), "wb") as fh:
                    fh.write(data + (b"# tampered\n" if name.endswith(".py") else b""))
            problems = sc.verify(d)
            self.assertTrue(problems and "pin says" in problems[0])

    def test_missing_or_malformed_pin_fails(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertTrue(sc.verify(d))
            os.makedirs(os.path.join(d, "vendor"))
            with open(os.path.join(d, "vendor", "EVIDENCE.sha256"), "w") as fh:
                fh.write("not a pin\n")
            self.assertIn("pin unreadable", sc.verify(d)[0])

    def test_package_marker_exists_and_import_path_works(self):
        self.assertTrue(os.path.exists(os.path.join(ROOT, "vendor", "__init__.py")))
        from vendor.juridicator_evidence import SCHEMA, make_evidence, validate  # noqa: F401
        self.assertEqual(SCHEMA, "tengoku-evidence/1")


class SyncScript(unittest.TestCase):
    def make_source(self, d, text=b"SCHEMA = 'x'\n"):
        os.makedirs(os.path.join(d, "juridicator"))
        with open(os.path.join(d, "juridicator", "evidence.py"), "wb") as fh:
            fh.write(text)

    def test_sync_copies_byte_for_byte_and_writes_the_pin(self):
        with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as dst:
            payload = "# café ℕ\r\nx = 1\n".encode("utf-8")
            self.make_source(src, payload)
            result = sc.sync(src, dst, commit="b" * 40)
            with open(os.path.join(dst, "vendor", "juridicator_evidence.py"), "rb") as fh:
                self.assertEqual(fh.read(), payload)
            self.assertEqual(result["sha256"], hashlib.sha256(payload).hexdigest())
            self.assertEqual(sc.read_pin(dst), (hashlib.sha256(payload).hexdigest(), "b" * 40))
            self.assertEqual(sc.verify(dst), [])
            self.assertTrue(os.path.exists(os.path.join(dst, "vendor", "__init__.py")))

    def test_sync_refuses_a_directory_that_is_not_a_juridicator_checkout(self):
        with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as dst:
            with self.assertRaises(SystemExit):
                sc.sync(src, dst, commit="b" * 40)

    def test_sync_refuses_a_bad_commit(self):
        with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as dst:
            self.make_source(src)
            with self.assertRaises(SystemExit):
                sc.sync(src, dst, commit="nope")

    def test_sync_reads_the_commit_from_git_and_refuses_uncommitted_changes(self):
        try:
            subprocess.run(["git", "--version"], check=True, capture_output=True)
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("git not available")
        with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as dst:
            self.make_source(src)
            run = lambda *a: subprocess.run(["git", "-C", src, "-c", "user.name=t", "-c", "user.email=t@example.com", *a],
                                            check=True, capture_output=True, text=True)
            run("init", "-q")
            run("add", ".")
            run("commit", "-q", "-m", "x")
            head = run("rev-parse", "HEAD").stdout.strip()
            self.assertEqual(sc.sync(src, dst)["commit"], head)
            with open(os.path.join(src, "juridicator", "evidence.py"), "ab") as fh:
                fh.write(b"# dirty\n")
            with self.assertRaises(SystemExit):
                sc.sync(src, dst)


if __name__ == "__main__":
    unittest.main()

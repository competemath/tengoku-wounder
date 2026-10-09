import os
import shlex
import sys
import time
import unittest

from tests.helpers import PY, tmpdir, write_script
from wounder import runner


class Runner(unittest.TestCase):
    def test_absolutizes_only_existing_paths_containing_a_separator(self):
        with tmpdir() as d:
            old = os.getcwd()
            os.chdir(d)
            try:
                os.makedirs("sub")
                open("sub/gate.py", "w").close()
                open("python3", "w").close()      # a planted file with a bare name must not be picked up
                argv = runner.split_command("python3 sub/gate.py missing/file")
            finally:
                os.chdir(old)
        self.assertEqual(argv[0], "python3")
        self.assertTrue(os.path.isabs(argv[1]) and argv[1].endswith(os.path.join("sub", "gate.py")))
        self.assertEqual(argv[2], "missing/file")

    def test_empty_command_refused(self):
        for bad in ("", "  ", None):
            with self.assertRaises(ValueError):
                runner.split_command(bad)

    def test_scrubbed_env_keeps_path_and_drops_the_rest(self):
        os.environ["SOME_API_KEY"] = "x"
        try:
            env = runner.scrubbed_env("/h")
        finally:
            del os.environ["SOME_API_KEY"]
        self.assertNotIn("SOME_API_KEY", env)
        self.assertEqual(env["HOME"], "/h")
        self.assertNotIn("WOUNDER_NO_NETWORK", env, "no environment hint that a canary run is under way")
        self.assertEqual(env["https_proxy"], "http://127.0.0.1:9")
        self.assertIn("PATH", env)

    def test_output_is_bounded(self):
        with tmpdir() as d:
            s = write_script(d, "loud.py", "import sys\nsys.stdout.write('x' * 1000000)\n")
            r = runner.run_command([sys.executable, s], timeout=20)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(len(r.stdout), runner.MAX_OUTPUT)

    def test_timeout_kills_the_whole_process_group(self):
        with tmpdir() as d:
            pidfile = os.path.join(d, "child.pid")
            s = write_script(d, "spawn.py",
                             "import subprocess, sys, time\n"
                             f"p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
                             f"open({pidfile!r}, 'w').write(str(p.pid))\n"
                             "time.sleep(60)\n")
            start = time.time()
            r = runner.run_command([sys.executable, s], timeout=2.0)
            self.assertTrue(r.timed_out)
            self.assertLess(time.time() - start, 15)
            with open(pidfile) as fh:
                pid = int(fh.read())
            time.sleep(0.3)
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_could_not_start_is_reported_not_raised(self):
        r = runner.run_command(["/definitely/not/here"], timeout=2)
        self.assertIsNotNone(r.error)


if __name__ == "__main__":
    unittest.main()

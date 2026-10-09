import copy
import json
import os
import re
import shlex
import sys
import unittest

from vendor.juridicator_evidence import validate
from wounder import canary
from wounder.canary import CATEGORIES, CorpusError, GateResult, ReferenceTextGate, load_corpus, validate_case
from tests.helpers import (CASE, CORPUS_DIR, HEAD, NOW, PY, AcceptAll, ErroringGate, PerfectGate, RaisingGate, RejectAll, Recorder,
                           corpus, producer, repro, run_all, tmpdir, write_script)

BAD_BY_TEXT = {"axiom_declared", "sorry_present", "sorry_hidden_in_term", "native_decide_used", "unsafe_or_implemented_by"}
MISSED_BY_TEXT = {"axiom_via_metaprogram", "vacuous_hypotheses", "statement_type_drift", "shadowed_name", "duplicate_statement"}


def by_id(records):
    return {r["subject"]["declaration"]: r for r in records}


class Corpus(unittest.TestCase):
    def test_every_case_is_valid_and_ids_match_file_names(self):
        entries = corpus()
        self.assertGreaterEqual(len(entries), 14)
        self.assertEqual(sorted(os.listdir(CORPUS_DIR)), [e["id"] + ".json" for e in entries])

    def test_every_defect_category_has_a_case(self):
        present = {e["category"] for e in corpus()}
        self.assertEqual(present, set(CATEGORIES))

    def test_known_good_cases_exist_so_over_blocking_is_detected(self):
        good = [e for e in corpus() if e["category"] == "known_good"]
        self.assertGreaterEqual(len(good), 3)
        self.assertTrue(all(e["expected"] == "accept" for e in good))

    def test_comment_only_directive_expects_accept(self):
        e = {c["id"]: c for c in corpus()}["comment_hidden_directive"]
        self.assertEqual(e["expected"], "accept")

    def test_each_case_is_tiny(self):
        for e in corpus():
            for name, text in e["files"].items():
                self.assertLessEqual(len(text.splitlines()), 8, (e["id"], name))

    def test_why_is_one_sentence_naming_what_a_correct_gate_does(self):
        for e in corpus():
            self.assertTrue(e["why"].startswith("A correct gate "), e["id"])
            self.assertEqual(e["why"].count(". "), 0, e["id"])

    def test_metaprogram_case_never_uses_axiom_as_a_keyword(self):
        e = {c["id"]: c for c in corpus()}["axiom_via_metaprogram"]
        src = "\n".join(e["files"].values())
        self.assertIn("addDecl", src)
        self.assertIn("axiomDecl", src)
        self.assertIsNone(re.search(r"(?<![\w.])axiom(?![\w'])", src))

    def test_unknown_key_missing_key_bad_category_and_wrong_expectation_are_refused(self):
        base = corpus()[0]
        for mutate in (
            lambda c: c.update(status="proposed"),
            lambda c: c.pop("why"),
            lambda c: c.update(category="made_up"),
            lambda c: c.update(expected="accept"),            # axiom_declared must expect reject
            lambda c: c.update(id="Bad Id"),
            lambda c: c.update(description="two\nlines"),
            lambda c: c.update(files={}),
            lambda c: c.update(files={"../escape.lean": "x"}),
            lambda c: c.update(files={"a/b.lean": "x"}),
            lambda c: c.update(files={"notlean.txt": "x"}),
            lambda c: c.update(files={"a.lean": "x" * 5000}),
            lambda c: c.update(files={"a.lean": "x\x00y"}),
            lambda c: c.update(files={f"f{i}.lean": "x" for i in range(9)}),
        ):
            c = copy.deepcopy(base)
            mutate(c)
            with self.assertRaises(CorpusError):
                validate_case(c)
        with self.assertRaises(CorpusError):
            validate_case("not an object")

    def test_known_good_must_expect_accept(self):
        c = copy.deepcopy([e for e in corpus() if e["category"] == "known_good"][0])
        c["expected"] = "reject"
        with self.assertRaises(CorpusError):
            validate_case(c)

    def test_loader_refuses_proposed_directory_by_name_even_when_the_cases_in_it_are_valid(self):
        with tmpdir() as d:
            p = os.path.join(d, "proposed")
            sub = os.path.join(p, "deeper")
            os.makedirs(sub)
            for where in (p, sub):
                with open(os.path.join(where, "sorry_present.json"), "w", encoding="utf-8") as fh:
                    json.dump([e for e in corpus() if e["id"] == "sorry_present"][0], fh)
                with self.assertRaises(CorpusError) as ctx:
                    load_corpus(where)
                self.assertIn("quarantine", str(ctx.exception))
            with self.assertRaises(CorpusError) as ctx:
                load_corpus(CORPUS_DIR, p)
            self.assertIn("quarantine", str(ctx.exception))

    def test_loader_refuses_empty_missing_and_duplicate(self):
        with tmpdir() as d:
            with self.assertRaises(CorpusError):
                load_corpus(d)
            with self.assertRaises(CorpusError):
                load_corpus(os.path.join(d, "nope"))
            with self.assertRaises(CorpusError):
                load_corpus()
            second = os.path.join(d, "second")
            os.makedirs(second)
            with open(os.path.join(second, "sorry_present.json"), "w") as fh:
                json.dump([e for e in corpus() if e["id"] == "sorry_present"][0], fh)
            with self.assertRaises(CorpusError):
                load_corpus(CORPUS_DIR, second)

    def test_loader_refuses_a_file_name_that_is_not_the_id(self):
        with tmpdir() as d:
            with open(os.path.join(d, "other.json"), "w") as fh:
                json.dump(corpus()[0], fh)
            with self.assertRaises(CorpusError):
                load_corpus(d)

    def test_a_private_slice_can_sit_beside_the_public_corpus(self):
        with tmpdir() as d:
            extra = copy.deepcopy([e for e in corpus() if e["id"] == "sorry_present"][0])
            extra["id"] = "private_sorry"
            with open(os.path.join(d, "private_sorry.json"), "w") as fh:
                json.dump(extra, fh)
            ids = [e["id"] for e in load_corpus(CORPUS_DIR, d)]
            self.assertIn("private_sorry", ids)
            self.assertEqual(ids, sorted(ids))

    def test_corpus_digest_changes_when_any_case_changes(self):
        a = corpus()
        b = copy.deepcopy(a)
        b[0]["files"] = {k: v + "-- x\n" for k, v in b[0]["files"].items()}
        self.assertNotEqual(canary.corpus_digest(a), canary.corpus_digest(b))
        self.assertEqual(canary.corpus_digest(a), canary.corpus_digest(list(reversed(a))))


class ReferenceGateBehaviour(unittest.TestCase):
    def test_strip_comments_handles_line_nested_block_and_strings(self):
        self.assertNotIn("sorry", canary.strip_comments("-- sorry\nx"))
        self.assertNotIn("sorry", canary.strip_comments("/- a /- sorry -/ sorry -/ y"))
        self.assertNotIn("sorry", canary.strip_comments('def s := "sorry -- not a comment"'))
        self.assertIn("y", canary.strip_comments("/- unterminated sorry"+"\n") + "y")
        self.assertEqual(canary.strip_comments("a -- b\nc"), "a \nc")

    def test_whole_word_only(self):
        g = ReferenceTextGate()
        self.assertTrue(g({"files": {"a.lean": "def sorryCount := 1\n"}}).accepted)
        self.assertTrue(g({"files": {"a.lean": "def my_sorry := 1\n"}}).accepted, "a longer name ending in a forbidden word")
        self.assertTrue(g({"files": {"a.lean": "def x := Foo.sorry\n"}}).accepted, "a qualified name is not the command")
        self.assertTrue(g({"files": {"a.lean": "theorem x : 1 = 1 := by decide\n"}}).accepted)
        self.assertFalse(g({"files": {"a.lean": "theorem x : 1 = 1 := by native_decide\n"}}).accepted)
        self.assertFalse(g({"files": {"a.lean": "x := sorry\n"}}).accepted)


class HarnessHasTeeth(unittest.TestCase):
    def setUp(self):
        self.records = by_id(run_all(ReferenceTextGate()))

    def test_text_gate_catches_what_text_can_see(self):
        for cid in BAD_BY_TEXT:
            self.assertEqual(self.records[cid]["outcome"], "pass", cid)
            self.assertFalse(self.records[cid]["details"]["gate_accepted"])

    def test_text_gate_misses_what_needs_a_semantic_gate(self):
        """This documents what a purely textual gate cannot catch. If one of these starts to pass, check why."""
        for cid in MISSED_BY_TEXT:
            self.assertEqual(self.records[cid]["outcome"], "fail", cid)
            self.assertTrue(self.records[cid]["details"]["gate_accepted"])
            self.assertIn("ACCEPTED", self.records[cid]["claim"])
        for cid in ("axiom_via_metaprogram", "vacuous_hypotheses", "statement_type_drift"):
            self.assertEqual(self.records[cid]["outcome"], "fail")

    def test_text_gate_passes_comments_and_known_good(self):
        for e in corpus():
            if e["expected"] == "accept":
                self.assertEqual(self.records[e["id"]]["outcome"], "pass", e["id"])

    def test_a_gate_that_accepts_everything_fails_every_planted_bad_case(self):
        records = by_id(run_all(AcceptAll()))
        for e in corpus():
            want = "fail" if e["expected"] == "reject" else "pass"
            self.assertEqual(records[e["id"]]["outcome"], want, e["id"])
        self.assertEqual(sum(r["outcome"] == "fail" for r in records.values()), sum(e["expected"] == "reject" for e in corpus()))

    def test_a_gate_that_rejects_everything_fails_every_known_good_case(self):
        records = by_id(run_all(RejectAll()))
        for e in corpus():
            want = "fail" if e["expected"] == "accept" else "pass"
            self.assertEqual(records[e["id"]]["outcome"], want, e["id"])
        self.assertIn("REJECTED a known-good", records["good_add_comm"]["claim"])

    def test_a_perfect_gate_passes_everything(self):
        records = run_all(PerfectGate(corpus()))
        self.assertTrue(all(r["outcome"] == "pass" for r in records))

    def test_gate_errors_are_inconclusive_never_a_pass(self):
        for gate in (ErroringGate(), RaisingGate()):
            records = run_all(gate)
            self.assertTrue(all(r["outcome"] == "inconclusive" for r in records), type(gate).__name__)
            self.assertTrue(all(r["details"]["gate_error"] for r in records))

    def test_a_gate_returning_the_wrong_type_is_an_error(self):
        records = run_all(lambda case: True)
        self.assertTrue(all(r["outcome"] == "inconclusive" for r in records))

    def test_the_gate_is_shown_only_the_files(self):
        rec = Recorder()
        run_all(rec)
        self.assertEqual(len(rec.seen), len(corpus()))
        for seen in rec.seen:
            self.assertEqual(set(seen), {"files"})


class RecordShape(unittest.TestCase):
    def setUp(self):
        self.records = run_all(ReferenceTextGate())

    def test_one_canary_record_per_case_in_corpus_order(self):
        self.assertEqual([r["subject"]["declaration"] for r in self.records], [e["id"] for e in corpus()])
        self.assertTrue(all(r["kind"] == "mechanical.canary" for r in self.records))

    def test_every_record_validates_under_the_vendored_contract(self):
        for r in self.records:
            self.assertEqual(validate(r), [], r["claim"])
            self.assertEqual(r["verifiability"], "mechanical")
            self.assertEqual(r["producer"]["role"], "wounder")
            self.assertEqual(r["ai"], {"used": False, "role": "none"})

    def test_claim_names_case_and_category_and_fits_the_limit(self):
        for r, e in zip(self.records, corpus()):
            self.assertIn(e["id"], r["claim"])
            self.assertIn(e["category"], r["claim"])
            self.assertLessEqual(len(r["claim"]), 300)
            self.assertEqual(r["details"]["category"], e["category"])

    def test_reproduce_command_reruns_just_that_case(self):
        for r in self.records:
            cid = r["subject"]["declaration"]
            self.assertEqual(r["reproduce"]["command"], repro(cid))
            self.assertIn(f"--only {cid} ", r["reproduce"]["command"] + " ")

    def test_reproduce_may_be_a_template_with_an_id_slot(self):
        records = canary.run_canaries(corpus()[:2], AcceptAll(), CASE, producer(), NOW, "python3 -m wounder run-canaries --only {id}")
        self.assertTrue(records[0]["reproduce"]["command"].endswith(corpus()[0]["id"]))

    def test_a_missing_or_overlong_reproduce_command_is_refused_not_emitted(self):
        with self.assertRaises(ValueError):
            canary.run_canaries(corpus()[:1], AcceptAll(), CASE, producer(), NOW, lambda cid: "")
        with self.assertRaises(ValueError):
            canary.run_canaries(corpus()[:1], AcceptAll(), CASE, producer(), NOW, lambda cid: "x" * 1001)

    def test_subjects_are_distinct_so_one_failure_does_not_look_like_a_checker_disagreement(self):
        self.assertEqual(len({json.dumps(r["subject"], sort_keys=True) for r in self.records}), len(self.records))

    def test_details_stay_small_even_when_the_gate_is_chatty(self):
        chatty = lambda case: GateResult(False, ["x" * 5000 + "\x00"] * 50)
        for r in run_all(chatty):
            self.assertEqual(validate(r), [])
            self.assertLessEqual(len(r["details"]["gate_reasons"]), 5)
            self.assertTrue(all(len(x) <= 200 and "\x00" not in x for x in r["details"]["gate_reasons"]))

    def test_same_inputs_same_records(self):
        self.assertEqual(self.records, run_all(ReferenceTextGate()))

    def test_case_digest_pins_the_exact_case_text(self):
        for r, e in zip(self.records, corpus()):
            self.assertEqual(r["details"]["case_sha256"], canary.case_digest(e))

    def test_an_invalid_corpus_entry_is_refused_before_running(self):
        bad = copy.deepcopy(corpus()[0])
        bad["expected"] = "maybe"
        rec = Recorder()
        with self.assertRaises(CorpusError):
            canary.run_canaries([bad], rec, CASE, producer(), NOW, repro)
        self.assertEqual(rec.seen, [])

    def test_on_record_callback_sees_each_record_as_it_is_made(self):
        seen = []
        canary.run_canaries(corpus()[:3], AcceptAll(), CASE, producer(), NOW, repro, on_record=seen.append)
        self.assertEqual(len(seen), 3)


class Manifest(unittest.TestCase):
    def test_manifest_declares_the_canary_kind_and_validates(self):
        m = canary.manifest_for(CASE, producer(), NOW, corpus())
        self.assertEqual(validate(m), [])
        self.assertEqual(m["kind"], "manifest.declared")
        self.assertEqual(m["verifiability"], "attested")
        self.assertEqual(m["details"]["checks"], ["mechanical.canary"])
        self.assertEqual(m["details"]["canary_count"], len(corpus()))
        self.assertEqual(m["producer"], producer())

    def test_canary_run_puts_the_manifest_first(self):
        out = canary.canary_run(corpus(), AcceptAll(), CASE, producer(), NOW, repro)
        self.assertEqual(out[0]["kind"], "manifest.declared")
        self.assertEqual(len(out), len(corpus()) + 1)

    def test_manifest_is_made_before_the_gate_runs(self):
        order = []

        class G:
            def __call__(self, case):
                order.append("gate")
                return GateResult(True, [])

        canary.canary_run(corpus()[:2], G(), CASE, producer(), NOW, repro, on_record=lambda r: order.append(r["kind"]))
        self.assertEqual(order[0], "manifest.declared")
        self.assertLess(order.index("manifest.declared"), order.index("gate"))

    def test_missing_cases_names_canaries_that_were_not_reported(self):
        records = run_all(AcceptAll())
        self.assertEqual(canary.missing_cases(corpus(), records), [])
        self.assertEqual(canary.missing_cases(corpus(), records[1:]), [records[0]["subject"]["declaration"]])
        not_run = copy.deepcopy(records)
        not_run[0]["outcome"] = "not_run"
        self.assertEqual(canary.missing_cases(corpus(), not_run), [records[0]["subject"]["declaration"]])


class CommandGateTests(unittest.TestCase):
    GATE = (
        "import os, sys\n"
        "d = sys.argv[-1]\n"
        "names = sorted(os.listdir(d))\n"
        "if os.environ.get('WOUNDER_TEST_SECRET'):\n    print('secret visible'); sys.exit(7)\n"
        "text = ''.join(open(os.path.join(d, n), encoding='utf-8').read() for n in names)\n"
        "if 'sorry' in text:\n    print('found sorry'); sys.exit(1)\n"
        "sys.exit(0)\n")

    def setUp(self):
        self._tmp = tmpdir()
        self.dir = self._tmp.__enter__()
        self.script = write_script(self.dir, "gate.py", self.GATE)
        self.cmd = f"{PY} {shlex.quote(self.script)}"

    def tearDown(self):
        self._tmp.__exit__(None, None, None)

    def test_exit_zero_accepts_and_nonzero_rejects_with_reasons(self):
        g = canary.CommandGate(self.cmd)
        ok = g({"files": {"Main.lean": "theorem x : 1 = 1 := rfl\n"}})
        self.assertTrue(ok.accepted)
        self.assertFalse(ok.error)
        bad = g({"files": {"Main.lean": "x := sorry\n"}})
        self.assertFalse(bad.accepted)
        self.assertFalse(bad.error)
        self.assertIn("found sorry", bad.reasons)

    def test_the_gate_runs_in_the_real_corpus_end_to_end(self):
        records = by_id(run_all(canary.CommandGate(self.cmd)))
        self.assertEqual(records["sorry_present"]["outcome"], "pass")
        self.assertEqual(records["axiom_declared"]["outcome"], "fail")   # this toy gate only looks for sorry
        self.assertEqual(records["good_add_comm"]["outcome"], "pass")

    def test_timeout_is_an_error_not_a_pass(self):
        slow = write_script(self.dir, "slow.py", "import time\ntime.sleep(30)\n")
        r = canary.CommandGate(f"{PY} {shlex.quote(slow)}", timeout=0.5)({"files": {"A.lean": "x"}})
        self.assertTrue(r.error)
        self.assertFalse(r.accepted)
        self.assertIn("timed out", r.reasons[0])

    def test_a_crash_with_a_traceback_is_an_error_even_though_it_exits_nonzero(self):
        crash = write_script(self.dir, "crash.py", "raise RuntimeError('bug in the gate')\n")
        r = canary.CommandGate(f"{PY} {shlex.quote(crash)}")({"files": {"A.lean": "x"}})
        self.assertTrue(r.error)

    def test_signal_death_and_command_not_found_are_errors(self):
        killed = write_script(self.dir, "killed.py", "import os, signal\nos.kill(os.getpid(), signal.SIGKILL)\n")
        self.assertTrue(canary.CommandGate(f"{PY} {shlex.quote(killed)}")({"files": {"A.lean": "x"}}).error)
        self.assertTrue(canary.CommandGate("definitely-not-a-real-command-xyz")({"files": {"A.lean": "x"}}).error)
        exit127 = write_script(self.dir, "e127.py", "import sys\nsys.exit(127)\n")
        self.assertTrue(canary.CommandGate(f"{PY} {shlex.quote(exit127)}")({"files": {"A.lean": "x"}}).error)

    def test_environment_is_scrubbed(self):
        os.environ["WOUNDER_TEST_SECRET"] = "hunter2"
        try:
            r = canary.CommandGate(self.cmd)({"files": {"Main.lean": "fine\n"}})
        finally:
            del os.environ["WOUNDER_TEST_SECRET"]
        self.assertTrue(r.accepted, r.reasons)

    def test_no_shell_is_involved(self):
        marker = os.path.join(self.dir, "pwned")
        g = canary.CommandGate(f"{PY} {shlex.quote(self.script)} ';' touch {shlex.quote(marker)}")
        g({"files": {"Main.lean": "fine\n"}})
        self.assertFalse(os.path.exists(marker))
        g2 = canary.CommandGate(f"{PY} {shlex.quote(self.script)} && touch {shlex.quote(marker)}")
        g2({"files": {"Main.lean": "fine\n"}})
        self.assertFalse(os.path.exists(marker))

    def test_case_directory_is_the_last_argument_and_holds_exactly_the_files(self):
        probe = write_script(self.dir, "probe.py",
                             "import os, sys\nd = sys.argv[-1]\nsys.exit(0 if sorted(os.listdir(d)) == ['a.lean', 'b.lean'] else 1)\n")
        g = canary.CommandGate(f"{PY} {shlex.quote(probe)}")
        self.assertTrue(g({"files": {"a.lean": "1", "b.lean": "2"}}).accepted)
        self.assertFalse(g({"files": {"a.lean": "1"}}).accepted)

    def test_unsafe_file_names_are_never_written(self):
        r = canary.CommandGate(self.cmd)({"files": {"../x.lean": "1"}})
        self.assertTrue(r.error)

    def test_case_directories_are_removed_afterwards(self):
        record = write_script(self.dir, "rec.py", f"import sys\nopen({os.path.join(self.dir, 'seen.txt')!r}, 'w').write(sys.argv[-1])\n")
        canary.CommandGate(f"{PY} {shlex.quote(record)}")({"files": {"a.lean": "1"}})
        with open(os.path.join(self.dir, "seen.txt")) as fh:
            self.assertFalse(os.path.exists(fh.read()))

    def test_empty_command_is_refused(self):
        with self.assertRaises(ValueError):
            canary.CommandGate("   ")


if __name__ == "__main__":
    unittest.main()


class Layers(unittest.TestCase):
    def test_every_case_has_a_layer_and_the_static_layer_is_what_a_text_gate_can_be_asked(self):
        layers = {e["id"]: canary.layer_of(e) for e in corpus()}
        self.assertEqual({v for v in layers.values()}, {"static", "axioms", "vacuity", "fidelity", "tree"})
        self.assertEqual(layers["vacuous_hypotheses"], "vacuity")
        self.assertEqual(layers["statement_type_drift"], "fidelity")
        self.assertEqual({k for k, v in layers.items() if v == "tree"}, {"shadowed_name", "duplicate_statement"})
        self.assertEqual({k for k, v in layers.items() if v == "axioms"}, {"sorry_present", "sorry_hidden_in_term"})
        static = {k for k, v in layers.items() if v == "static"}
        self.assertIn("axiom_via_metaprogram", static)  # an allow-list lint is expected to catch this one
        self.assertIn("comment_hidden_directive", static)

    def test_cli_layer_flag_scopes_the_run_and_its_manifest(self):
        import contextlib
        import io
        import tempfile

        from wounder.cli import main

        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "o")
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(["run-canaries", "--corpus", CORPUS_DIR, "--reference-gate", "--layer", "static", "--repo", "r", "--head", HEAD,
                             "--class", "gate", "--out", out, "--created", NOW])
            self.assertEqual(code, 0)
            def read(name):
                with open(os.path.join(out, name), encoding="utf-8") as fh:
                    return json.load(fh)

            subjects = sorted(read(f)["subject"]["declaration"] for f in os.listdir(out) if "mechanical-canary" in f)
            self.assertEqual(subjects, sorted(e["id"] for e in corpus() if canary.layer_of(e) == "static"))
            manifest = read("00-manifest-declared.json")
            self.assertEqual(len(manifest["details"]["expected"]), len(subjects))
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(["run-canaries", "--corpus", CORPUS_DIR, "--reference-gate", "--layer", "nonsense", "--repo", "r", "--head", HEAD,
                      "--class", "gate", "--out", out + "2"])

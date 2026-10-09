# Security notes for the wounder

The wounder is quality assurance for our own gate, so what needs protecting is the *honesty of its evidence*: a canary run
that reports health which does not exist is worse than no run. The program-wide threat model and residual risks R1 to R10
are in the juridicator's `docs/SECURITY.md`; this page adds the risks that are specific to the wounder. Nothing here has
been through an outside audit.

## What is defended

| Threat | Defence | Where |
| --- | --- | --- |
| A harness that cannot fail | tests assert the textual reference gate misses the semantic defects, an accept-everything gate fails every bad case, a reject-everything gate fails every known-good case | `tests/test_canary.py` |
| Over-blocking goes unseen | known-good and comment-only cases expect accept; rejecting them is a fail | corpus, `canary.judge` |
| A gate crash looks like a catch | signals, exit 126/127, timeouts and Python tracebacks are errors, reported inconclusive, never pass | `canary.interpret` |
| The gate answers from the label | the gate is shown only the files, not the id, category or verdict | `canary.gate_view` |
| A failure hidden by the exit code | failures are evidence; the exit code is 0 whenever evidence was written | `cli.py` |
| Selective reporting | a manifest is declared before running; the run directory carries `COMPLETE` only after every case is reported | `canary.canary_run`, `cli.py` |
| A command escaping the fixture | no shell, scrubbed environment, scratch directory, timeout, process-group kill, output and file-size limits | `runner.py` |
| Path tricks in a corpus case | file names must be plain `.lean` names; checked on load and again before writing | `canary.validate_case`, `CommandGate` |
| AI output treated as trusted | one-time marker, validation, quarantine, no execution, human promotion | `ai_boundary.py` |
| Runaway spend | reserve-before-spend, persisted, day supplied not read, fails closed on a damaged file | `budget.py` |
| Audit dodging by grinding commits | commit-reveal salt | `sampler.py`, `docs/AUDIT-LOTTERY.md` |
| Contract drift | vendored evidence module pinned by hash; a test fails on any difference | `vendor/`, `scripts/sync_contract.py` |
| Tests that do not test | `scripts/mutation_check.py` breaks key lines one at a time and requires the suite to notice | `scripts/` |

## Residual risks (not solved)

- **W1 The corpus only covers what we thought of.** Canaries guard against regressions and known categories, not unknown
  ones. A green canary run means "no known defect got through", never "no defect gets through". The near-miss generators
  and the red-team loop widen coverage; neither is a guarantee (juridicator R6).
- **W2 Canary leakage and overfitting.** If the corpus is public, a gate (or the people tuning it) can learn the exact
  cases and pass them without being sound. Mitigations: a private held-out slice (`corpus-private/`, a second `--corpus`)
  that is never published; new cases generated from the operators so the text changes; the gate sees only files. None of
  these stops a gate from memorising text it has seen.
- **W3 The gate under test can recognise the test.** A gate (or its environment) that detects a canary run could behave
  well only then. The runner avoids naming the run in the environment or the scratch directory, but a gate can still match
  file contents. Mitigations: run canaries through the same command and path that real submissions take; use the held-out
  slice; compare behaviour on canaries with behaviour on real submissions; audit sampling of accepted cases. Network
  isolation is likewise not provided by the wounder: probes must run in a sandbox clone or on a runner with egress
  blocked, because the command we run is code we chose, run with the operator's privileges.
- **W4 A text-level view of a semantic problem.** The reference gate and the mutation operators are textual. Operators
  work on a restricted statement shape and silently produce nothing for anything else; a near miss is presumed to differ in
  meaning and in rare cases will not, so a reported insensitivity needs a person's triage.
- **W5 Completeness is checked by the wounder, not by the statute.** The juridicator's manifest rule (R9) works per kind: it
  notices a declared kind that was never reported, not a case that was left out. Checked against the juridicator at
  3e70f62: a run missing one canary is still ACCEPT, and one canary that errored among passing ones only raises scrutiny one
  tier (T2), it does not hold the case. The wounder therefore refuses to mark a run directory `COMPLETE` unless every corpus
  case is reported, and `canary.missing_cases` is the check to use before publishing. Publish only complete directories.
- **W6 A crashing gate can look like a rejecting one.** Exit codes are the only protocol. The traceback and signal
  heuristics catch the common crashes; a gate that exits 1 on an internal error without a traceback will look like a
  rejection. Known-good cases catch the damage (such a gate rejects them too), but gates should use a distinct exit code
  for their own failures.
- **W7 Proposed cases still pass through a tired reviewer.** Quarantine and validation make bad proposals harmless to run,
  not impossible to promote. Cases are kept tiny so review is quick, code owners review the pull request, and a case that
  reads like an evasion recipe is not promoted (`docs/ADVERSARIAL-SCOPE.md`).
- **W8 The salt holder can withhold the reveal.** Batches are fixed by the ledger (`lottery_book.py`) and unbatched verdicts
  are always audited, so grinding is prevented. A batch that never gets its reveal stays pending and is listed, but nothing
  forces the reveal (juridicator R3). The salt file is plain text on the operator's machine.
- **W9 The budget file is local and trusting.** It stops accidents and runaway loops, not someone with write access to the
  file. It is locked against concurrent processes on one machine (POSIX `flock`), not across machines.
- **W10 Identity and signing.** Records name `tengoku-wounder` as producer, but nothing proves it (juridicator R5). A
  compromised workflow could emit records in the wounder's name. Signed records are on the juridicator's roadmap.
- **W11 Platform assumptions.** Process-group kill, resource limits and file locks are POSIX; elsewhere those protections
  are absent, not emulated.

## What is not claimed

That a healthy canary run means the gate is correct. It means the gate still catches every defect we have thought to plant,
still accepts every good case we have thought to include, and that the evidence for both can be re-run by anyone.

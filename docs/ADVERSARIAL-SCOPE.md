# Scope: quality assurance for our own gate

The wounder is quality assurance for our own acceptance gate. It finds where the gate would wrongly accept a bad
submission, and it keeps the gate honest over time. It produces evidence about whether our gate behaves correctly. It is
not a toolkit for getting past anyone else's checks, and nothing in it is shaped like one.

## The hard scope

These are obeyed in code, not only stated here.

| Rule | How it is enforced |
| --- | --- |
| Only against gates we control. | A gate is a command or function the operator names. The wounder has no list of targets, no discovery, no URL handling. |
| Only on fixtures and sandbox clones we control. | Cases are written into a fresh temporary directory per run and removed afterwards. Corpus cases are validated: a few plain `.lean` files, small, safe names. |
| No live services, no third-party systems. | No module imports a network library (`tests/test_cli.py` checks every module). The runner starts commands with a scrubbed environment, no shell, a timeout, bounded output and a file-size limit. |
| No network while probes run. | The wounder does not use the network. The command it runs is not a sandbox, so isolation has to come from the machine: run probes in a sandbox clone or a runner with egress blocked (`SECURITY.md`, W3). |
| Evidence, not exploits. | Output is `tengoku-evidence/1` records: a claim, an outcome, the command that reproduces it. Fixtures state a defect *category* with the smallest example, a few lines each, not an elaborate chain. |
| Mostly deterministic. | Generators, mutation operators and seeded sampling. AI proposes at most variants and candidate cases, as quarantined data (`docs/AI-USE.md`). |
| No write access to anything that gates. | The wounder emits evidence files. Only the juridicator decides. The corpus is owned by people (CODEOWNERS). |

## What is out of scope

Probing a system we do not own or run. Finding a way past a check someone else operates. Anything that needs a live
service, a real credential, a real user's data or the open internet. Elaborate evasion chains: a canary shows that a
category of defect exists and that the gate must catch it; it is not a recipe, and a case that reads like one is not
promoted. Automatic "fixing" of a gate. Deciding whether content is accepted.

## Vocabulary, and why

The words are *probes*, *canaries* (planted-defect regression cases), *challenges*, *defects*, *sensitivity tests* and
*audit sampling*. They are testing words because that is what the work is: the same discipline as a regression suite, a
fault-injection test or a code audit's sample, applied to a gate we are responsible for. The vocabulary also keeps the code
honest about its direction: everything points at our own gate and at evidence, never at someone else's.

## What a fixture looks like

One JSON file per case in `corpus/`: `{id, category, description, expected: "reject"|"accept", why, files}`. The `why` says,
in one sentence, what a correct gate does and why. Categories: `axiom_declared`, `axiom_via_metaprogram`, `sorry_present`,
`sorry_hidden_in_term`, `native_decide_used`, `unsafe_or_implemented_by`, `vacuous_hypotheses`, `statement_type_drift`,
`shadowed_name`, `duplicate_statement`, `comment_hidden_directive` (a forbidden word only inside a comment, which must NOT
be rejected) and `known_good` (several, so that over-blocking is also detected).

`axiom_via_metaprogram` adds an axiom by calling Lean's declaration API from a command block, so the word "axiom" never
appears as a keyword. That is a documented Lean capability, and it is exactly why a purely textual gate is not enough: the
test suite asserts that the textual reference gate misses it, as it misses `vacuous_hypotheses` and `statement_type_drift`.
Those need semantic checks (which axioms the finished proof depends on; whether the hypotheses can hold together; whether
the statement still says what the source says).

The gate under test is shown only a case's files. It is never shown the expected verdict, the category or the id.

## Adding a defect category

1. Write the smallest example that shows the defect, and decide what a correct gate does with it (`expected`).
2. Add the category name to `CATEGORIES` in `wounder/canary.py` (and to `ACCEPT_CATEGORIES` if the right verdict is accept).
3. Add `corpus/<id>.json`. The file name is the case id. Keep it to a few lines.
4. Run the tests: `tests/test_canary.py` requires every category to have a case and every case to validate. If a
   text-level gate can or cannot catch it, add that to the "what a text gate sees" tests so the suite documents it.
5. Open a pull request. `/corpus/` and this document are owned by a person (CODEOWNERS); an AI may propose, not merge.

## How a person promotes a proposed canary

An AI proposer may suggest candidate cases (`propose_canaries`). They land in `proposed/` as `status: "proposed"` files,
which git ignores and `load_corpus` refuses to read. Nothing runs them. To promote one:

1. Read it. Is it tiny, is the category right, is the expected verdict right, does it show a category and not a chain?
   Run it by hand against a gate if in doubt.
2. `python3 -m wounder promote proposed/<file>.json --reviewed-by "Your Name" --new-id a_clear_name`. This validates the
   case exactly as any corpus case is, drops the proposal fields, refuses to overwrite, and removes the proposal.
3. Commit the new `corpus/<id>.json` in a pull request. Review by a code owner is the second look.

`promote` is called by nothing else; a test checks that the only caller in the package is the explicit CLI command.

## The red-team loop

A continuing process, not a one-off exercise. In order:

1. **Deterministic generators first.** The mutation operators (`mutate.py`) and the corpus cover what can be written down.
   Every operator has a stable id; every run is reproducible.
2. **AI proposes variants, as quarantined data.** Near-miss statements and candidate cases come back as inert strings,
   validated, never executed, never in the corpus (`ai_boundary.py`).
3. **A person promotes.** What is worth keeping becomes a corpus case by the steps above.
4. **The corpus grows.** More categories, more cases, a private held-out slice that is not published
   (`corpus-private/`, passed as a second `--corpus`), so a gate cannot overfit to what it has seen.
5. **Canaries become permanent regression tests.** They run on every change to the gate; the juridicator refuses to accept
   anything while the gate's health is unproven.
6. **A new real incident ALWAYS becomes a canary the same day.** No incident closes without its case in the corpus.

The founding example is the Leak verifier incident: an acceptance gate that never checked which axioms a proof depends on,
so a script declaring its own axiom was reported as fully verified. That incident is the reason `axiom_declared` is the
first canary, and `axiom_via_metaprogram` is its generalisation: the gate must look at what the proof depends on, not at
what the text says. A canary of that shape is how the gap would have shown up before anyone relied on the gate.

## Layers

A real pipeline has several gates, each responsible for different defects. `run-canaries --layer L` runs only the cases the
layer is responsible for, so a gate is judged on what it is for: `static` (a text lint, with no compiler), `axioms` (the
compile step's axiom collection, which is what sees a `sorry`), `vacuity`, `fidelity` and `tree` (a name shadowed or a
statement duplicated in the existing tree). The mapping is `LAYERS` in `wounder/canary.py`. Tengoku's content lint, for
example, rejects an axiom added by a metaprogram and does not read `sorry` at all, on purpose; the `axioms` layer owns that case.

## Agent-security canaries

The same discipline, pointed at the gates that contain our AI agents instead of the gates that accept their output.
[tengoku-warden](https://github.com/competemath/tengoku-warden) holds those gates: a secret scan for diffs and commit messages, the
scope check for what a push may touch, the untrusted-content prompt and the one-time verdict marker, the tool-policy checks and
the environment allowlist. A gate that nobody attacks is a gate nobody knows works, so the wounder plants a known defect in front
of each and checks that it is blocked, and plants known-good input to check that it is not over-blocked.

**Scope is unchanged, and it is the point.** This tests *our own* gates, the warden's, through copies vendored into
`vendor/warden/` and pinned to a commit (`vendor/warden/PIN`, with a test that fails on any drift), so the code under test is a
reviewed, named version and not whatever is installed. There is no live target: no network, no GitHub, no model, no real
credential. The cases that need a repository build a throwaway one in a temporary directory with every git configuration source
neutralised and delete it afterwards. Nothing here is a way past anyone else's checks.

| Piece | What it does | Evidence |
| --- | --- | --- |
| `wounder/agentsec.py` + `corpus-agent/` | one JSON case per planted defect or known-good input: `{id, category, description, expected: "block"\|"allow", input, why}`; the gates are the warden's functions called through the vendored copies | `mechanical.agent_canary`, one per case, manifest first (`python3 -m wounder agent-canaries --out DIR ...`) |
| `injection-eval` | records an injection-resistance run (the warden's 32 payloads against a reader backend the operator names, or an existing report) with the rates and their Wilson intervals | `mechanical.injection_eval` |
| `jail-selftest` | records the warden's escape battery for a jail or runner (an existing report written inside the jail, or `--run` there) | `mechanical.jail_selftest` |

**Categories**: `secret_in_diff`, `secret_in_commit_message`, `symlink_added`, `protected_path_touched`, `executable_bit`,
`append_only_rewritten`, `human_owned_reverted`, `forged_marker_in_evidence`, `malformed_findings`, `deny_list_only_spawn`,
`bypass_flag_without_tools`, `env_leak` (each expects `block`) and `known_good` (expects `allow`, one case per surface, so
over-blocking is noticed everywhere a gate can block). Each is a failure that Tau Ceti's public record shows, tested here against
the gate meant to prevent it; `wounder/agentsec.py` names the Tau Ceti finding behind each category. A planted case is the smallest
example of the category, a few lines, never a chain.

**Fixtures never contain a credential.** A value with the shape of a token is written in a case as a placeholder such as
`{{GITHUB_TOKEN}}` and built at run time by concatenation (`agentsec.fixture_values`). A test scans every file of the corpus with
the vendored secret scanner and requires that it finds nothing, and checks that the run-time values do have the shape a scanner
looks for. The gate under test is shown only the category and the input (values expanded), never the expected verdict or the id.

**How to read a result.** `pass`: the gate did what the case expects. `fail`: a missed block (the gate ALLOWED a planted defect) or
a wrongful block (the gate BLOCKED a known-good case). `inconclusive`: the gate crashed or gave no verdict, which is never a pass.
A gate that allows everything fails every block case and a gate that blocks everything fails every known-good case; the test suite
checks both, so the harness cannot go green on a dead gate. The test suite also checks that each block happens for the reason the
category names (`EXPECTED_REASON`), so a gate that blocks everything for the wrong reason is still noticed.

**Limits.** The cases are public, so they can be memorised (W2); a green run means no known category got through (W1); and it tests
the pinned copy of the warden, not what is deployed in a repository (W10 in `SECURITY.md`).

Adding a category follows the same steps as above: the smallest example, the expected verdict, a line in `CATEGORIES`/`SURFACES`/
`EXPECTED_REASON` in `wounder/agentsec.py`, a case file, and a pull request that a code owner reviews (`/corpus-agent/` is owned by
a person).

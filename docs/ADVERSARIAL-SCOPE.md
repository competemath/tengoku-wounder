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

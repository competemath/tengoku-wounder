# tengoku-wounder

Quality assurance for our own acceptance gate. One program in three repositories, for deciding whether AI-generated
content should be trusted into Tengoku:

| Repository | Role | One line |
| --- | --- | --- |
| **tengoku-wounder** (this one) | challenge | finds where our gate would wrongly accept a bad submission, and keeps the gate honest over time |
| [tengoku-praiser](https://github.com/competemath/tengoku-praiser) | credibility | gathers reasons to trust content that anyone can re-check |
| [tengoku-juridicator](https://github.com/competemath/tengoku-juridicator) | decision | weighs both with a fixed statute, history and a tightly leashed AI |

The wounder produces *evidence about whether our gate behaves correctly*. It never decides anything and has no write
access to anything that gates. It works only against gates we run ourselves, on fixtures and sandbox clones, with no live
service and no network. Read `docs/ADVERSARIAL-SCOPE.md` first: it states the scope and the reasons for it.

## What is in it

| Piece | What it does | Evidence it emits |
| --- | --- | --- |
| `wounder/canary.py` + `corpus/` | planted-defect regression suite: tiny fixtures per defect category, plus known-good cases so over-blocking is caught too | `mechanical.canary` (one per case), `manifest.declared` first |
| `wounder/agentsec.py` + `corpus-agent/` | planted-defect canaries for the **warden's** agent-security gates (secret scan, scope, prompt and marker, tool policy, environment), through vendored, pinned copies; plus `injection-eval` and `jail-selftest`, which record the warden's injection run and escape battery | `mechanical.agent_canary` (one per case), `mechanical.injection_eval`, `mechanical.jail_selftest`; manifest first |
| `wounder/mutate.py` | deterministic near-miss generators for formal statements (a type, an inequality, a quantifier, a literal, a dropped hypothesis) | none by itself |
| `wounder/sensitivity.py` | asks the statement-fidelity check whether each near miss still "means the same"; it should say no | `mechanical.sensitivity` |
| `wounder/sampler.py` | audit lottery: which accepted cases get a human look, with a commit-then-reveal salt (`docs/AUDIT-LOTTERY.md`) | none (a yes/no for the ledger) |
| `wounder/budget.py` | spend and round caps, reserved before anything is spent | none |
| `wounder/ai_boundary.py` | the only place AI touches the wounder, and only as quarantined data (`docs/AI-USE.md`) | none |

Most of the "intelligence" is deterministic: generators, mutation operators, seeded sampling. No AI is called by any
default code path or test; no backend is wired in.

## Use

```bash
# run the canaries against a gate we control; evidence goes to out/, manifest first
python3 -m wounder run-canaries --corpus corpus --gate-cmd "/abs/path/to/our-gate" \
    --repo competemath/tengoku-sandbox --head <40-hex sha> --class gate --out out/canaries

# try the harness with the built-in text-level reference gate (it misses the semantic defects on purpose)
python3 -m wounder run-canaries --corpus corpus --reference-gate --repo r --head <40-hex sha> --class gate --out out/ref

# test the warden's agent-security gates with planted defects (docs/ADVERSARIAL-SCOPE.md, "Agent-security canaries")
python3 -m wounder agent-canaries --repo competemath/tengoku-sandbox --head <40-hex sha> --class gate --out out/agent
# record an injection-resistance run or an escape battery that the warden produced
python3 -m wounder injection-eval --report-file report.json --target reviewer --model <model> --repo r --head <sha> --class gate --out out/inj
python3 -m wounder jail-selftest --report-file selftest.json --target runner-1 --repo r --head <sha> --class gate --out out/jail

# probe the statement-fidelity check with near misses
python3 -m wounder sensitivity --statement-file statement.txt --oracle-cmd "/abs/path/to/fidelity-check" \
    --repo r --head <sha> --class gate --out out/sens

# declare, before running, what will be reported (then use --no-manifest on the runs)
python3 -m wounder manifest --checks mechanical.canary mechanical.sensitivity --repo r --head <sha> --class gate --out out/m

# audit lottery with a committed salt
python3 -m wounder lottery new-salt --out salt.txt          # prints the commitment to publish
python3 -m wounder lottery select --salt-file salt.txt --head <sha> --tier 1 --commitment <published>

# a person promotes a reviewed, machine-proposed case into the corpus
python3 -m wounder promote proposed/<file>.json --reviewed-by "Your Name" --new-id some_good_name

python3 -W error::ResourceWarning -m unittest discover -s tests
python3 scripts/mutation_check.py          # breaks key lines one at a time; every mutation must be killed
```

Exit code 0 means the evidence was written, 2 means bad input. **A failed canary never changes the exit code**: a failure
is evidence for the judge, not a crash. A run directory is complete only if it holds a `COMPLETE` file.

The gate command is run as `<command> <directory>`: the directory holds the case's `.lean` files; exit 0 means accepted,
nonzero rejected. A timeout, a crash (signal, exit 126/127, a Python traceback) is an error, counted as inconclusive and
never as a pass. Use absolute paths in `--gate-cmd`, because the command runs from a scratch directory.

## The contract

The only thing shared with the other repositories is the evidence record. `vendor/juridicator_evidence.py` is a verbatim
copy of the juridicator's `juridicator/evidence.py`, pinned in `vendor/EVIDENCE.sha256` to a juridicator commit; a test
fails if the copy and the pin disagree. Refresh both with `python3 scripts/sync_contract.py --from ../tengoku-juridicator`.

The agent-security canaries also vendor nine modules of [tengoku-warden](https://github.com/competemath/tengoku-warden) byte for byte into
`vendor/warden/`, pinned in `vendor/warden/PIN` to a warden commit; refresh with `python3 scripts/sync_warden.py --from ../tengoku-warden`.
Import it as `from vendor.juridicator_evidence import make_evidence, validate`.

## Documents

`docs/ADVERSARIAL-SCOPE.md` scope, vocabulary, the red-team loop, agent-security canaries · `docs/AUDIT-LOTTERY.md` sampling and commit-reveal ·
`docs/AI-USE.md` what the wounder's AI may and may not do · `SECURITY.md` residual risks specific to the wounder.

Standard library only, Python 3.12 or newer, no network. The code that runs commands uses POSIX process groups and
resource limits where present.

## Status

A working seed: the harness, the ledger-fixed audit lottery (`lottery plan`) and their tests are real; the corpus is small by
design; the real gates, the sandbox runner and any AI backend are not wired in. The whole flow is in the juridicator's
`docs/PIPELINE.md`. Apache-2.0.

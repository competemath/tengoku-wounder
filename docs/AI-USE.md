# How AI is used in the wounder

The rules are the program's, written in the juridicator's `docs/AI-USE.md`
(https://github.com/competemath/tengoku-juridicator/blob/main/docs/AI-USE.md). This page applies them to the wounder and
lists exactly what its AI may and may not do. Short version: by default there is no AI at all; the only AI surface is a
quarantined data interface.

## What the wounder's AI may do

* **Propose near-miss variants of a formal statement** (`ai_boundary.propose_variants`): up to 8 one-line strings.
* **Propose candidate canary cases** (`ai_boundary.propose_canaries`): up to 3 tiny corpus entries for one named defect
  category, written into the `proposed/` quarantine.

Both come back as **data only**.

## How it is contained (each item is enforced by code and has a test)

1. **No tools.** A proposer that exposes any tool is refused before it is called (`ToolsNotAllowed`). The tool set itself is
   read, not a flag.
2. **Budget first.** Every call is reserved against a `Budget` (daily cap, per-case round cap) before it is made. Over budget
   raises before anything is asked. An unreadable reply still costs its round.
3. **One-time marker, fail closed.** A fresh random marker per call; only the text after the last marker is parsed; no marker,
   bad JSON or the wrong shape means "no answer". Anything planted earlier is discarded.
4. **Validated field by field.** Variants must be printable single lines of at most 400 characters, contain no marker-shaped
   text, differ from the original, be unique, and be few. Candidate cases go through the same `validate_case` as the corpus
   (known category, the right expected verdict for that category, plain small `.lean` files). Failures are dropped and
   counted, never repaired.
5. **Never executed, never in the corpus.** The module imports nothing that could run text (checked by a test). Candidates
   are written only into a directory named `proposed/`, with `status: "proposed"`. `load_corpus` refuses that directory by
   name, and a proposal copied into the corpus unreviewed fails validation because of its extra fields.
6. **A person promotes.** `promote` moves a reviewed candidate into `corpus/`. It needs a named reviewer, only takes files
   from a `proposed/` directory, never overwrites, and is called by nothing but the explicit CLI command.
7. **Labelled.** The result carries an `ai` label (`used: true`, `role: proposer`, model, family, a hash of the prompt
   template) that fits the evidence record's `ai` field, so any record built from a proposal says so.

## What it may not do

Decide that a proof is valid, that a statement is faithful, that a gate passed or failed, or that anything is accepted.
Write to the corpus, the policy, the statute or any rubric. Run, compile or evaluate anything it produced. Read raw
untrusted text (only a statement the operator chose, after a marker-shape check). Choose which evidence the judge sees.
Reach the network, a credential or a tool. Grade its own proposals or those of its own model family. Spend beyond the cap.

## What is deliberately absent

No AI backend is wired in. There is no CLI command that calls one. Nothing in a test, a default path or CI calls an AI. A
real backend would implement the small `Proposer` protocol (`model`, `family`, `tools == ()`, `complete(prompt)`) in the
operator's own wrapper, behind the juridicator's rules and the budget above.

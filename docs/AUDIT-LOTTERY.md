# The audit lottery

Every case the juridicator decides gets a scrutiny tier 0 to 3. The tier sets the chance that the case is audited later by
a person: 5%, 20%, 50% and 100%. Auditing a sample is how we learn whether accepted content was really good, and it is only
worth anything if the sample cannot be dodged.

## The rule

```
draw     = HMAC-SHA256(salt, head_sha), first 8 bytes as an integer, divided by 2**64      in [0, 1)
selected = draw < rate(tier)
```

* Deterministic: the same salt and commit always give the same answer, so anyone holding the salt can check every draw.
* Tier 3 is always selected, whatever the configured rates say.
* The tier is clamped to 0..3.
* The rate never falls below 2% and never exceeds 100%, so no policy file can configure a tier into never being audited.
* A salt shorter than 16 bytes, or a commit that is not 40 hex characters, is an error.

## The grinding problem

If the author can learn the salt before pushing, they can compute the draw for a candidate commit and keep adjusting it (a
whitespace edit, a comment) until the draw lands above the rate, then submit that commit. Auditing then catches only the
authors who do not try. A public formula with a fixed, known salt is therefore not enough.

## The fix: commit, then reveal

1. Before any case in a batch is judged, generate a fresh salt (`lottery new-salt`) and publish **only its commitment**
   (`commit_salt(salt)`, a domain-separated SHA-256 of the salt) in the juridicator's ledger.
2. The author can see the commitment. It reveals nothing about any draw, and the salt cannot be changed afterwards because
   the hash is already public.
3. Judge the batch. After it, reveal the salt. Anyone runs `verify_salt(commitment, salt)` and recomputes every draw.

Which batch a commit belongs to has to be fixed by the ledger (the order of entries), not by the author. If an author could
choose to be judged in a later batch whose salt is still hidden, they would gain nothing by grinding; if they could choose
an earlier, already revealed one, they would. So: no case is judged under a salt that has been revealed.

## What is shipped, and what is not

Shipped: `draw`, `select_for_audit`, `commit_salt`, `verify_salt`, `new_salt`, the CLI (`lottery new-salt | commit | select`)
and tests for determinism, independence from other salts, the empirical rate at every tier over 20,000 commits, tier 3,
clamping, the floor, and tampering with the commitment.

Not shipped: the publication step (writing the commitment into the ledger before a batch, and the reveal after), and the
custody of the salt between the two. Until that exists the lottery is only as good as the discipline around the salt file
(it is created with mode 0600 and never overwritten). This is the juridicator's residual risk R3.

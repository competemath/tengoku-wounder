"""The publication half of the audit lottery: batches are fixed by the ledger, not by the author or the operator.

The ledger (juridicator `Ledger`, entries `{seq, kind, body, prev, hash}`) carries three kinds this module reads:

  lottery_commit   body {"commitment": commit_salt(salt)}     opens a batch
  verdict          body is a tengoku-verdict/1                joins the batch that is open when it is written
  lottery_reveal   body {"salt": salt}                        closes the batch and makes every draw recomputable

A verdict written while no batch is open is *unbatched*: nobody committed to a salt for it, so it cannot be sampled
fairly and is flagged for a person to look at (it never silently escapes the lottery). A reveal whose salt does not
match its commitment, a second commit while a batch is still open, or a reveal with nothing open are problems, reported
and never papered over. Only ACCEPT verdicts are sampled: every other decision already gets a person's attention.

Residual risk, stated plainly: whoever holds the salt can withhold the reveal. A batch left open is reported as pending,
and `plan` lists it so that a missing reveal is itself visible. Pure function of the ledger entries; no files, no clock.
"""

from __future__ import annotations

from . import sampler


def audit_plan(entries: list[dict], rates: tuple[float, ...] = sampler.DEFAULT_RATES) -> dict:
    batches: list[dict] = []
    unbatched: list[dict] = []
    problems: list[str] = []
    open_batch: dict | None = None

    for e in entries:
        kind, body, seq = e.get("kind"), e.get("body") or {}, e.get("seq")
        if kind == "lottery_commit":
            commitment = body.get("commitment")
            if not isinstance(commitment, str) or len(commitment) != 64:
                problems.append(f"entry {seq}: a lottery commit without a 64-hex commitment is ignored")
                continue
            if open_batch is not None:
                problems.append(f"entry {seq}: a commit while the batch opened at entry {open_batch['opened_at']} is still unrevealed")
            open_batch = {"opened_at": seq, "commitment": commitment, "revealed_at": None, "status": "pending", "cases": []}
            batches.append(open_batch)
        elif kind == "lottery_reveal":
            if open_batch is None:
                problems.append(f"entry {seq}: a reveal with no open batch is ignored")
                continue
            salt = body.get("salt")
            try:
                good = sampler.verify_salt(open_batch["commitment"], salt)
            except (TypeError, ValueError):
                good = False
            if not good:
                problems.append(f"entry {seq}: the revealed salt does not match the commitment at entry {open_batch['opened_at']}")
                open_batch["status"] = "bad-reveal"
                open_batch = None
                continue
            open_batch["status"], open_batch["revealed_at"] = "revealed", seq
            for case in open_batch["cases"]:
                case["selected"] = sampler.select_for_audit(case["head_sha"], salt, case["tier"], rates)
            open_batch = None
        elif kind == "verdict":
            if body.get("decision") != "ACCEPT":
                continue
            head = ((body.get("case") or {}).get("head_sha"))
            tier = body.get("tier")
            if not isinstance(head, str) or isinstance(tier, bool) or not isinstance(tier, int):
                problems.append(f"entry {seq}: an ACCEPT verdict without a commit or tier cannot be sampled")
                continue
            item = {"entry": seq, "head_sha": head, "tier": tier, "selected": None}
            if open_batch is None:
                unbatched.append(item)
            else:
                open_batch["cases"].append(item)

    must_audit = sorted(
        {c["head_sha"] for b in batches if b["status"] == "revealed" for c in b["cases"] if c["selected"]}
        | {c["head_sha"] for c in unbatched}
        | {c["head_sha"] for b in batches if b["status"] == "bad-reveal" for c in b["cases"]}
    )
    return {"batches": batches, "unbatched": unbatched, "problems": problems, "must_audit": must_audit,
            "pending": sorted({c["head_sha"] for b in batches if b["status"] == "pending" for c in b["cases"]})}

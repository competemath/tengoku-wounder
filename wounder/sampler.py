"""The audit lottery: which accepted cases get a second, human look.

The juridicator gives every case a scrutiny tier 0..3 and a base audit rate (5%, 20%, 50%, 100%). This module turns
(commit, secret salt, tier) into a yes/no that nobody can predict without the salt and everybody can recompute with it:

    draw = HMAC-SHA256(salt, head_sha), first 8 bytes read as an integer, divided by 2**64      -> a number in [0, 1)
    selected = draw < rate(tier)

THE GRINDING PROBLEM. If the salt were known to the author before they push, they could compute the draw for a candidate
commit and keep changing it (a whitespace edit, a comment) until the draw lands above the rate, then submit that commit.
Auditing would then catch only the authors who do not try. A public, fixed formula is not enough.

THE FIX, COMMIT AND REVEAL. Before any case in a batch is judged, publish `commit_salt(salt)` (a hash of the secret salt)
in the ledger. The author sees the commitment, which reveals nothing about the draws. After the batch is judged, reveal the
salt; anyone checks `verify_salt(commitment, salt)` and recomputes every draw. The salt cannot be changed after the fact
(the hash is already public) and could not be known while commits were being made. Which batch a commit belongs to must be
fixed by the ledger, not by the author; this version ships the functions and the rule, not the publication step
(juridicator SECURITY.md R3). See docs/AUDIT-LOTTERY.md.

Rules fixed here: tier 3 is always selected; the tier is clamped to 0..3; the rate never falls below 2% whatever a policy
file says, so no tier can be configured into never being audited.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import re
import secrets

DEFAULT_RATES = (0.05, 0.20, 0.50, 1.00)
RATE_FLOOR = 0.02
MIN_SALT_BYTES = 16
SHA40 = re.compile(r"^[0-9a-f]{40}$")
COMMIT_DOMAIN = b"tengoku-wounder/audit-salt/1\x00"


def new_salt() -> str:
    """A fresh 256-bit salt as hex."""
    return secrets.token_hex(32)


def _salt_bytes(salt: str | bytes) -> bytes:
    raw = salt.encode("utf-8") if isinstance(salt, str) else bytes(salt)
    if len(raw) < MIN_SALT_BYTES:
        raise ValueError(f"the salt must be at least {MIN_SALT_BYTES} bytes")
    return raw


def draw(head_sha: str, salt: str | bytes) -> float:
    """The case's number in [0, 1). Deterministic in (salt, head_sha)."""
    if not isinstance(head_sha, str) or not SHA40.match(head_sha):
        raise ValueError("head_sha must be a 40-hex commit")
    digest = hmac.new(_salt_bytes(salt), head_sha.encode("ascii"), hashlib.sha256).digest()
    return int.from_bytes(digest[:8], "big") / 2**64


def clamp_tier(tier: int) -> int:
    if isinstance(tier, bool) or not isinstance(tier, int):
        raise TypeError("tier must be an integer")
    return max(0, min(3, tier))


def effective_rate(tier: int, rates: tuple[float, ...] = DEFAULT_RATES) -> float:
    t = clamp_tier(tier)
    if len(rates) != 4 or not all(isinstance(r, (int, float)) and not isinstance(r, bool) and math.isfinite(r) for r in rates):
        raise ValueError("rates must be four finite numbers")
    return min(1.0, max(RATE_FLOOR, float(rates[t])))


def select_for_audit(head_sha: str, salt: str | bytes, tier: int, rates: tuple[float, ...] = DEFAULT_RATES) -> bool:
    if clamp_tier(tier) == 3:
        _salt_bytes(salt)  # a bad salt is still an error at tier 3, so a misconfiguration is not hidden by the shortcut
        return True
    return draw(head_sha, salt) < effective_rate(tier, rates)


def commit_salt(salt: str | bytes) -> str:
    """The value to publish in the ledger before cases are judged."""
    return hashlib.sha256(COMMIT_DOMAIN + _salt_bytes(salt)).hexdigest()


def verify_salt(commitment: str, salt: str | bytes) -> bool:
    try:
        expected = commit_salt(salt)
    except (ValueError, TypeError):
        return False
    return isinstance(commitment, str) and hmac.compare_digest(expected, commitment.strip().lower())

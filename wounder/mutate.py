"""Near-miss generators for formal statements: small, deterministic text edits that change what a statement says.

A sensitivity test (sensitivity.py) asks the pipeline's statement-fidelity check whether each near miss still means the
same as the original. It should not. Every operator here is a pure function of a restricted statement string, such as
`theorem foo (a b : ℕ) (h : a ≤ b) : ∀ x : ℕ, x + a ≤ x + b`. They are text edits, not a Lean parser: they work on the
restricted shape above (unicode symbols, binders in parentheses, hypotheses named h, h1, hab...) and quietly produce
nothing for anything else. Counting is left to right and 0-based. Each operator has a stable id such as `le_lt_toggle:1`.

A near miss is *presumed* to differ in meaning. In rare cases it will not (a toggle on a redundant clause), so a person
triages a reported insensitivity before acting on it.
"""

from __future__ import annotations

import re
from typing import Callable

NAT_WORD = re.compile(r"(?<![\w.'])Nat(?![\w.'])")
CMP = re.compile(r"(?<![-=<|$*>;])(<=|>=|≤|≥|<|>)(?![-;|$*>=])")
QUANT = re.compile(r"∀|∃(?!!)")
LITERAL = re.compile(r"(?<![\w.'])[0-9]+(?![\w.'])")
HYP_NAMES = re.compile(r"^h[\w']*(?:\s+h[\w']*)*\s*:")
TOGGLE = {"≤": "<", "<=": "<", "<": "≤", "≥": ">", ">=": ">", ">": "≥"}
FLIP = {"≤": "≥", "<=": ">=", "<": ">", "≥": "≤", ">=": "<=", ">": "<"}
DELTAS = (1, -1)


def _replace_nth(pattern: re.Pattern, text: str, k: int, make: Callable[[re.Match], str]) -> str | None:
    for index, m in enumerate(pattern.finditer(text)):
        if index == k:
            return text[:m.start()] + make(m) + text[m.end():]
    return None


def head_colon(statement: str) -> int:
    """Index of the first `:` outside any bracket that is not part of `:=`, or -1."""
    depth = 0
    for i, ch in enumerate(statement):
        if ch in "([{⟨":
            depth += 1
        elif ch in ")]}⟩":
            depth = max(0, depth - 1)
        elif ch == ":" and depth == 0 and statement[i + 1:i + 2] != "=":
            return i
    return -1


def hypothesis_spans(statement: str) -> list[tuple[int, int]]:
    """(start, end) of each top-level `(h... : ...)` binder before the statement's own colon."""
    stop = head_colon(statement)
    limit = len(statement) if stop < 0 else stop
    spans, depth, start = [], 0, -1
    for i in range(limit):
        ch = statement[i]
        if ch in "([{⟨":
            if depth == 0 and ch == "(":
                start = i
            depth += 1
        elif ch in ")]}⟩":
            depth = max(0, depth - 1)
            if depth == 0 and ch == ")" and start >= 0:
                if HYP_NAMES.match(statement[start + 1:i].strip()):
                    spans.append((start, i + 1))
                start = -1
    return spans


def nat_to_int(statement: str) -> str | None:
    out = NAT_WORD.sub("Int", statement.replace("ℕ", "ℤ"))
    return out if out != statement else None


def nat_to_real(statement: str) -> str | None:
    out = NAT_WORD.sub("Real", statement.replace("ℕ", "ℝ"))
    return out if out != statement else None


def le_lt_toggle(statement: str, k: int = 0) -> str | None:
    return _replace_nth(CMP, statement, k, lambda m: TOGGLE[m.group(1)])


def drop_hypothesis(statement: str, i: int = 0) -> str | None:
    spans = hypothesis_spans(statement)
    if not 0 <= i < len(spans):
        return None
    a, b = spans[i]
    return re.sub(r"[ \t]{2,}", " ", statement[:a].rstrip() + " " + statement[b:].lstrip()).strip()


def swap_quantifier(statement: str, k: int = 0) -> str | None:
    return _replace_nth(QUANT, statement, k, lambda m: "∃" if m.group(0) == "∀" else "∀")


def shift_literal(statement: str, k: int = 0, delta: int = 1) -> str | None:
    def make(m: re.Match) -> str:
        return str(int(m.group(0)) + delta) if int(m.group(0)) + delta >= 0 else m.group(0)

    out = _replace_nth(LITERAL, statement, k, make)
    return out if out != statement else None


def flip_direction(statement: str) -> str | None:
    """Turn the first comparison of the conclusion (or, failing that, of the statement) around: `a ≤ b` becomes `a ≥ b`."""
    stop = head_colon(statement)
    for start in ([stop + 1, 0] if stop >= 0 else [0]):
        m = CMP.search(statement, start)
        if m:
            return statement[:m.start()] + FLIP[m.group(1)] + statement[m.end():]
    return None


def count(statement: str, operator: str) -> int:
    """How many places an indexed operator can be applied (its parameter ranges over 0..count-1)."""
    if operator == "le_lt_toggle":
        return len(CMP.findall(statement))
    if operator == "drop_hypothesis":
        return len(hypothesis_spans(statement))
    if operator == "swap_quantifier":
        return len(QUANT.findall(statement))
    if operator == "shift_literal":
        return len(LITERAL.findall(statement))
    return 1


def apply_operator(statement: str, operator_id: str) -> str | None:
    """Apply an operator by its stable id (`nat_to_int`, `le_lt_toggle:2`, `shift_literal:0:-1`). None when it does not apply."""
    name, *args = operator_id.split(":")
    try:
        nums = [int(a) for a in args]
    except ValueError:
        return None
    simple = {"nat_to_int": nat_to_int, "nat_to_real": nat_to_real, "flip_direction": flip_direction}
    if name in simple and not nums:
        return simple[name](statement)
    indexed = {"le_lt_toggle": le_lt_toggle, "drop_hypothesis": drop_hypothesis, "swap_quantifier": swap_quantifier}
    if name in indexed and len(nums) == 1 and nums[0] >= 0:
        return indexed[name](statement, nums[0])
    if name == "shift_literal" and len(nums) == 2 and nums[0] >= 0:
        return shift_literal(statement, nums[0], nums[1])
    return None


def operator_ids(statement: str) -> list[str]:
    """Every operator id worth trying on this statement, in a fixed order."""
    ids = ["nat_to_int", "nat_to_real"]
    ids += [f"le_lt_toggle:{k}" for k in range(count(statement, "le_lt_toggle"))]
    ids += [f"drop_hypothesis:{i}" for i in range(count(statement, "drop_hypothesis"))]
    ids += [f"swap_quantifier:{k}" for k in range(count(statement, "swap_quantifier"))]
    ids += [f"shift_literal:{k}:{d}" for k in range(count(statement, "shift_literal")) for d in DELTAS]
    ids.append("flip_direction")
    return ids


def _norm(text: str) -> str:
    return " ".join(text.split())


def near_misses(statement: str, limit: int = 50) -> list[tuple[str, str]]:
    """Ordered (operator_id, variant) pairs, each variant different from the statement, duplicates removed."""
    if not isinstance(statement, str) or not statement.strip():
        raise ValueError("a statement is required")
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
        raise ValueError("limit must be a non-negative integer")
    seen = {statement, _norm(statement)}
    out: list[tuple[str, str]] = []
    for op in operator_ids(statement):
        if len(out) >= limit:
            break
        variant = apply_operator(statement, op)
        if variant is None or _norm(variant) in seen:
            continue
        seen.add(variant)
        seen.add(_norm(variant))
        out.append((op, variant))
    return out

"""The one-time reply marker, for the wounder's AI boundary (the idea comes from the juridicator's marker.py).

Before a proposer sees any text, a fresh random marker is made and the proposer is told to print it, then its answer.
Only what follows the LAST occurrence of the marker is parsed, so anything planted earlier (a forged marker, a ready-made
answer) is discarded. Parsing fails closed: a missing marker or malformed JSON means "no answer", never a default.
Marker-shaped text of either family (this module's PROPOSAL-... or the juridicator's VERDICT-...) is also what the
validators refuse to let through inside a statement or a variant.
"""

from __future__ import annotations

import json
import re
import secrets

MARKER_RE = re.compile(r"(?:PROPOSAL|VERDICT)-[0-9a-f]{32}")


def new_marker() -> str:
    return "PROPOSAL-" + secrets.token_hex(16)


def instructions(marker: str) -> str:
    return (
        "When you have finished, print this exact line on its own: "
        f"{marker}\nThen, immediately after it, print one JSON object and nothing else. "
        "Text before that line is ignored."
    )


def has_marker_like_text(text: str) -> bool:
    return bool(MARKER_RE.search(text))


def extract(text: str, marker: str) -> dict | None:
    """The JSON object after the last marker, or None. The caller checks the object's shape."""
    if not isinstance(text, str) or not isinstance(marker, str) or not MARKER_RE.fullmatch(marker):
        return None
    at = text.rfind(marker)
    if at < 0:
        return None
    rest = text[at + len(marker):].lstrip()
    try:
        obj, _ = json.JSONDecoder().raw_decode(rest)
    except ValueError:
        return None
    return obj if isinstance(obj, dict) else None

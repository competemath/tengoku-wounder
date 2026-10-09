"""Refresh the vendored copy of the juridicator's evidence contract and its pin.

    python3 scripts/sync_contract.py --from ../tengoku-juridicator

Copies juridicator/evidence.py byte for byte to vendor/juridicator_evidence.py and rewrites vendor/EVIDENCE.sha256 with its
hash and the juridicator commit it came from. Refuses a checkout whose evidence.py differs from its own HEAD, so the pin
always names a commit that really contains these bytes. Never edit the vendored copy by hand.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE_REL = os.path.join("juridicator", "evidence.py")
VENDOR_REL = os.path.join("vendor", "juridicator_evidence.py")
PIN_REL = os.path.join("vendor", "EVIDENCE.sha256")
PIN_LINE = re.compile(r"^([0-9a-f]{64})  juridicator/evidence\.py  # tengoku-juridicator ([0-9a-f]{40})$")


def sha256_file(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def read_pin(root: str = ROOT) -> tuple[str, str]:
    """(sha256, juridicator commit) from the pin file; ValueError when the line is not exactly the expected shape."""
    with open(os.path.join(root, PIN_REL), encoding="utf-8") as fh:
        lines = [line for line in fh.read().splitlines() if line.strip()]
    if len(lines) != 1 or not PIN_LINE.match(lines[0]):
        raise ValueError("vendor/EVIDENCE.sha256 must hold exactly one pin line")
    m = PIN_LINE.match(lines[0])
    return m.group(1), m.group(2)


def verify(root: str = ROOT) -> list[str]:
    """Reasons the vendored copy no longer matches its pin. Empty means it matches."""
    try:
        expected, _ = read_pin(root)
    except (OSError, ValueError) as exc:
        return [f"pin unreadable: {exc}"]
    path = os.path.join(root, VENDOR_REL)
    if not os.path.isfile(path):
        return ["vendor/juridicator_evidence.py is missing"]
    actual = sha256_file(path)
    return [] if actual == expected else [f"vendored copy hashes to {actual}, the pin says {expected}"]


def _git(source: str, *args: str) -> str:
    return subprocess.run(["git", "-C", source, *args], check=True, capture_output=True, text=True).stdout.strip()


def sync(source: str, dest_root: str = ROOT, commit: str | None = None) -> dict:
    """Copy and re-pin. `commit` is for tests; normally it is read from the checkout, which must be clean for evidence.py."""
    src = os.path.join(source, SOURCE_REL)
    if not os.path.isfile(src):
        raise SystemExit(f"{src} not found: --from must be a tengoku-juridicator checkout")
    if commit is None:
        try:
            commit = _git(source, "rev-parse", "HEAD")
            if _git(source, "status", "--porcelain", "--", SOURCE_REL):
                raise SystemExit("evidence.py has uncommitted changes in the juridicator checkout; commit it there first")
        except (OSError, subprocess.CalledProcessError) as exc:
            raise SystemExit(f"cannot read the juridicator commit ({type(exc).__name__}); is --from a git checkout?")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise SystemExit("the juridicator commit is not a 40-hex sha")
    os.makedirs(os.path.join(dest_root, "vendor"), exist_ok=True)
    shutil.copyfile(src, os.path.join(dest_root, VENDOR_REL))
    init = os.path.join(dest_root, "vendor", "__init__.py")
    if not os.path.exists(init):
        open(init, "w").close()
    digest = sha256_file(os.path.join(dest_root, VENDOR_REL))
    with open(os.path.join(dest_root, PIN_REL), "w", encoding="utf-8") as fh:
        fh.write(f"{digest}  juridicator/evidence.py  # tengoku-juridicator {commit}\n")
    return {"sha256": digest, "commit": commit}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--from", dest="source", required=True, help="path to a tengoku-juridicator checkout")
    args = ap.parse_args(argv)
    result = sync(args.source)
    print(f"vendored evidence.py at juridicator {result['commit']} (sha256 {result['sha256']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

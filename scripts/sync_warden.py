"""Refresh the vendored copies of tengoku-warden modules and their pin.

    python3 scripts/sync_warden.py --from ../tengoku-warden

Copies the modules named in FILES from warden/ to vendor/warden/ byte for byte and rewrites vendor/warden/PIN with the warden
commit and the sha-256 of every file. Refuses a checkout whose copies of those files differ from its own HEAD, so the pin always
names a commit that really contains these bytes. Never edit a vendored copy by hand; change it in tengoku-warden first.
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
FILES = ("__init__.py", "untrusted.py", "verdict.py", "secretscan.py", "scope.py", "toolpolicy.py", "envscrub.py", "injection_eval.py", "selftest.py")
SOURCE_DIR = "warden"
VENDOR_DIR = os.path.join("vendor", "warden")
PIN_REL = os.path.join(VENDOR_DIR, "PIN")
PIN_HEAD = re.compile(r"^# tengoku-warden ([0-9a-f]{40})$")
PIN_LINE = re.compile(r"^([0-9a-f]{64})  warden/([a-z_]+\.py)$")


def sha256_file(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def read_pin(root: str = ROOT) -> tuple[str, dict[str, str]]:
    """(warden commit, {file name: sha256}); ValueError when the pin is not exactly the expected shape."""
    with open(os.path.join(root, PIN_REL), encoding="utf-8") as fh:
        lines = [line for line in fh.read().splitlines() if line.strip()]
    if not lines or not PIN_HEAD.match(lines[0]):
        raise ValueError("the first line of vendor/warden/PIN must be '# tengoku-warden <40-hex commit>'")
    files: dict[str, str] = {}
    for line in lines[1:]:
        m = PIN_LINE.match(line)
        if not m or m.group(2) in files:
            raise ValueError(f"bad or repeated pin line: {line[:60]!r}")
        files[m.group(2)] = m.group(1)
    if set(files) != set(FILES):
        raise ValueError("the pin must list exactly: " + ", ".join(FILES))
    return PIN_HEAD.match(lines[0]).group(1), files


def verify(root: str = ROOT) -> list[str]:
    """Reasons the vendored copies no longer match their pin. Empty means they match."""
    try:
        _commit, pinned = read_pin(root)
    except (OSError, ValueError) as exc:
        return [f"pin unreadable: {exc}"]
    problems = []
    directory = os.path.join(root, VENDOR_DIR)
    for name in FILES:
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            problems.append(f"vendor/warden/{name} is missing")
        elif sha256_file(path) != pinned[name]:
            problems.append(f"vendor/warden/{name} hashes to {sha256_file(path)}, the pin says {pinned[name]}")
    extra = sorted(n for n in os.listdir(directory) if n not in FILES and n not in ("PIN", "__pycache__")) if os.path.isdir(directory) else []
    if extra:
        problems.append("unpinned files in vendor/warden: " + ", ".join(extra))
    return problems


def _git(source: str, *args: str) -> str:
    return subprocess.run(["git", "-C", source, *args], check=True, capture_output=True, text=True).stdout.strip()


def sync(source: str, dest_root: str = ROOT, commit: str | None = None) -> dict:
    """Copy and re-pin. `commit` is for tests; normally it is read from the checkout, whose files must be committed."""
    for name in FILES:
        if not os.path.isfile(os.path.join(source, SOURCE_DIR, name)):
            raise SystemExit(f"{source}/{SOURCE_DIR}/{name} not found: --from must be a tengoku-warden checkout")
    if commit is None:
        try:
            commit = _git(source, "rev-parse", "HEAD")
            if _git(source, "status", "--porcelain", "--", *[f"{SOURCE_DIR}/{n}" for n in FILES]):
                raise SystemExit("the vendored modules have uncommitted changes in the warden checkout; commit them there first")
        except (OSError, subprocess.CalledProcessError) as exc:
            raise SystemExit(f"cannot read the warden commit ({type(exc).__name__}); is --from a git checkout?")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise SystemExit("the warden commit is not a 40-hex sha")
    directory = os.path.join(dest_root, VENDOR_DIR)
    os.makedirs(directory, exist_ok=True)
    init = os.path.join(dest_root, "vendor", "__init__.py")
    if not os.path.exists(init):
        open(init, "w").close()
    digests = {}
    for name in FILES:
        shutil.copyfile(os.path.join(source, SOURCE_DIR, name), os.path.join(directory, name))
        digests[name] = sha256_file(os.path.join(directory, name))
    with open(os.path.join(dest_root, PIN_REL), "w", encoding="utf-8") as fh:
        fh.write(f"# tengoku-warden {commit}\n")
        for name in FILES:
            fh.write(f"{digests[name]}  warden/{name}\n")
    return {"commit": commit, "sha256": digests}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--from", dest="source", required=True, help="path to a tengoku-warden checkout")
    args = ap.parse_args(argv)
    result = sync(args.source)
    print(f"vendored {len(FILES)} warden modules at {result['commit']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Spend and round caps, enforced before anything is spent.

A budget is a small JSON file: today's date, what has been reserved today, and how many rounds each case has used.
`reserve` is called BEFORE an action that costs something (an AI call, a long probe). It either records the spend and
returns, or raises `BudgetExceeded` having changed nothing. The record is written to disk (atomically, under a lock)
before `reserve` returns, so a crash after the reservation cannot lose it; a crash before the action wastes at most one
reservation, which is the safe direction. Every allowed attempt counts, whether or not the action then succeeds.

The calendar day is supplied by the caller (`day="2026-10-09"`); nothing here reads the clock, so a run can be replayed and
a test never depends on the time. A day that moves backwards is refused rather than treated as a fresh allowance. A
state file that cannot be read is an error, never a silent reset to zero.
"""

from __future__ import annotations

import json
import math
import os
import re
import tempfile

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MAX_KEY = 200


class BudgetExceeded(RuntimeError):
    pass


class BudgetError(RuntimeError):
    """The budget file or an argument is unusable. Fails closed."""


class Budget:
    def __init__(self, path: str, daily_cap: float, per_case_rounds: int, *, day: str):
        _check_day(day)
        _check_number(daily_cap, "daily_cap", allow_zero=True)
        if isinstance(per_case_rounds, bool) or not isinstance(per_case_rounds, int) or per_case_rounds < 0:
            raise BudgetError("per_case_rounds must be a non-negative integer")
        self.path = path
        self.daily_cap = float(daily_cap)
        self.per_case_rounds = per_case_rounds
        self.day = day
        with self._locked():
            self._load()  # reading also validates an existing file now rather than at the first reserve

    # -- public

    def reserve(self, case_key: str, cost: float = 1.0) -> dict:
        if not isinstance(case_key, str) or not case_key or len(case_key) > MAX_KEY:
            raise BudgetError("case_key must be a non-empty string")
        _check_number(cost, "cost", allow_zero=True)
        with self._locked():
            state = self._load()
            rounds = state["rounds"].get(case_key, 0)
            if rounds + 1 > self.per_case_rounds:
                raise BudgetExceeded(f"case {case_key} has used its {self.per_case_rounds} rounds")
            if state["spent"] + cost > self.daily_cap:
                raise BudgetExceeded(f"today's cap of {self.daily_cap:g} would be passed")
            state["spent"] += cost
            state["rounds"][case_key] = rounds + 1
            self._save(state)  # persisted before the caller is allowed to act
            return {"spent_today": state["spent"], "case_rounds": rounds + 1}

    def spent_today(self) -> float:
        with self._locked():
            return self._load()["spent"]

    def rounds(self, case_key: str) -> int:
        with self._locked():
            return self._load()["rounds"].get(case_key, 0)

    # -- persistence

    def _lock_path(self) -> str:
        return self.path + ".lock"

    def _locked(self):
        return _Lock(self._lock_path())

    def _load(self) -> dict:
        try:
            with open(self.path, encoding="utf-8") as fh:
                raw = json.load(fh)
        except FileNotFoundError:
            return {"day": self.day, "spent": 0.0, "rounds": {}}
        except (OSError, ValueError) as exc:
            raise BudgetError(f"budget file unreadable ({type(exc).__name__}); refusing to start from zero") from exc
        try:
            day, spent, rounds = raw["day"], raw["spent"], raw["rounds"]
            _check_day(day)
            _check_number(spent, "spent", allow_zero=True)
            if not isinstance(rounds, dict) or not all(isinstance(k, str) and isinstance(v, int) and not isinstance(v, bool) and v >= 0
                                                       for k, v in rounds.items()):
                raise BudgetError("rounds is malformed")
        except (KeyError, TypeError, BudgetError) as exc:
            raise BudgetError("budget file malformed; refusing to start from zero") from exc
        if self.day < day:
            raise BudgetError(f"the supplied day {self.day} is before the recorded day {day}")
        if self.day > day:  # a new day: today's spend restarts, each case's rounds do not
            return {"day": self.day, "spent": 0.0, "rounds": dict(rounds)}
        return {"day": day, "spent": float(spent), "rounds": dict(rounds)}

    def _save(self, state: dict) -> None:
        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        fd, tmp = tempfile.mkstemp(prefix=".budget-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(state, fh, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


class _Lock:
    def __init__(self, path: str):
        self.path = path
        self.fh = None

    def __enter__(self):
        self.fh = open(self.path, "a+")
        if fcntl is not None:
            fcntl.flock(self.fh, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        try:
            if fcntl is not None:
                fcntl.flock(self.fh, fcntl.LOCK_UN)
        finally:
            self.fh.close()


def _check_day(day: object) -> None:
    if not isinstance(day, str) or not DAY.match(day):
        raise BudgetError("day must be a YYYY-MM-DD string supplied by the caller")


def _check_number(value: object, name: str, *, allow_zero: bool) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0 \
            or (value == 0 and not allow_zero):
        raise BudgetError(f"{name} must be a finite non-negative number")

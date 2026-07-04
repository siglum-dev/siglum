"""Verdict, coverage, independence, and validator-status enumerations.

Stable string values: they are serialized into the predicate and the decision hash,
so renaming a value is a breaking schema change.
"""
from __future__ import annotations

from enum import Enum


class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"


class Coverage(str, Enum):
    FULL = "FULL"
    INCOMPLETE = "INCOMPLETE"


class Independence(str, Enum):
    SATISFIED = "SATISFIED"
    UNMET = "UNMET"
    NOT_REQUIRED = "NOT_REQUIRED"


class ApprovalProof(str, Enum):
    PROVEN = "PROVEN"
    UNMET = "UNMET"
    NOT_REQUIRED = "NOT_REQUIRED"


class ValidatorStatus(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    ERRORED = "ERRORED"
    UNKNOWN = "UNKNOWN"


# A required validator with a definite status contributes to FULL coverage.
DEFINITE: frozenset[ValidatorStatus] = frozenset(
    {ValidatorStatus.PASSED, ValidatorStatus.FAILED}
)

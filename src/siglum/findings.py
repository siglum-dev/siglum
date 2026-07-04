"""Structured findings + a new/persistent/resolved diff across pushes.

STAGED CAPABILITY: fully tested, but no runtime consumer yet. The gate currently reports
validator status through the check-run summary; wiring per-finding reporting (a PR
comment naming individual issues, and dispositions acting on them) is roadmap work. The
diff is what will tell a reviewer "what's new since last push"."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True, slots=True)
class Finding:
    fingerprint: str          # stable id for the same issue across pushes
    rule_id: str              # e.g. "aws_access_key_id", "SIG-INDEPENDENCE-GAP"
    validator_id: str
    message: str
    severity: Severity = Severity.MEDIUM


@dataclass(frozen=True, slots=True)
class FindingDiff:
    new: tuple[Finding, ...]
    persistent: tuple[Finding, ...]
    resolved: tuple[Finding, ...]


def _sorted(findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
    return tuple(sorted(findings, key=lambda f: f.fingerprint))


def diff_findings(
    previous: tuple[Finding, ...], current: tuple[Finding, ...]
) -> FindingDiff:
    prev_fps = {f.fingerprint for f in previous}
    cur_fps = {f.fingerprint for f in current}
    new = _sorted(tuple(f for f in current if f.fingerprint not in prev_fps))
    persistent = _sorted(tuple(f for f in current if f.fingerprint in prev_fps))
    resolved = _sorted(tuple(f for f in previous if f.fingerprint not in cur_fps))
    return FindingDiff(new=new, persistent=persistent, resolved=resolved)

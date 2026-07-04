"""Surface an Assessment's coverage gaps and independence state as structured Findings,
so dispositions (apply_dispositions) and the cannot-override class (override.py) have
concrete issues to act on. The rule_ids here are exactly the ones CANNOT_OVERRIDE_RULES
checks. STAGED CAPABILITY: tested, but not called by the runtime gate today (see
findings.py); it becomes live when per-finding reporting is wired."""
from __future__ import annotations

from siglum.findings import Finding, Severity
from siglum.models import Assessment
from siglum.verdict import Independence

COVERAGE_GAP_RULE = "SIG-COVERAGE-GAP"
INDEPENDENCE_GAP_RULE = "SIG-INDEPENDENCE-GAP"


def derive_findings(assessment: Assessment) -> tuple[Finding, ...]:
    out: list[Finding] = []
    for g in assessment.coverage_gaps:
        out.append(
            Finding(
                fingerprint=f"{COVERAGE_GAP_RULE}:{g.validator_id}",
                rule_id=COVERAGE_GAP_RULE,
                validator_id=g.validator_id,
                message=f"validator '{g.validator_id}' did not provide full coverage: {g.reason}",
                severity=Severity.HIGH,
            )
        )
    if assessment.independence is Independence.UNMET:
        out.append(
            Finding(
                fingerprint=f"{INDEPENDENCE_GAP_RULE}:{assessment.bundle.change.repo}",
                rule_id=INDEPENDENCE_GAP_RULE,
                validator_id="independence",
                message=(
                    "independence required but the verdict was not produced by the org-pinned "
                    "gate identity (check the gate identity policy and the seal workflow)"
                ),
                severity=Severity.HIGH,
            )
        )
    return tuple(out)

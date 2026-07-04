"""Binary enforcement: only PASS + FULL coverage + independence != UNMET, over
the SHA that will actually merge, concludes 'success'. Everything else blocks, with a
legible summary (what ran / skipped / unknown + what to fix)."""
from __future__ import annotations

from siglum.forge.base import CheckConclusion
from siglum.gate.binding import RunBinding
from siglum.models import Assessment
from siglum.verdict import Verdict, ValidatorStatus


def _summary(a: Assessment) -> str:
    ran = sorted(v.id for v in a.bundle.validators if v.status is ValidatorStatus.PASSED)
    failed = sorted(v.id for v in a.bundle.validators if v.status is ValidatorStatus.FAILED)
    skipped = sorted(
        v.id for v in a.bundle.validators
        if v.status in (ValidatorStatus.SKIPPED, ValidatorStatus.UNKNOWN, ValidatorStatus.ERRORED)
    )
    lines = [
        f"verdict={a.verdict.value} coverage={a.coverage.value} independence={a.independence.value}",
        f"passed: {ran or '-'}",
        f"failed: {failed or '-'}",
        f"skipped/unknown: {skipped or '-'}",
    ]
    if a.coverage_gaps:
        gaps = ", ".join(f"{g.validator_id} ({g.reason})" for g in a.coverage_gaps)
        lines.append(f"coverage gaps to fix: {gaps}")
    return "\n".join(lines)


def conclude(assessment: Assessment, binding: RunBinding) -> CheckConclusion:
    a = assessment
    subject = binding.merge_candidate_sha or binding.head_sha
    change_subject = a.bundle.change.merge_candidate_sha or a.bundle.change.head_sha
    if subject != change_subject:
        return CheckConclusion(
            "failure",
            "Siglum: run/assessment SHA mismatch",
            f"binding subject {subject} != assessment subject {change_subject}",
        )
    if a.merge_eligible:
        return CheckConclusion("success", "Siglum: merge-eligible", _summary(a))
    if a.verdict is Verdict.ERROR:
        return CheckConclusion("action_required", "Siglum: validation errored", _summary(a))
    return CheckConclusion("failure", "Siglum: not merge-eligible", _summary(a))

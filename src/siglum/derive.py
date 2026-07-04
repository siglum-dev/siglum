"""The one pure pipeline: EvidenceBundle -> Assessment.

Fail-closed rules (a required validator drives the verdict):
  - any required ERRORED            -> ERROR
  - else any required FAILED        -> FAIL
  - else                            -> PASS
Coverage is FULL iff every required validator has a DEFINITE status (PASSED/FAILED).
A SKIPPED/UNKNOWN/ERRORED required validator yields a coverage gap.
merge_eligible = PASS and FULL and independence != UNMET.
"""
from __future__ import annotations

from siglum.authority import gate_identity_matches
from siglum.canonical import decision_hash
from siglum.models import Assessment, CoverageGap, EvidenceBundle
from siglum.verdict import (
    DEFINITE,
    Coverage,
    Independence,
    ValidatorStatus,
    Verdict,
)

SCHEMA_VERSION = "0.3"


def _derive_verdict(bundle: EvidenceBundle) -> Verdict:
    required = [v for v in bundle.validators if v.required]
    if any(v.status is ValidatorStatus.ERRORED for v in required):
        return Verdict.ERROR
    if any(v.status is ValidatorStatus.FAILED for v in required):
        return Verdict.FAIL
    return Verdict.PASS


def _derive_coverage(bundle: EvidenceBundle) -> tuple[Coverage, tuple[CoverageGap, ...]]:
    gaps: list[CoverageGap] = []
    for v in bundle.validators:
        if v.required and v.status not in DEFINITE:
            gaps.append(CoverageGap(validator_id=v.id, reason=f"status={v.status.value}"))
    coverage = Coverage.FULL if not gaps else Coverage.INCOMPLETE
    return coverage, tuple(gaps)


def _derive_independence(bundle: EvidenceBundle) -> Independence:
    # Structural (Option A): independence is SATISFIED iff the verified run authority is the
    # org-pinned gate identity. A required-but-unconfigured expected identity fails closed.
    if not bundle.policy.independence_required:
        return Independence.NOT_REQUIRED
    expected = bundle.gate_identity
    if expected is None:
        return Independence.UNMET
    return (
        Independence.SATISFIED
        if gate_identity_matches(bundle.validator_authority, expected)
        else Independence.UNMET
    )


def _decision_payload(
    bundle: EvidenceBundle,
    verdict: Verdict,
    coverage: Coverage,
    independence: Independence,
    merge_eligible: bool,
    schema_version: str,
) -> dict[str, object]:
    # Decision-relevant fields ONLY. No timestamps, run ids, or other run metadata.
    return {
        "schema_version": schema_version,
        "change": {
            "repo": bundle.change.repo,
            "base_sha": bundle.change.base_sha,
            "head_sha": bundle.change.head_sha,
            "merge_base": bundle.change.merge_base,
            "merge_candidate_sha": bundle.change.merge_candidate_sha,
        },
        "policy": {
            "policy_id": bundle.policy.policy_id,
            "policy_hash": bundle.policy.policy_hash,
            "anchored_inputs_hash": bundle.policy.anchored_inputs_hash,
            "independence_required": bundle.policy.independence_required,
        },
        "validators": sorted(
            (
                {
                    "id": v.id,
                    "version": v.version,
                    "status": v.status.value,
                    "required": v.required,
                    "artifact_digest": v.artifact_digest,
                }
                for v in bundle.validators
            ),
            key=lambda d: (d["id"], d["version"]),
        ),
        "validator_authority": _authority_fields(bundle),
        "gate_identity": _gate_identity_fields(bundle),
        # change_author is recorded in the predicate (and covered by the signature) but is NOT
        # a decision input, so it is deliberately excluded from the decision hash.
        "verdict": verdict.value,
        "coverage": coverage.value,
        "independence": independence.value,
        "merge_eligible": merge_eligible,
    }


def _authority_fields(bundle: EvidenceBundle) -> dict[str, object]:
    a = bundle.validator_authority
    return {
        "repository": a.repository,
        "repository_id": a.repository_id,
        "workflow_ref": a.workflow_ref,
        "ref": a.ref,
        "runner_class": a.runner_class,
    }


def _gate_identity_fields(bundle: EvidenceBundle) -> dict[str, object] | None:
    g = bundle.gate_identity
    if g is None:
        return None
    return {
        "repository": g.repository,
        "workflow_path": g.workflow_path,
        "protected_refs": list(g.protected_refs),
        "repository_id": g.repository_id,
    }


def assess(bundle: EvidenceBundle, schema_version: str = SCHEMA_VERSION) -> Assessment:
    verdict = _derive_verdict(bundle)
    coverage, gaps = _derive_coverage(bundle)
    independence = _derive_independence(bundle)
    merge_eligible = (
        verdict is Verdict.PASS
        and coverage is Coverage.FULL
        and independence is not Independence.UNMET
    )
    payload = _decision_payload(
        bundle, verdict, coverage, independence, merge_eligible, schema_version
    )
    return Assessment(
        bundle=bundle,
        verdict=verdict,
        coverage=coverage,
        independence=independence,
        merge_eligible=merge_eligible,
        coverage_gaps=gaps,
        decision_hash=decision_hash(payload),
        schema_version=schema_version,
    )

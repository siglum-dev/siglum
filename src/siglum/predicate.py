"""Serialize an Assessment to an in-toto Statement carrying the Siglum validation predicate.

Sibling to SLSA provenance: SLSA attests how an artifact was built; this attests that a
specific change was independently validated. The `predicate` body is a pure function of the
Assessment, so signing it later (a separate plan, via Sigstore) never changes the payload.
"""
from __future__ import annotations

from typing import Any

from siglum.models import Assessment

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://siglum.dev/ValidationAttestation/v0.3"


def _gate_identity(a: Assessment) -> dict[str, Any] | None:
    g = a.bundle.gate_identity
    if g is None:
        return None
    return {
        "repository": g.repository,
        "workflow_path": g.workflow_path,
        "protected_refs": list(g.protected_refs),
        "repository_id": g.repository_id,
    }


def build_predicate(a: Assessment) -> dict[str, Any]:
    change = a.bundle.change
    subject_sha = change.merge_candidate_sha or change.head_sha
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": change.repo, "digest": {"gitCommit": subject_sha}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "schema_version": a.schema_version,
            "verdict": a.verdict.value,
            "coverage": a.coverage.value,
            "independence": a.independence.value,
            "merge_eligible": a.merge_eligible,
            "change": {
                "repo": change.repo,
                "base_sha": change.base_sha,
                "head_sha": change.head_sha,
                "merge_base": change.merge_base,
                "merge_candidate_sha": change.merge_candidate_sha,
            },
            "policy": {
                "policy_id": a.bundle.policy.policy_id,
                "policy_hash": a.bundle.policy.policy_hash,
                "anchored_inputs_hash": a.bundle.policy.anchored_inputs_hash,
                "independence_required": a.bundle.policy.independence_required,
            },
            # The verified run identity that produced the verdict (OBSERVED), the org-pinned
            # identity it was required to match (EXPECTED), and the change author (audit only).
            # Carried so an external verifier holding only the attestation can RECONSTRUCT the
            # evidence bundle and rederive the verdict, not merely re-hash it. See verify_signed.
            "validator_authority": {
                "repository": a.bundle.validator_authority.repository,
                "repository_id": a.bundle.validator_authority.repository_id,
                "workflow_ref": a.bundle.validator_authority.workflow_ref,
                "ref": a.bundle.validator_authority.ref,
                "runner_class": a.bundle.validator_authority.runner_class,
            },
            "gate_identity": _gate_identity(a),
            "change_author": a.bundle.change_author,
            "validators": [
                {
                    "id": v.id,
                    "version": v.version,
                    "status": v.status.value,
                    "required": v.required,
                    "artifact_digest": v.artifact_digest,
                }
                for v in a.bundle.validators
            ],
            "coverage_gaps": [
                {"validator_id": g.validator_id, "reason": g.reason} for g in a.coverage_gaps
            ],
            "decision_hash": a.decision_hash,
        },
    }

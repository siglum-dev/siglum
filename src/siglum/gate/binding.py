"""Bind the verdict to the exact run: run_attempt, workflow path+SHA, event, all SHAs
(incl. the merge_group candidate), the anchored-inputs hash, validator versions, and
artifact digests. The gate enforces the binding at conclusion time, and the Sealed tier
records it inside the signed statement (seal() takes the binding payload), so the
attestation carries which exact run produced it. The binding is provenance: it is covered
by the signature but deliberately not by the decision_hash."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from siglum.forge.base import MergeContext, RunContext
from siglum.gate.anchor import AnchoredInputs
from siglum.models import EvidenceBundle


@dataclass(frozen=True, slots=True)
class RunBinding:
    run_id: str
    run_attempt: str
    workflow_path: str
    workflow_ref_sha: str
    event_name: str
    head_sha: str
    base_sha: str
    merge_base: str
    merge_candidate_sha: str | None
    anchored_inputs_hash: str
    validator_versions: tuple[tuple[str, str], ...]   # (validator_id, version), sorted
    artifact_digests: tuple[tuple[str, str], ...]      # (validator_id, digest), sorted


def bind_run(
    run: RunContext, merge: MergeContext, anchored: AnchoredInputs, bundle: EvidenceBundle
) -> RunBinding:
    return RunBinding(
        run_id=run.run_id,
        run_attempt=run.run_attempt,
        workflow_path=run.workflow_path,
        workflow_ref_sha=run.workflow_ref_sha,
        event_name=run.event_name,
        head_sha=merge.head_sha,
        base_sha=merge.base_sha,
        merge_base=merge.merge_base,
        merge_candidate_sha=merge.merge_candidate_sha,
        anchored_inputs_hash=anchored.anchored_inputs_hash,
        validator_versions=tuple(sorted((v.id, v.version) for v in bundle.validators)),
        artifact_digests=tuple(sorted((v.id, v.artifact_digest) for v in bundle.validators)),
    )


def binding_payload(binding: RunBinding) -> dict[str, Any]:
    """The binding as the JSON shape recorded under predicate['run_binding']."""
    return {
        "run_id": binding.run_id,
        "run_attempt": binding.run_attempt,
        "workflow_path": binding.workflow_path,
        "workflow_ref_sha": binding.workflow_ref_sha,
        "event_name": binding.event_name,
        "head_sha": binding.head_sha,
        "base_sha": binding.base_sha,
        "merge_base": binding.merge_base,
        "merge_candidate_sha": binding.merge_candidate_sha,
        "anchored_inputs_hash": binding.anchored_inputs_hash,
        "validator_versions": [list(p) for p in binding.validator_versions],
        "artifact_digests": [list(p) for p in binding.artifact_digests],
    }


def binding_into_predicate(predicate: dict[str, Any], binding: RunBinding) -> dict[str, Any]:
    """Attach the binding under predicate['run_binding']. Pure; returns a new dict and
    leaves the decision_hash untouched."""
    new = dict(predicate)
    body = dict(new["predicate"])
    body["run_binding"] = binding_payload(binding)
    new["predicate"] = body
    return new

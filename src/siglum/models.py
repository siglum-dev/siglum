"""Immutable data models for the verdict core. No behavior, no I/O."""
from __future__ import annotations

from dataclasses import dataclass

from siglum.verdict import Coverage, Independence, ValidatorStatus, Verdict


@dataclass(frozen=True, slots=True)
class Change:
    repo: str
    base_sha: str
    head_sha: str
    merge_base: str
    merge_candidate_sha: str | None = None  # set by the org-gate for merge-queue runs


@dataclass(frozen=True, slots=True)
class PolicyRef:
    policy_id: str
    # sha256 hex of the canonical parsed policy (policy.policy_hash). Reproducible by anyone
    # holding the policy file: parse it and hash the canonical form (`siglum policy lint`).
    policy_hash: str
    independence_required: bool = False
    approval_required: bool = False
    # sha256 over the sorted (path, base-digest) pairs of every anchored input, filled by the
    # gate from its own base reads. Reproducible from the repository at base_sha plus the
    # policy's anchored paths. Distinct from policy_hash on purpose: one commits to what the
    # policy SAYS, the other to what the anchored files WERE.
    anchored_inputs_hash: str = ""


@dataclass(frozen=True, slots=True)
class ValidatorResult:
    id: str
    version: str
    status: ValidatorStatus
    required: bool
    artifact_digest: str  # e.g. "sha256:<hex>"; "" means no artifact produced


@dataclass(frozen=True, slots=True)
class ValidatorAuthority:
    """The verified run identity of the job that produced the verdict, extracted from the OIDC
    token (head-unforgeable). The OBSERVED side of structural independence."""
    repository: str
    repository_id: str
    workflow_ref: str        # full job_workflow_ref, e.g. "o/r/.github/workflows/seal.yml@refs/heads/main"
    ref: str                 # the ref the gate workflow was pinned to, parsed from workflow_ref
    runner_class: str


@dataclass(frozen=True, slots=True)
class GateIdentityPolicy:
    """The org-controlled identity the validation authority must match for independence. The
    EXPECTED side. Recorded in the predicate so independence stays recomputable from evidence."""
    repository: str
    workflow_path: str               # repo-relative, e.g. ".github/workflows/seal.yml"
    protected_refs: tuple[str, ...]  # refs the gate workflow may be pinned to
    repository_id: str = ""          # "" means do not pin the immutable id (looser)


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    change: Change
    policy: PolicyRef
    validators: tuple[ValidatorResult, ...]
    validator_authority: ValidatorAuthority  # verified run identity that produced the verdict
    change_author: str = ""                   # who authored the change (audit only; not a decision input, not in the decision hash)
    gate_identity: GateIdentityPolicy | None = None  # the required identity, when independence is required


@dataclass(frozen=True, slots=True)
class CoverageGap:
    validator_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class Assessment:
    bundle: EvidenceBundle
    verdict: Verdict
    coverage: Coverage
    independence: Independence
    merge_eligible: bool
    coverage_gaps: tuple[CoverageGap, ...]
    decision_hash: str
    schema_version: str = "0.3"

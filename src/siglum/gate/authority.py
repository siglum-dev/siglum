"""Verify the gate's own run identity at runtime.

The OIDC token is cryptographically verified upstream. `authority_from_claims` extracts the
verified run identity and applies the UNCONDITIONAL floor: a workflow in the gated repository,
on a hosted runner, or the gate fails closed. That floor alone kills cross-repo token replay,
fork-workflow impersonation, and self-hosted tampering.

`require_gate_identity` applies the TIGHT check (the shared `gate_identity_mismatch` predicate):
the exact org-pinned gate workflow, a protected ref, and the immutable repository id. This is the
basis for structural independence, so the runtime fail-closed and the recomputable independence
verdict are the same rule, never two that can drift apart.
"""
from __future__ import annotations

from siglum.authority import authority_floor_mismatch, gate_identity_mismatch, ref_of
from siglum.gate.errors import GateRefused
from siglum.models import GateIdentityPolicy, ValidatorAuthority


def authority_from_claims(claims: dict[str, object], *, gated_repo: str) -> ValidatorAuthority:
    workflow_ref = str(claims.get("job_workflow_ref") or claims.get("workflow_ref") or "")
    authority = ValidatorAuthority(
        repository=str(claims.get("repository", "")),
        repository_id=str(claims.get("repository_id", "")),
        workflow_ref=workflow_ref,
        ref=ref_of(workflow_ref),
        runner_class=str(claims.get("runner_environment", "unknown")),
    )
    # The unconditional floor (shared with offline verification): kills cross-repo replay,
    # fork-workflow impersonation, and self-hosted tampering before any verdict is derived.
    reason = authority_floor_mismatch(authority, gated_repo)
    if reason is not None:
        raise GateRefused(reason)
    return authority


def require_gate_identity(
    authority: ValidatorAuthority, expected: GateIdentityPolicy
) -> None:
    """Fail closed unless the verified authority is the expected org-pinned gate identity."""
    reason = gate_identity_mismatch(authority, expected)
    if reason is not None:
        raise GateRefused(reason)

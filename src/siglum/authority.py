"""The tight gate-identity match: pure logic over the data models, no I/O.

Structural independence (Option A) is SATISFIED only when the verified run authority is the
org-pinned gate workflow, on a protected ref, on a hosted runner, in the gated repository.
`gate_identity_mismatch` is the single source of truth for that rule. It returns a human
reason on mismatch (so the runtime can fail closed with a specific message) or None on match
(so the derivation can recompute independence). Both surfaces share this one predicate, which
is why the recorded `independence` verdict can never drift from the rule that was enforced.
"""
from __future__ import annotations

from siglum.models import GateIdentityPolicy, ValidatorAuthority

HOSTED = "github-hosted"


def workflow_path_of(workflow_ref: str, repository: str) -> str:
    """Repo-relative workflow path from a job_workflow_ref.
    "o/r/.github/workflows/seal.yml@refs/heads/main" -> ".github/workflows/seal.yml"."""
    head = workflow_ref.split("@", 1)[0]
    prefix = f"{repository}/"
    return head[len(prefix):] if head.startswith(prefix) else head


def ref_of(workflow_ref: str) -> str:
    """The pinned ref from a job_workflow_ref ('' if absent)."""
    return workflow_ref.partition("@")[2]


def authority_floor_mismatch(authority: ValidatorAuthority, repo: str) -> str | None:
    """The unconditional floor every legitimate gate run must meet: a hosted workflow IN `repo`
    (the repository being gated / attested). Returns a reason on mismatch, else None. This is
    shared by the runtime gate (which refuses) and offline verification (which rejects), so both
    deny the same illegitimate authority states, independent of whether independence is required."""
    if authority.repository != repo:
        return f"gate identity repository {authority.repository!r} does not match the repo {repo!r}"
    if not authority.workflow_ref.startswith(f"{repo}/"):
        return f"gate workflow_ref {authority.workflow_ref!r} is not a workflow in {repo!r}"
    if authority.runner_class != HOSTED:
        return f"gate ran on a non-hosted runner ({authority.runner_class!r})"
    return None


def gate_identity_mismatch(
    authority: ValidatorAuthority, expected: GateIdentityPolicy
) -> str | None:
    """None iff the verified authority is the expected org-pinned gate identity; else a reason."""
    if authority.repository != expected.repository:
        return f"gate repository {authority.repository!r} != required {expected.repository!r}"
    if expected.repository_id and authority.repository_id != expected.repository_id:
        return (
            f"gate repository_id {authority.repository_id!r} != required "
            f"{expected.repository_id!r}"
        )
    # The workflow_ref must be a workflow IN the repository (runtime-floor parity), else a bare
    # path that happens to equal workflow_path would match. Enforced here so both the runtime
    # check and the offline rederivation share one rule.
    if not authority.workflow_ref.startswith(f"{authority.repository}/"):
        return f"gate workflow_ref {authority.workflow_ref!r} is not a workflow in {authority.repository!r}"
    path = workflow_path_of(authority.workflow_ref, authority.repository)
    if path != expected.workflow_path:
        return f"gate workflow {path!r} != required {expected.workflow_path!r}"
    # The protected-ref check derives the ref from workflow_ref, never from the separate `ref`
    # field, so a split identity (workflow pinned to a PR ref, `ref` claiming a protected ref)
    # cannot satisfy the match.
    actual_ref = ref_of(authority.workflow_ref)
    if actual_ref not in expected.protected_refs:
        return f"gate ref {actual_ref!r} is not one of the required protected refs"
    if authority.runner_class != HOSTED:
        return f"gate ran on a non-hosted runner ({authority.runner_class!r})"
    return None


def gate_identity_matches(authority: ValidatorAuthority, expected: GateIdentityPolicy) -> bool:
    return gate_identity_mismatch(authority, expected) is None

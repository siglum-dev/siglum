"""The mergeable subject: which SHA the verdict binds, and that it is the approved one.

Selects the SHA that will actually merge (the merge_group candidate in a merge queue, else
head). When the policy requires approval, `prove_approval` is the time-of-check-to-time-of-use
defense from spec sections 8.5 and 8.6: the approval must be for the exact subject being
gated, so approve-A-then-force-push-B fails closed. Approval proof is opt-in
(`approval_required` in the base policy); a policy that does not require it never consults
review state at all.
"""
from __future__ import annotations

from siglum.forge.base import MergeContext
from siglum.verdict import ApprovalProof


def select_subject_sha(merge: MergeContext) -> str:
    return merge.merge_candidate_sha or merge.head_sha


def prove_approval(
    merge: MergeContext, *, required: bool, queue_enforces_review: bool = False
) -> ApprovalProof:
    """Prove the mergeable subject carries a current approval.

    PR: the approved SHA must be the head being gated. This is the force-push defense
    (approve-A-then-force-push-B), and it also means an approval left behind by a later push
    does not count: the reviewer must approve the commit that will actually merge.
    merge_group: the gate cannot see per-PR approval from the merge_group event, so it proves the
    PREREQUISITE instead. `queue_enforces_review` is the audited fact that the protected target
    branch requires an approving review; when true, the merge queue would not have admitted
    an unapproved pull request, so the candidate is PROVEN. When false (the default, including any
    tier that cannot read branch protection) it fails closed. The queue prerequisite applies only
    to merge_group; a plain PR always needs its own current approval."""
    if not required:
        return ApprovalProof.NOT_REQUIRED
    if merge.merge_candidate_sha is not None:
        return ApprovalProof.PROVEN if queue_enforces_review else ApprovalProof.UNMET
    if merge.approved_sha is not None and merge.approved_sha == merge.head_sha:
        return ApprovalProof.PROVEN
    return ApprovalProof.UNMET

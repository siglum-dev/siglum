"""The approval proof. When approval is required, the mergeable subject must carry a
current, non-dismissed approval, else the gate fails closed (replacing the old inert
approved_sha compare that no-oped when None)."""
from siglum.forge.base import MergeContext
from siglum.gate.mergeable_subject import prove_approval
from siglum.verdict import ApprovalProof

H = "h" * 40
B = "b" * 40
M = "m" * 40


def _merge(head=H, approved=None, candidate=None):
    return MergeContext(
        head_sha=head, base_sha=B, merge_base=M,
        merge_candidate_sha=candidate, approved_sha=approved,
    )


def test_not_required_is_not_required():
    assert prove_approval(_merge(), required=False) is ApprovalProof.NOT_REQUIRED


def test_pr_with_a_matching_approval_is_proven():
    assert prove_approval(_merge(approved=H), required=True) is ApprovalProof.PROVEN


def test_pr_without_any_approval_is_unmet():
    assert prove_approval(_merge(approved=None), required=True) is ApprovalProof.UNMET


def test_pr_approval_for_a_different_sha_is_unmet():
    # approve-A-then-force-push-B: the approval is for the old SHA, not the current head.
    assert prove_approval(_merge(head=H, approved="d" * 40), required=True) is ApprovalProof.UNMET


def test_merge_group_without_queue_enforced_review_is_unmet():
    # Without proof that the queue enforced approval (the default), a merge_group fails closed:
    # the gate will not trust an unaudited branch-protection config.
    assert prove_approval(_merge(candidate="c" * 40, approved=None), required=True) is ApprovalProof.UNMET
    assert prove_approval(_merge(candidate="c" * 40, approved=H), required=True) is ApprovalProof.UNMET


def test_merge_group_with_queue_enforced_review_is_proven():
    # When the protected branch is audited to require an approving review, the merge queue
    # would not have admitted an unapproved pull request, so the candidate is PROVEN.
    assert (
        prove_approval(_merge(candidate="c" * 40, approved=None),
                       required=True, queue_enforces_review=True)
        is ApprovalProof.PROVEN
    )


def test_queue_enforced_review_does_not_relax_a_plain_pr():
    # The queue prerequisite only applies to merge_group; a plain PR still needs its own approval.
    assert (
        prove_approval(_merge(approved=None), required=True, queue_enforces_review=True)
        is ApprovalProof.UNMET
    )

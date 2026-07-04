"""The org-controlled seal-enforce half, composed end-to-end over a ForgeProvider.

This is the trusted job: it never checks out head code. It anchors inputs to the base,
fills any base-required validator that the gather job did not produce with UNKNOWN
(fail-closed: a head that deletes a gate-critical validator cannot make it silently
vanish), derives + verifies the verdict, binds the run, and posts a source-restricted
check-run. Signing (seal) is wired at build time around this same composition."""
from __future__ import annotations

import dataclasses
from collections.abc import Callable
from dataclasses import dataclass

from siglum.derive import assess
from siglum.forge.base import (
    CheckConclusion,
    CheckRun,
    ForgeProvider,
    ForgeReadError,
    MergeContext,
    VerifiedPr,
)
from siglum.gate.anchor import anchor_inputs
from siglum.gate.binding import RunBinding, bind_run
from siglum.gate.comment import SIGLUM_COMMENT_MARKER, format_authority, render_pr_comment
from siglum.gate.enforce import conclude
from siglum.gate.enforcement import enforcement_mismatch
from siglum.gate.errors import GateRefused
from siglum.gate.runner import require_hosted_runner
from siglum.gate.mergeable_subject import prove_approval, select_subject_sha
from siglum.gate.authority import authority_from_claims, require_gate_identity
from siglum.gate.evidence import EvidenceError, normalize_evidence
from siglum.models import (
    Assessment,
    Change,
    EvidenceBundle,
    GateIdentityPolicy,
    PolicyRef,
    ValidatorResult,
)
from siglum.policy import ValidatorPolicy
from siglum.sealing.seal import SignedAttestation
from siglum.verdict import ApprovalProof
from siglum.verify import verify

CHECK_RUN_NAME = "siglum"

# A sealer signs and self-verifies the attestation for a success verdict, raising on any
# failure. It receives the run binding so the signed statement records which exact run
# produced it. The Sealed tier injects the real Sigstore-backed sealer; Standard omits it.
Sealer = Callable[[Assessment, RunBinding], SignedAttestation]


def trusted_author(verified: VerifiedPr | None, fallback: str) -> str:
    """Prefer the App-fetched PR author (trusted-side) over the event-supplied fallback.
    Audit only: change_author is recorded in the predicate but is never a decision input."""
    return verified.author if verified is not None else fallback


@dataclass(frozen=True, slots=True)
class GateInputs:
    repo: str
    policy: PolicyRef
    base_validators: tuple[ValidatorPolicy, ...]       # full specs, authoritative from the base policy
    anchored_paths: tuple[str, ...]                    # derived from the base policy
    validator_results: tuple[ValidatorResult, ...]     # produced by the untrusted gather job
    change_author: str                                 # who authored the change (audit only)
    gate_identity: GateIdentityPolicy | None = None    # required gate identity when independence is required


def _publish(
    provider: ForgeProvider,
    *,
    subject: str,
    conclusion: CheckConclusion,
    authority_section: str = "",
) -> None:
    provider.post_check_run(CheckRun(name=CHECK_RUN_NAME, head_sha=subject, conclusion=conclusion))
    try:
        provider.upsert_pr_comment(
            marker=SIGLUM_COMMENT_MARKER,
            body=render_pr_comment(conclusion, authority_section=authority_section),
        )
    except Exception:
        # The check-run is authoritative. Comment write failures should not change the
        # merge verdict or mask the check-run result.
        pass


def _self_audit_enforcement(
    provider: ForgeProvider, inputs: GateInputs, *, subject: str, authority_section: str
) -> CheckConclusion | None:
    """At the Sealed tier, fail closed unless the gate's own check is actually required and
    source-restricted to the Siglum App. Returns a refusal to publish, or None to proceed."""
    expected_app_id = provider.expected_app_id()
    if expected_app_id is None:
        # A policy that requires independence asserts the Sealed posture. No App id means the
        # App credentials are missing and the run degraded to Standard: fail closed rather than
        # silently posting an unrestricted check with GITHUB_TOKEN.
        if inputs.policy.independence_required:
            refused = CheckConclusion(
                "failure",
                "Siglum: Sealed posture requires the GitHub App",
                "the policy requires independence but no Siglum App credentials are configured; "
                "the gate cannot post a source-restricted check",
            )
            _publish(provider, subject=subject, conclusion=refused, authority_section=authority_section)
            return refused
        return None  # Standard tier: no App-restricted check to verify
    try:
        config = provider.enforcement_config()
    except ForgeReadError as exc:
        refused = CheckConclusion("failure", "Siglum: enforcement not verified", str(exc))
        _publish(provider, subject=subject, conclusion=refused, authority_section=authority_section)
        return refused
    reason = enforcement_mismatch(
        config, check_name=CHECK_RUN_NAME, expected_app_id=expected_app_id
    )
    if reason is not None:
        refused = CheckConclusion("failure", "Siglum: enforcement not configured", reason)
        _publish(provider, subject=subject, conclusion=refused, authority_section=authority_section)
        return refused
    return None


def _approval_refusal_reason(merge: MergeContext) -> str:
    """Why the approval could not be proven, written for the person who has to fix it."""
    if merge.merge_candidate_sha is not None:
        return (
            "the policy requires an approving review, and in a merge queue the gate can only "
            "prove that by confirming the target branch itself requires a current, "
            "non-bypassable review. That could not be confirmed. Enable required reviews with "
            "stale-review dismissal (or last-push approval) and no bypass actors on the target "
            "branch, then re-run the check."
        )
    if merge.approved_sha is None:
        return (
            "the policy requires an approving review, and this pull request has no current "
            "approving review. Get an approving review on the current head commit, then "
            "re-run the check."
        )
    return (
        f"the latest approval is for an older commit ({merge.approved_sha[:12]}), not the "
        f"current head ({merge.head_sha[:12]}). This happens when commits are pushed after "
        "the review, and it is also the state a force-push after approval produces, so the "
        "gate cannot tell them apart. Have a reviewer approve the current head, then re-run "
        "the check."
    )


def run_gate(
    provider: ForgeProvider, inputs: GateInputs, *, sealer: Sealer | None = None
) -> CheckConclusion:
    run = provider.run_context()
    merge = provider.merge_context()
    subject = select_subject_sha(merge)

    # Confirm the head sha against the PR fetched with the gate's own token, before it is
    # trusted as the head-read target, the approval subject, or the bound commit. If the PR head
    # moved between the event and this run, the verdict would not bind the mergeable commit, so
    # fail closed and let the re-triggered run evaluate the new head. None for non-PR events
    # (merge_group, push), where there is no single PR head to confirm.
    verified = provider.verified_pr()
    if verified is not None and verified.head_sha != merge.head_sha:
        refused = CheckConclusion(
            "failure",
            "Siglum: PR head moved",
            f"the event head {merge.head_sha} is not the current PR head {verified.head_sha}; "
            "the pull request changed while the gate was running. Re-run on the new head.",
        )
        _publish(provider, subject=subject, conclusion=refused)
        return refused

    # Fail-closed stop: the gate must run on a hosted runner.
    try:
        require_hosted_runner(run)
    except GateRefused as exc:
        refused = CheckConclusion("failure", "Siglum: gate refused", str(exc))
        _publish(provider, subject=subject, conclusion=refused)
        return refused

    # When the policy requires approval, the mergeable subject must carry a current
    # approval for the exact SHA being gated (the force-push defense). Approval is a gate
    # PRECONDITION (like the runner, authority floor, and enforcement self-audit), enforced
    # before assess. It is deliberately NOT a recorded verdict field: a success verdict from an
    # approval-required policy already implies this stop passed. A policy that does not require
    # approval never consults review state, so a leftover approval for an older commit cannot
    # refuse a gate that was never asked to prove one.
    #
    # In a merge_group the gate cannot see per-PR approval, so it proves the prerequisite
    # that the protected target branch requires an approving review. That fact is read from
    # branch protection (the App reads it; a tier that cannot read it stays unproven and fails
    # closed).
    if inputs.policy.approval_required:
        queue_enforces_review = False
        if merge.merge_candidate_sha is not None:
            try:
                config = provider.enforcement_config()
            except ForgeReadError as exc:
                refused = CheckConclusion("failure", "Siglum: approval not verified", str(exc))
                _publish(provider, subject=subject, conclusion=refused)
                return refused
            # The prerequisite is read from the audited (default) branch's protection. A
            # merge_group targeting any other branch cannot be proven from it, so fail closed
            # rather than trust the wrong branch's policy.
            expected_ref = f"refs/heads/{config.default_branch}"
            if merge.base_ref != expected_ref:
                refused = CheckConclusion(
                    "failure",
                    "Siglum: merge_group target not supported",
                    f"the merge_group targets {merge.base_ref!r}, but approval can only be "
                    f"proven for the audited default branch {expected_ref!r}",
                )
                _publish(provider, subject=subject, conclusion=refused)
                return refused
            queue_enforces_review = config.requires_review
        else:
            # The approved SHA is a trusted-side fact: the gate reads the PR's reviews with its
            # own token. A read failure means the approval cannot be proven, so fail closed.
            try:
                merge = dataclasses.replace(merge, approved_sha=provider.approved_head_sha())
            except ForgeReadError as exc:
                refused = CheckConclusion("failure", "Siglum: approval not verified", str(exc))
                _publish(provider, subject=subject, conclusion=refused)
                return refused
        if (
            prove_approval(merge, required=True, queue_enforces_review=queue_enforces_review)
            is ApprovalProof.UNMET
        ):
            refused = CheckConclusion(
                "failure", "Siglum: approval not proven", _approval_refusal_reason(merge)
            )
            _publish(provider, subject=subject, conclusion=refused)
            return refused

    # The head version of each anchored path is read from the trusted forge at the head sha
    # itself; a non-404 read failure raises ForgeReadError and fails closed upstream.
    anchored = anchor_inputs(
        provider, merge.base_sha, merge.head_sha, paths=inputs.anchored_paths
    )
    if anchored.head_overrides_detected:
        paths = ", ".join(anchored.head_overrides_detected)
        refused = CheckConclusion(
            "failure",
            "Siglum: base-anchored inputs changed",
            f"head changed gate-critical input(s): {paths}",
        )
        _publish(provider, subject=subject, conclusion=refused)
        return refused

    claims = provider.oidc_claims()
    try:
        authority = authority_from_claims(claims, gated_repo=inputs.repo)
        # Tight identity check: when independence is required and an expected
        # identity is configured, fail closed with a specific reason on any mismatch. A
        # required-but-unconfigured identity is left to derivation (independence -> UNMET).
        if inputs.policy.independence_required and inputs.gate_identity is not None:
            require_gate_identity(authority, inputs.gate_identity)
    except GateRefused as exc:
        refused = CheckConclusion("failure", "Siglum: gate identity not verified", str(exc))
        _publish(provider, subject=subject, conclusion=refused)
        return refused

    # The gate run is now verified, so every comment from here on names the authority.
    authority_section = format_authority(authority)

    enforcement_refusal = _self_audit_enforcement(
        provider, inputs, subject=subject, authority_section=authority_section
    )
    if enforcement_refusal is not None:
        return enforcement_refusal

    try:
        validators = normalize_evidence(inputs.base_validators, inputs.validator_results)
    except EvidenceError as exc:
        refused = CheckConclusion("failure", "Siglum: invalid validator evidence", str(exc))
        _publish(provider, subject=subject, conclusion=refused, authority_section=authority_section)
        return refused
    # policy_hash (the canonical parsed-policy hash) passes through untouched; the anchored
    # hash is a separate fact the gate itself derived from base reads.
    policy = dataclasses.replace(
        inputs.policy, anchored_inputs_hash=anchored.anchored_inputs_hash
    )

    change = Change(
        repo=inputs.repo,
        base_sha=merge.base_sha,
        head_sha=merge.head_sha,
        merge_base=merge.merge_base,
        merge_candidate_sha=merge.merge_candidate_sha,
    )
    bundle = EvidenceBundle(
        change=change,
        policy=policy,
        validators=validators,
        validator_authority=authority,
        # Record the author from the trusted-side PR when available, else the event fallback.
        change_author=trusted_author(verified, inputs.change_author),
        gate_identity=inputs.gate_identity,
    )
    assessment = assess(bundle)
    verify(assessment)  # recompute guard before we publish anything
    binding = bind_run(run, merge, anchored, bundle)
    conclusion = conclude(assessment, binding)
    section = format_authority(authority, independence=assessment.independence)

    # Never a green check without a signed, self-verified attestation. The invariant is
    # enforced here, not by caller convention: at the Sealed tier (App present) signing is
    # mandatory, and on success the attestation is sealed and self-verified FIRST.
    if conclusion.conclusion == "success":
        sealed_tier = provider.expected_app_id() is not None
        if sealed_tier and sealer is None:
            failure = CheckConclusion(
                "failure",
                "Siglum: attestation signing required",
                "the Sealed tier must sign and self-verify the verdict before a green check, "
                "but no sealer is configured",
            )
            _publish(provider, subject=subject, conclusion=failure, authority_section=section)
            return failure
        if sealer is not None:
            try:
                attestation = sealer(assessment, binding)
            except Exception as exc:  # any signing/self-verification failure must fail closed
                failure = CheckConclusion(
                    "failure",
                    "Siglum: attestation signing failed",
                    "the verdict passed but signing or self-verification failed, so no green "
                    f"check is posted: {exc}",
                )
                _publish(provider, subject=subject, conclusion=failure, authority_section=section)
                return failure
            conclusion = _with_attestation(conclusion, attestation)

    _publish(provider, subject=subject, conclusion=conclusion, authority_section=section)
    return conclusion


def _with_attestation(
    conclusion: CheckConclusion, attestation: SignedAttestation
) -> CheckConclusion:
    if not attestation.rekor_log_url:
        return conclusion
    return dataclasses.replace(
        conclusion, summary=f"{conclusion.summary}\nattestation: {attestation.rekor_log_url}"
    )

"""Miasma decision-table invariants, driven end-to-end through run_gate over a
FakeProvider. Each test is one attacker move the gate must defeat at the data layer."""
from siglum.audit.model import RepoConfig, RequiredCheck
from siglum.forge.base import VerifiedPr
from siglum.gate.orchestrate import run_gate, GateInputs
from siglum.models import PolicyRef, ValidatorResult
from siglum.policy import ValidatorPolicy
from siglum.verdict import ValidatorStatus
from tests.gate.fakes import FakeProvider, run_ctx, merge_ctx, vr, pinned, H

SIGLUM_APP = 42


def _enforced(*, app_id=SIGLUM_APP, context="siglum", protected=True, requires_review=False):
    return RepoConfig(
        repo="o/r",
        required_checks=(
            RequiredCheck(context=context, enforcement="app_check_run",
                          source_restricted=app_id is not None, app_id=app_id),
        ),
        workflows=(), admin_bypass_allowed=False, protected=protected,
        requires_review=requires_review,
    )


def _inputs(results, required=("tests",), change_author="alice",
            independence=False, anchored_paths=(), gate_identity=None, approval=False):
    return GateInputs(
        repo="o/r",
        policy=PolicyRef(policy_id="default", policy_hash="p" * 40,
                         independence_required=independence, approval_required=approval),
        base_validators=tuple(
            ValidatorPolicy(id=vid, version="0", required=True) for vid in required
        ),
        anchored_paths=anchored_paths,
        validator_results=tuple(results),
        change_author=change_author,
        gate_identity=gate_identity,
    )


def test_clean_change_concludes_success_and_posts_one_app_check():
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(approved=H))
    c = run_gate(fp, _inputs([vr("tests")]))
    assert c.conclusion == "success"
    assert len(fp.posted) == 1
    assert fp.posted[0].name == "siglum"          # App check-run, not a commit status
    assert fp.posted[0].conclusion.conclusion == "success"
    assert len(fp.comments) == 1
    assert "merge eligible" in fp.comments[0][1]


def test_pr_head_moved_after_the_event_blocks():
    # The head sha is verified against the App-fetched current PR head. If the PR head moved
    # between the event and this run, the verdict would not bind the mergeable commit: fail closed.
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(approved=H),
                      verified_pr=VerifiedPr(head_sha="x" * 40, author="alice"))
    c = run_gate(fp, _inputs([vr("tests")]))
    assert c.conclusion == "failure"
    assert "head moved" in c.title.lower()
    assert fp.posted[0].conclusion.conclusion == "failure"


def test_verified_pr_head_matching_the_event_proceeds():
    # The App-fetched head equals the event head: a legit PR passes the verification.
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(approved=H),
                      verified_pr=VerifiedPr(head_sha=H, author="alice"))
    c = run_gate(fp, _inputs([vr("tests")]))
    assert c.conclusion == "success"


def test_self_hosted_runner_blocks():
    fp = FakeProvider(run=run_ctx("self-hosted"), merge=merge_ctx(approved=H))
    c = run_gate(fp, _inputs([vr("tests")]))
    assert c.conclusion == "failure" and "refused" in c.title.lower()
    assert fp.posted[0].conclusion.conclusion == "failure"


def test_force_push_after_approve_blocks_when_approval_required():
    # TOCTOU: the policy requires approval and the latest approval is for a different SHA
    # (approve-A-then-push-B). Fail closed with a message that says what to do, because the
    # same state is produced by an innocent fixup push after review.
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(approved="d" * 40))   # approved != head
    c = run_gate(fp, _inputs([vr("tests")], approval=True))
    assert c.conclusion == "failure"
    assert "approval not proven" in c.title
    assert "older commit" in c.summary
    assert "approve the current head" in c.summary


def test_stale_approval_does_not_block_when_approval_not_required():
    # A stale approval must not refuse a policy that never opted into approval proof: the
    # reviews API is not even consulted, so the everyday approve-then-push-a-fixup flow passes.
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(approved="d" * 40))
    c = run_gate(fp, _inputs([vr("tests")]))
    assert c.conclusion == "success"
    assert fp.approval_fetches == 0


def test_approval_required_fetches_the_reviews_trusted_side():
    # When the policy requires approval on a plain PR, the approved SHA comes from the
    # provider's own reviews read, not from anything the event carried.
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(approved=H))
    c = run_gate(fp, _inputs([vr("tests")], approval=True))
    assert c.conclusion == "success"
    assert fp.approval_fetches == 1


def test_approval_reviews_read_failure_fails_closed():
    # The reviews read is a trusted-side fact; if it cannot be read, the approval cannot be
    # proven, so the gate posts a failure rather than passing without the proof.
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(approved=H), approval_error=True)
    c = run_gate(fp, _inputs([vr("tests")], approval=True))
    assert c.conclusion == "failure"
    assert "approval not verified" in c.title
    assert fp.posted[0].conclusion.conclusion == "failure"


def test_head_dropping_a_base_required_validator_is_not_eligible():
    # base policy requires 'tests' AND 'scan'; gather produced only 'tests'
    # (head removed scan's config). 'scan' is filled UNKNOWN -> INCOMPLETE -> blocked.
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(approved=H))
    c = run_gate(fp, _inputs([vr("tests")], required=("tests", "scan")))
    assert c.conclusion == "failure"
    assert "scan" in c.summary


def test_a_failure_reported_as_non_required_cannot_launder_past_the_gate():
    # A head-controlled results.json marks the base-required 'tests' validator as
    # required=false and FAILED. The gate takes 'required' from the base policy, so it blocks.
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(approved=H))
    laundered = ValidatorResult(
        id="tests", version="9", status=ValidatorStatus.FAILED, required=False, artifact_digest=""
    )
    c = run_gate(fp, _inputs([laundered], required=("tests",)))
    assert c.conclusion == "failure"


def test_duplicate_validator_evidence_fails_closed_with_one_failed_check():
    # Two observed rows for one id is an integrity violation; the gate fails closed,
    # posts exactly one failed 'siglum' check, and never reaches a success path.
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(approved=H))
    dup = [
        ValidatorResult(id="tests", version="0", status=ValidatorStatus.PASSED,
                        required=True, artifact_digest=""),
        ValidatorResult(id="tests", version="0", status=ValidatorStatus.PASSED,
                        required=True, artifact_digest=""),
    ]
    c = run_gate(fp, _inputs(dup, required=("tests",)))
    assert c.conclusion == "failure"
    assert "invalid validator evidence" in c.title
    assert len(fp.posted) == 1 and fp.posted[0].conclusion.conclusion == "failure"


def test_a_token_from_a_different_repo_is_refused_by_the_gate():
    # Even a cryptographically valid token is refused if its identity is not a workflow
    # in the gated repo. Kills cross-repo token replay.
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(approved=H),
                      oidc={"iss": "i", "sub": "s", "actor": "a", "repository": "attacker/x",
                            "job_workflow_ref": "attacker/x/.github/workflows/w.yml@refs/heads/main",
                            "runner_environment": "github-hosted"})
    c = run_gate(fp, _inputs([vr("tests")]))
    assert c.conclusion == "failure"
    assert "gate identity" in c.title.lower()


def test_head_editing_base_anchored_input_blocks_before_verdict():
    # The gate reads the head version itself. An untrusted gather cannot suppress
    # this override by lying about (or omitting) head digests; there is no head-digest input.
    fp = FakeProvider(
        run=run_ctx(),
        merge=merge_ctx(approved=H),
        base_files={".siglum/policy.toml": b"BASE"},
        head_files={".siglum/policy.toml": b"HEAD-EDIT"},
    )
    c = run_gate(fp, _inputs([vr("tests")], anchored_paths=(".siglum/policy.toml",)))
    assert c.conclusion == "failure"
    assert "base-anchored inputs changed" in c.title
    assert ".siglum/policy.toml" in c.summary
    assert len(fp.comments) == 1
    assert "separate trusted update" in fp.comments[0][1]


def test_head_deleting_a_base_anchored_input_blocks_before_verdict():
    # The head removes a gate-critical input present at base (404 at head). Detected as an
    # override and blocked, even though the gather never reported anything about it.
    fp = FakeProvider(
        run=run_ctx(),
        merge=merge_ctx(approved=H),
        base_files={".siglum/policy.toml": b"BASE"},
        head_files={},
    )
    c = run_gate(fp, _inputs([vr("tests")], anchored_paths=(".siglum/policy.toml",)))
    assert c.conclusion == "failure"
    assert "base-anchored inputs changed" in c.title


def test_head_matching_base_on_an_anchored_path_succeeds():
    # A legit PR that does not touch the anchored input passes through the head-read path cleanly.
    fp = FakeProvider(
        run=run_ctx(),
        merge=merge_ctx(approved=H),
        base_files={".siglum/policy.toml": b"SAME"},
        head_files={".siglum/policy.toml": b"SAME"},
    )
    c = run_gate(fp, _inputs([vr("tests")], anchored_paths=(".siglum/policy.toml",)))
    assert c.conclusion == "success"


def test_independence_required_with_the_pinned_identity_succeeds():
    # Independence requires the full Sealed setup to succeed: the pinned org identity
    # that actually ran, the App configured, and the `siglum` check really enforced.
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(approved=H),
                      expected_app_id=SIGLUM_APP, enforcement=_enforced())
    c = run_gate(fp, _inputs([vr("tests")], independence=True, gate_identity=pinned()),
                 sealer=lambda a, b: _fake_attestation())
    assert c.conclusion == "success"
    assert fp.posted[0].conclusion.conclusion == "success"


def test_independence_required_without_a_pinned_identity_blocks():
    # Independence required but no expected gate identity configured -> cannot prove it -> UNMET.
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(approved=H))
    c = run_gate(fp, _inputs([vr("tests")], independence=True, gate_identity=None))
    assert c.conclusion == "failure"


def test_independence_required_with_a_non_pinned_workflow_blocks():
    # A same-repo hosted workflow that is NOT the org-pinned gate must not satisfy independence.
    # It clears the unconditional floor (same repo, hosted) but fails the tight identity match.
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(approved=H),
                      oidc={"iss": "i", "sub": "s", "actor": "mallory", "repository": "o/r",
                            "job_workflow_ref": "o/r/.github/workflows/evil.yml@refs/heads/main",
                            "runner_environment": "github-hosted"})
    c = run_gate(fp, _inputs([vr("tests")], independence=True, gate_identity=pinned()))
    assert c.conclusion == "failure"
    assert "gate identity" in c.title.lower()


def test_sealed_policy_without_app_credentials_fails_closed():
    # A policy that requires independence (the Sealed posture) but a gate with no App id means
    # the App secrets are missing and the run degraded to Standard. Fail closed, never run as
    # Standard with GITHUB_TOKEN and skip the enforcement self-audit.
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(approved=H), expected_app_id=None)
    c = run_gate(fp, _inputs([vr("tests")], independence=True, gate_identity=pinned()))
    assert c.conclusion == "failure"
    assert "App" in c.title


def test_sealed_gate_with_real_enforcement_succeeds():
    # At the Sealed tier (expected_app_id set), the gate self-audits and proceeds only when
    # its own check is required and restricted to THIS app.
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(approved=H),
                      expected_app_id=SIGLUM_APP, enforcement=_enforced())
    c = run_gate(fp, _inputs([vr("tests")]), sealer=lambda a, b: _fake_attestation())
    assert c.conclusion == "success"


def test_sealed_gate_fails_closed_when_siglum_not_restricted_to_our_app():
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(approved=H),
                      expected_app_id=SIGLUM_APP, enforcement=_enforced(app_id=999))
    c = run_gate(fp, _inputs([vr("tests")]))
    assert c.conclusion == "failure"
    assert "enforcement not configured" in c.title
    assert fp.posted[0].conclusion.conclusion == "failure"


def test_sealed_gate_fails_closed_when_enforcement_is_unreadable():
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(approved=H),
                      expected_app_id=SIGLUM_APP, enforcement_error=True)
    c = run_gate(fp, _inputs([vr("tests")]))
    assert c.conclusion == "failure"
    assert "enforcement not verified" in c.title


def _fake_attestation():
    from siglum.sealing.identity import SignerIdentity
    from siglum.sealing.seal import SignedAttestation
    return SignedAttestation(
        statement={}, sigstore_bundle="{}",
        signer_identity=SignerIdentity(issuer="i", subject="s"),
        rekor_log_url="https://rekor.example", decision_hash="x" * 64,
    )


def test_sealed_tier_without_a_sealer_fails_closed():
    # The signing invariant enforced in run_gate, not by caller convention: a Sealed run (App present)
    # must not post an unsigned green even if the caller forgot to pass a sealer.
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(approved=H),
                      expected_app_id=SIGLUM_APP, enforcement=_enforced())
    c = run_gate(fp, _inputs([vr("tests")]))  # no sealer
    assert c.conclusion == "failure"
    assert "signing" in c.title.lower()


def test_success_seals_and_self_verifies_before_posting_green():
    # A green check is posted only after a signed attestation is produced and self-verified.
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(approved=H))
    c = run_gate(fp, _inputs([vr("tests")]), sealer=lambda a, b: _fake_attestation())
    assert c.conclusion == "success"
    assert fp.posted[0].conclusion.conclusion == "success"


def test_signing_failure_blocks_the_green_check():
    from siglum.sealing.seal import SigningError
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(approved=H))

    def boom(assessment, binding):
        raise SigningError("no ambient OIDC credential")

    c = run_gate(fp, _inputs([vr("tests")]), sealer=boom)
    assert c.conclusion == "failure"
    assert "signing failed" in c.title
    assert fp.posted[0].conclusion.conclusion == "failure"


def test_a_failing_verdict_is_not_signed():
    # No point signing a failure; the sealer must not be invoked unless the verdict is success.
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(approved=H))
    calls = []

    def sealer(assessment, binding):
        calls.append(assessment)
        return _fake_attestation()

    run_gate(fp, _inputs([vr("tests", status=ValidatorStatus.FAILED)]), sealer=sealer)
    assert calls == []


def test_approval_required_without_an_approval_blocks():
    # Approval required but the head carries no current approval -> fail closed (the old
    # optional compare no-oped here).
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(approved=None))
    c = run_gate(fp, _inputs([vr("tests")], approval=True))
    assert c.conclusion == "failure"
    assert "approval not proven" in c.title
    assert "no current approving review" in c.summary


def test_approval_required_with_a_matching_approval_succeeds():
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(approved=H))
    c = run_gate(fp, _inputs([vr("tests")], approval=True))
    assert c.conclusion == "success"


def test_merge_group_approval_blocks_when_branch_does_not_require_review():
    # A merge_group with approval required, but the protected branch does not require a
    # review, cannot be proven -> fail closed.
    cand = "c" * 40
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(candidate=cand, approved=cand),
                      enforcement=_enforced(requires_review=False))
    c = run_gate(fp, _inputs([vr("tests")], approval=True))
    assert c.conclusion == "failure"
    assert "approval not proven" in c.title


def test_merge_group_approval_succeeds_when_branch_requires_review():
    # The protected branch requires an approving review, so the merge queue would not have
    # admitted an unapproved PR; the candidate is proven and merge proceeds.
    cand = "c" * 40
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(candidate=cand, approved=cand),
                      enforcement=_enforced(requires_review=True))
    c = run_gate(fp, _inputs([vr("tests")], approval=True))
    assert c.conclusion == "success"
    assert fp.posted[0].head_sha == cand


def test_merge_group_approval_fails_closed_when_branch_protection_unreadable():
    # If the queue prerequisite cannot be read, the approval cannot be verified -> fail closed.
    cand = "c" * 40
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(candidate=cand, approved=cand),
                      enforcement_error=True)
    c = run_gate(fp, _inputs([vr("tests")], approval=True))
    assert c.conclusion == "failure"
    assert "approval not verified" in c.title


def test_merge_group_targeting_a_non_default_branch_fails_closed():
    # The prerequisite is the default branch's protection; a merge_group
    # for another branch (e.g. release) cannot be proven from it, so fail closed.
    cand = "c" * 40
    fp = FakeProvider(
        run=run_ctx(),
        merge=merge_ctx(candidate=cand, approved=cand, base_ref="refs/heads/release"),
        enforcement=_enforced(requires_review=True),  # default_branch is "main"
    )
    c = run_gate(fp, _inputs([vr("tests")], approval=True))
    assert c.conclusion == "failure"
    assert "merge_group target not supported" in c.title


def test_merge_queue_binds_the_candidate_sha_not_head():
    # in a merge queue the subject is the merge_group candidate; the posted check targets it
    cand = "c" * 40
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(candidate=cand, approved=cand))
    c = run_gate(fp, _inputs([vr("tests")]))
    # change head==H but subject==candidate; assessment is built with that candidate so they match
    assert c.conclusion == "success"
    assert fp.posted[0].head_sha == cand


def test_the_sealed_assessment_carries_both_policy_hashes():
    # The canonical parsed-policy hash passes through the gate untouched, and the
    # anchored-file-digests hash is recorded separately, so an external verifier can
    # recompute each from its own source (the policy file; the repo at base_sha).
    import re
    captured = []

    def sealer(assessment, binding):
        captured.append(assessment)
        return _fake_attestation()

    fp = FakeProvider(run=run_ctx(), merge=merge_ctx())
    c = run_gate(fp, _inputs([vr("tests")]), sealer=sealer)
    assert c.conclusion == "success"
    policy = captured[0].bundle.policy
    assert policy.policy_hash == "p" * 40                       # untouched input
    assert re.fullmatch(r"[0-9a-f]{64}", policy.anchored_inputs_hash)


def test_the_sealer_receives_the_run_binding_for_the_gated_subject():
    # The signed statement must be able to name the exact run, so run_gate hands the sealer
    # the run binding alongside the assessment, already bound to the mergeable subject.
    bindings = []

    def sealer(assessment, binding):
        bindings.append(binding)
        return _fake_attestation()

    fp = FakeProvider(run=run_ctx(), merge=merge_ctx())
    c = run_gate(fp, _inputs([vr("tests")]), sealer=sealer)
    assert c.conclusion == "success"
    assert bindings[0].head_sha == H
    assert bindings[0].run_id == "r1"

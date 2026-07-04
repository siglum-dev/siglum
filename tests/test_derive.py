from siglum.verdict import Verdict, Coverage, Independence, ValidatorStatus, DEFINITE
from siglum.derive import assess
from siglum.models import (
    Change, PolicyRef, ValidatorResult, EvidenceBundle, ValidatorAuthority, GateIdentityPolicy,
)


def test_enum_values_are_stable_strings():
    assert Verdict.PASS.value == "PASS"
    assert Coverage.INCOMPLETE.value == "INCOMPLETE"
    assert Independence.NOT_REQUIRED.value == "NOT_REQUIRED"
    assert ValidatorStatus.ERRORED.value == "ERRORED"


def test_definite_statuses():
    assert DEFINITE == {ValidatorStatus.PASSED, ValidatorStatus.FAILED}


def _authority(wref="o/r/.github/workflows/seal.yml@refs/heads/main", repo="o/r", repo_id="123",
               runner="github-hosted"):
    return ValidatorAuthority(repository=repo, repository_id=repo_id, workflow_ref=wref,
                              ref=wref.partition("@")[2], runner_class=runner)


def _pinned(repo="o/r", repo_id="123", path=".github/workflows/seal.yml",
            refs=("refs/heads/main",)):
    return GateIdentityPolicy(repository=repo, workflow_path=path, protected_refs=refs,
                              repository_id=repo_id)


def _b(validators, independence_required=False, change_author="alice", authority=None,
       gate_identity=None):
    return EvidenceBundle(
        change=Change(repo="o/r", base_sha="b"*40, head_sha="h"*40, merge_base="m"*40),
        policy=PolicyRef(policy_id="default", policy_hash="d"*64,
                         independence_required=independence_required,
                         anchored_inputs_hash="c"*64),
        validators=tuple(validators),
        validator_authority=authority if authority is not None else _authority(),
        change_author=change_author,
        gate_identity=gate_identity,
    )


def _v(status, required=True, vid="tests"):
    return ValidatorResult(id=vid, version="1", status=status, required=required,
                           artifact_digest="sha256:" + "a"*64)


def test_all_required_passed_is_pass_full_eligible():
    a = assess(_b([_v(ValidatorStatus.PASSED)]))
    assert (a.verdict, a.coverage, a.merge_eligible) == (Verdict.PASS, Coverage.FULL, True)


def test_required_failed_is_fail_not_eligible():
    a = assess(_b([_v(ValidatorStatus.FAILED)]))
    assert a.verdict == Verdict.FAIL and a.merge_eligible is False


def test_required_errored_is_error_not_eligible():
    a = assess(_b([_v(ValidatorStatus.ERRORED)]))
    assert a.verdict == Verdict.ERROR and a.merge_eligible is False


def test_skipped_required_is_pass_but_incomplete_not_eligible():
    a = assess(_b([_v(ValidatorStatus.PASSED), _v(ValidatorStatus.SKIPPED, vid="scan")]))
    assert a.verdict == Verdict.PASS
    assert a.coverage == Coverage.INCOMPLETE and a.merge_eligible is False
    assert any(g.validator_id == "scan" for g in a.coverage_gaps)


def test_unknown_required_is_incomplete():
    a = assess(_b([_v(ValidatorStatus.UNKNOWN)]))
    assert a.coverage == Coverage.INCOMPLETE and a.merge_eligible is False


def test_non_required_skip_does_not_break_coverage():
    a = assess(_b([_v(ValidatorStatus.PASSED), _v(ValidatorStatus.SKIPPED, required=False, vid="x")]))
    assert a.coverage == Coverage.FULL and a.merge_eligible is True


def test_independence_not_required_is_not_required():
    a = assess(_b([_v(ValidatorStatus.PASSED)], independence_required=False))
    assert a.independence == Independence.NOT_REQUIRED and a.merge_eligible is True


def test_independence_required_without_gate_identity_fails_closed():
    # Required but no expected identity configured -> cannot prove it -> UNMET, not eligible.
    a = assess(_b([_v(ValidatorStatus.PASSED)], independence_required=True, gate_identity=None))
    assert a.independence == Independence.UNMET and a.merge_eligible is False


def test_independence_required_authority_matches_pinned_gate_is_satisfied():
    a = assess(_b([_v(ValidatorStatus.PASSED)], independence_required=True,
                  authority=_authority(), gate_identity=_pinned()))
    assert a.independence == Independence.SATISFIED and a.merge_eligible is True


def test_independence_required_authority_off_a_pull_ref_is_unmet():
    # A same-repo workflow running off the PR ref is NOT the protected org-pinned gate.
    a = assess(_b([_v(ValidatorStatus.PASSED)], independence_required=True,
                  authority=_authority(wref="o/r/.github/workflows/seal.yml@refs/pull/7/merge"),
                  gate_identity=_pinned()))
    assert a.independence == Independence.UNMET and a.merge_eligible is False


def test_decision_hash_changes_when_a_status_changes():
    a = assess(_b([_v(ValidatorStatus.PASSED)]))
    b = assess(_b([_v(ValidatorStatus.FAILED)]))
    assert a.decision_hash != b.decision_hash


def test_change_author_is_audit_only_and_not_in_the_decision_hash():
    # change_author is recorded for audit but is NOT a decision input, so two changes with
    # identical evidence and different authors share one decision_hash.
    a = assess(_b([_v(ValidatorStatus.PASSED)], change_author="alice"))
    b = assess(_b([_v(ValidatorStatus.PASSED)], change_author="mallory"))
    assert a.decision_hash == b.decision_hash


def test_decision_hash_covers_the_anchored_inputs_hash():
    # The anchored-file-digests hash is decision-relevant evidence, distinct from the
    # canonical policy hash, and both are committed by the decision hash.
    import dataclasses
    base = _b([_v(ValidatorStatus.PASSED)])
    with_anchor = dataclasses.replace(
        base, policy=dataclasses.replace(base.policy, anchored_inputs_hash="a" * 64)
    )
    assert assess(base).decision_hash != assess(with_anchor).decision_hash


def test_policy_hash_and_anchored_inputs_hash_are_separate_payload_fields():
    import dataclasses
    bundle = _b([_v(ValidatorStatus.PASSED)])
    bundle = dataclasses.replace(
        bundle, policy=dataclasses.replace(bundle.policy, anchored_inputs_hash="a" * 64)
    )
    from siglum.predicate import build_predicate
    policy = build_predicate(assess(bundle))["predicate"]["policy"]
    assert policy["policy_hash"] == "d" * 64
    assert policy["anchored_inputs_hash"] == "a" * 64

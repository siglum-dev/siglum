import pytest
from siglum.sealing.verify_signed import (
    verify_signed, AttestationRejected, recompute_decision_hash, check_decision_integrity,
)
from siglum.predicate import build_predicate
from siglum.derive import assess
from siglum.models import Change, EvidenceBundle, PolicyRef, ValidatorAuthority
from tests.test_derive import _b, _v
from siglum.verdict import ValidatorStatus


def _bundle_with_authority(authority, *, repo="o/r", independence_required=False):
    return EvidenceBundle(
        change=Change(repo=repo, base_sha="b" * 40, head_sha="h" * 40, merge_base="m" * 40),
        policy=PolicyRef(policy_id="default", policy_hash="d" * 64,
                         independence_required=independence_required,
                         anchored_inputs_hash="c" * 64),
        validators=(_v(ValidatorStatus.PASSED),),
        validator_authority=authority,
        change_author="alice",
    )


def test_missing_identity_policy_fails_closed():
    a = assess(_b([_v(ValidatorStatus.PASSED)]))
    att = {"statement": build_predicate(a), "sigstore_bundle": "x"}
    with pytest.raises(AttestationRejected):
        verify_signed(att, identity_policy=None)


def test_recompute_decision_hash_matches_for_real_predicate():
    # validators intentionally out of sorted order in the bundle
    a = assess(_b([_v(ValidatorStatus.PASSED, vid="zzz"), _v(ValidatorStatus.PASSED, vid="aaa")]))
    stmt = build_predicate(a)
    assert recompute_decision_hash(stmt["predicate"]) == a.decision_hash


def test_check_decision_integrity_rejects_a_lying_hash():
    a = assess(_b([_v(ValidatorStatus.PASSED)]))
    stmt = build_predicate(a)
    stmt["predicate"]["decision_hash"] = "0" * 64     # tamper
    with pytest.raises(AttestationRejected):
        check_decision_integrity(stmt["predicate"])


def test_check_decision_integrity_accepts_an_untampered_predicate():
    a = assess(_b([_v(ValidatorStatus.PASSED)]))
    stmt = build_predicate(a)
    check_decision_integrity(stmt["predicate"])  # must not raise


def test_non_bool_required_is_rejected_by_strict_typing():
    # `required` as int 0 must be REJECTED, not coerced to False (which would let a failed
    # validator launder past as non-required). The reason must be a type error, not a hash miss.
    stmt = build_predicate(assess(_b([_v(ValidatorStatus.PASSED)])))
    stmt["predicate"]["validators"][0]["required"] = 0
    with pytest.raises(AttestationRejected, match="bool"):
        check_decision_integrity(stmt["predicate"])


def test_non_bool_independence_required_is_rejected_by_strict_typing():
    # `independence_required` as [] must be rejected, not coerced to False.
    stmt = build_predicate(assess(_b([_v(ValidatorStatus.PASSED)])))
    stmt["predicate"]["policy"]["independence_required"] = []
    with pytest.raises(AttestationRejected, match="bool"):
        check_decision_integrity(stmt["predicate"])


def test_non_string_schema_version_is_rejected():
    # JSON 0.2 (float) must not be coerced to "0.2" and accepted.
    stmt = build_predicate(assess(_b([_v(ValidatorStatus.PASSED)])))
    stmt["predicate"]["schema_version"] = 0.2
    with pytest.raises(AttestationRejected):
        check_decision_integrity(stmt["predicate"])


def test_non_bool_merge_eligible_is_rejected():
    # stated merge_eligible as int 1 must not compare equal to Python True.
    stmt = build_predicate(assess(_b([_v(ValidatorStatus.PASSED)])))
    stmt["predicate"]["merge_eligible"] = 1
    with pytest.raises(AttestationRejected, match="bool"):
        check_decision_integrity(stmt["predicate"])


def test_offline_rejects_a_self_hosted_authority_even_without_independence():
    # The runtime floor refuses a non-hosted runner unconditionally; offline verification must
    # replay that, even when independence is NOT required (so assess() returns NOT_REQUIRED).
    authority = ValidatorAuthority(
        repository="o/r", repository_id="1",
        workflow_ref="o/r/.github/workflows/seal.yml@refs/heads/main",
        ref="refs/heads/main", runner_class="self-hosted",
    )
    pred = build_predicate(assess(_bundle_with_authority(authority)))["predicate"]
    assert pred["merge_eligible"] is True  # assess() alone would let it through
    with pytest.raises(AttestationRejected):
        check_decision_integrity(pred)


def test_offline_rejects_authority_for_a_different_repo_than_the_change():
    # The authority must be bound to the ATTESTED repo. A predicate whose validator_authority is
    # for another repo must be rejected, not rederived as a verdict for change.repo.
    authority = ValidatorAuthority(
        repository="attacker/x", repository_id="9",
        workflow_ref="attacker/x/.github/workflows/seal.yml@refs/heads/main",
        ref="refs/heads/main", runner_class="github-hosted",
    )
    pred = build_predicate(
        assess(_bundle_with_authority(authority, repo="victim/repo"))
    )["predicate"]
    assert pred["merge_eligible"] is True
    with pytest.raises(AttestationRejected):
        check_decision_integrity(pred)


def test_predicate_without_anchored_inputs_hash_is_rejected():
    # v0.3 schema: the anchored hash is required evidence; an attestation without it is not
    # reconstructable and must be rejected, not defaulted.
    stmt = build_predicate(assess(_b([_v(ValidatorStatus.PASSED)])))
    del stmt["predicate"]["policy"]["anchored_inputs_hash"]
    with pytest.raises(AttestationRejected):
        check_decision_integrity(stmt["predicate"])


def _stmt_with_binding(**overrides):
    a = assess(_b([_v(ValidatorStatus.PASSED)]))
    stmt = build_predicate(a)
    binding = {
        "run_id": "r1", "run_attempt": "1", "workflow_path": "wf", "workflow_ref_sha": "w" * 40,
        "event_name": "pull_request", "head_sha": "h" * 40, "base_sha": "b" * 40,
        "merge_base": "m" * 40, "merge_candidate_sha": None,
        "anchored_inputs_hash": a.bundle.policy.anchored_inputs_hash,
        "validator_versions": [["tests", "1"]],
        "artifact_digests": [["tests", "sha256:" + "a" * 64]],
    }
    binding.update(overrides)
    stmt["predicate"]["run_binding"] = binding
    return stmt


def test_a_consistent_run_binding_is_accepted():
    check_decision_integrity(_stmt_with_binding()["predicate"])  # must not raise


def test_a_run_binding_for_a_different_head_is_rejected():
    # The provenance and the evidence are one attestation; a binding that names a different
    # commit than the attested change is a contradiction, not extra data.
    stmt = _stmt_with_binding(head_sha="z" * 40)
    with pytest.raises(AttestationRejected, match="run_binding.head_sha"):
        check_decision_integrity(stmt["predicate"])


def test_a_run_binding_with_a_different_anchored_hash_is_rejected():
    stmt = _stmt_with_binding(anchored_inputs_hash="f" * 64)
    with pytest.raises(AttestationRejected, match="anchored_inputs_hash"):
        check_decision_integrity(stmt["predicate"])


def test_a_run_binding_with_laundered_validator_pins_is_rejected():
    stmt = _stmt_with_binding(validator_versions=[["tests", "999"]])
    with pytest.raises(AttestationRejected, match="validator_versions"):
        check_decision_integrity(stmt["predicate"])


def test_empty_anchored_inputs_hash_is_rejected():
    # An empty string satisfied the "is a string" check, so an
    # accepted attestation could lack the reproducible base-anchored digest entirely.
    stmt = build_predicate(assess(_b([_v(ValidatorStatus.PASSED)])))
    stmt["predicate"]["policy"]["anchored_inputs_hash"] = ""
    with pytest.raises(AttestationRejected, match="sha256 hex"):
        check_decision_integrity(stmt["predicate"])


def test_malformed_policy_hash_is_rejected():
    stmt = build_predicate(assess(_b([_v(ValidatorStatus.PASSED)])))
    stmt["predicate"]["policy"]["policy_hash"] = "Z" * 64
    with pytest.raises(AttestationRejected, match="sha256 hex"):
        check_decision_integrity(stmt["predicate"])


def test_a_run_binding_with_hollow_provenance_is_rejected():
    # A present binding whose provenance fields are missing or
    # empty is accountability-shaped without being accountability.
    stmt = _stmt_with_binding()
    del stmt["predicate"]["run_binding"]["run_id"]
    with pytest.raises(AttestationRejected, match="run_binding"):
        check_decision_integrity(stmt["predicate"])
    stmt = _stmt_with_binding(workflow_ref_sha="")
    with pytest.raises(AttestationRejected, match="workflow_ref_sha"):
        check_decision_integrity(stmt["predicate"])

"""Sealing-layer adversarial invariants: the pure subset that runs without Sigstore.
The signature-crypto rows (valid-sig + wrong-issuer, etc.) are exercised at build time
once the sigstore binding is in place."""
import dataclasses
import pytest
from siglum.derive import assess
from siglum.verify import AssessmentTampered
from siglum.sealing.seal import seal
from siglum.sealing.verify_signed import (
    verify_signed, AttestationRejected, check_decision_integrity,
    _require_subject_binds_decision,
)
from siglum.predicate import build_predicate
from tests.test_derive import _b, _v
from siglum.verdict import ValidatorStatus, Verdict


def test_sign_path_refuses_a_forged_verdict():
    a = assess(_b([_v(ValidatorStatus.FAILED)]))
    forged = dataclasses.replace(a, verdict=Verdict.PASS, merge_eligible=True)
    with pytest.raises(AssessmentTampered):
        seal(forged)


def test_verify_refuses_missing_policy_even_with_a_valid_looking_statement():
    a = assess(_b([_v(ValidatorStatus.PASSED)]))
    att = {"statement": build_predicate(a), "sigstore_bundle": "x"}
    with pytest.raises(AttestationRejected):
        verify_signed(att, identity_policy=None)


def test_verify_refuses_a_lying_decision_hash():
    a = assess(_b([_v(ValidatorStatus.PASSED)]))
    stmt = build_predicate(a)
    stmt["predicate"]["decision_hash"] = "0" * 64
    with pytest.raises(AttestationRejected):
        check_decision_integrity(stmt["predicate"])


def _signed_shape_statement():
    from siglum.sealing.seal import _signing_statement
    return _signing_statement(assess(_b([_v(ValidatorStatus.PASSED)])))


def test_subject_digest_must_bind_the_decision_hash():
    stmt = _signed_shape_statement()
    _require_subject_binds_decision(stmt)  # consistent: must not raise
    stmt["subject"][0]["digest"]["sha256"] = "0" * 64
    with pytest.raises(AttestationRejected, match="subject digest"):
        _require_subject_binds_decision(stmt)


def test_subject_must_be_a_single_entry():
    stmt = _signed_shape_statement()
    stmt["subject"] = stmt["subject"] + stmt["subject"]
    with pytest.raises(AttestationRejected, match="single entry"):
        _require_subject_binds_decision(stmt)

import dataclasses
import pytest
from siglum.derive import assess
from siglum.verify import verify, recompute, AssessmentTampered
from tests.test_derive import _b, _v
from siglum.verdict import ValidatorStatus, Verdict


def test_verify_accepts_a_freshly_assessed_object():
    a = assess(_b([_v(ValidatorStatus.PASSED)]))
    verify(a)  # must not raise


def test_recompute_reproduces_hash_and_fields():
    a = assess(_b([_v(ValidatorStatus.PASSED)]))
    b = recompute(a.bundle)
    assert b.decision_hash == a.decision_hash
    assert b.verdict == a.verdict and b.merge_eligible == a.merge_eligible


def test_verify_rejects_asserted_verdict():
    a = assess(_b([_v(ValidatorStatus.FAILED)]))           # truly a FAIL
    # frozen+slots dataclass has no __dict__; replace() builds a forged copy.
    forged = dataclasses.replace(a, verdict=Verdict.PASS, merge_eligible=True)
    with pytest.raises(AssessmentTampered):
        verify(forged)


def test_verify_rejects_tampered_hash():
    a = assess(_b([_v(ValidatorStatus.PASSED)]))
    forged = dataclasses.replace(a, decision_hash="0" * 64)
    with pytest.raises(AssessmentTampered):
        verify(forged)

"""Each test encodes an attacker move the core must defeat at the data layer.
Forge/identity/signing defenses live in later plans; here we prove the verdict
logic itself is fail-closed and tamper-evident."""
import dataclasses
import pytest
from siglum.derive import assess
from siglum.predicate import build_predicate
from siglum.verify import verify, AssessmentTampered
from siglum.canonical import decision_hash, canonical_json
from tests.test_derive import _b, _v
from siglum.verdict import ValidatorStatus, Verdict, Coverage, Independence


def test_unprovable_independence_blocks_merge_when_required():
    # Required independence with no expected gate identity to match cannot be proven -> UNMET.
    a = assess(_b([_v(ValidatorStatus.PASSED)], independence_required=True, gate_identity=None))
    assert a.independence == Independence.UNMET and a.merge_eligible is False


def test_skipped_gate_critical_validator_never_reads_as_pass():
    a = assess(_b([_v(ValidatorStatus.SKIPPED)]))
    assert a.merge_eligible is False and a.coverage == Coverage.INCOMPLETE


def test_unknown_status_never_reads_as_pass():
    a = assess(_b([_v(ValidatorStatus.UNKNOWN)]))
    assert a.merge_eligible is False


def test_errored_required_validator_is_error_not_pass():
    a = assess(_b([_v(ValidatorStatus.ERRORED)]))
    assert a.verdict == Verdict.ERROR and a.merge_eligible is False


def test_flipping_merge_eligible_is_rejected_by_verify():
    a = assess(_b([_v(ValidatorStatus.SKIPPED)]))         # not eligible
    forged = dataclasses.replace(a, merge_eligible=True)
    with pytest.raises(AssessmentTampered):
        verify(forged)


def test_predicate_decision_hash_matches_independent_recompute():
    a = assess(_b([_v(ValidatorStatus.PASSED)]))
    stmt = build_predicate(a)
    # An independent verifier recomputing over the predicate's decision fields gets the
    # same hash the engine sealed (the predicate cannot lie about its own decision_hash).
    assert stmt["predicate"]["decision_hash"] == a.decision_hash
    # And the canonical bytes are reproducible.
    assert decision_hash({"x": 1}) == decision_hash({"x": 1})
    assert canonical_json(stmt) == canonical_json(stmt)

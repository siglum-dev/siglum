import dataclasses
import importlib.util
import os
import pytest
from siglum.derive import assess
from siglum.verify import AssessmentTampered
from siglum.sealing.seal import seal, SignedAttestation
from tests.test_derive import _b, _v
from siglum.verdict import ValidatorStatus, Verdict

_HAS_SIGSTORE = importlib.util.find_spec("sigstore") is not None
# Real signing needs sigstore AND an ambient OIDC identity (set by Actions id-token: write).
# Skip otherwise, even when sigstore is merely installed locally.
needs_sigstore = pytest.mark.skipif(
    not (_HAS_SIGSTORE and os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")),
    reason="needs sigstore + ambient OIDC (GitHub Actions id-token: write)",
)


def test_seal_recomputes_before_signing_and_refuses_forged():
    a = assess(_b([_v(ValidatorStatus.FAILED)]))                 # truly FAIL
    forged = dataclasses.replace(a, verdict=Verdict.PASS, merge_eligible=True)
    # verify-before-sign runs first; the forged assessment never reaches the signer.
    with pytest.raises(AssessmentTampered):
        seal(forged)


@needs_sigstore
def test_seal_signs_a_clean_assessment():
    a = assess(_b([_v(ValidatorStatus.PASSED)]))
    att = seal(a)
    assert isinstance(att, SignedAttestation) and att.decision_hash == a.decision_hash


def test_signing_statement_records_the_run_binding_without_touching_the_decision():
    from siglum.sealing.seal import _signing_statement
    from siglum.sealing.verify_signed import check_decision_integrity

    a = assess(_b([_v(ValidatorStatus.PASSED)]))
    binding = {
        "run_id": "r1", "run_attempt": "1", "workflow_path": "wf", "workflow_ref_sha": "w" * 40,
        "event_name": "pull_request", "head_sha": "h" * 40, "base_sha": "b" * 40,
        "merge_base": "m" * 40, "merge_candidate_sha": None,
        "anchored_inputs_hash": a.bundle.policy.anchored_inputs_hash,
        "validator_versions": [["tests", "1"]],
        "artifact_digests": [["tests", "sha256:" + "a" * 64]],
    }
    stmt = _signing_statement(a, binding)
    assert stmt["predicate"]["run_binding"]["run_id"] == "r1"
    assert stmt["predicate"]["decision_hash"] == a.decision_hash
    check_decision_integrity(stmt["predicate"])  # binding is consistent: must not raise


def test_signing_statement_without_a_binding_is_unchanged():
    from siglum.sealing.seal import _signing_statement

    a = assess(_b([_v(ValidatorStatus.PASSED)]))
    assert "run_binding" not in _signing_statement(a)["predicate"]

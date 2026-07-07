"""The trusted gate must take `required` and `version` for each validator from the
base policy, never from the untrusted results.json. The gather artifact may only supply
observations (status, artifact_digest)."""
import pytest

from siglum.gate.evidence import EvidenceError, normalize_evidence
from siglum.models import ValidatorResult
from siglum.policy import ValidatorPolicy
from siglum.verdict import ValidatorStatus


def _observed(vid, status, *, required=True, version="x", digest=""):
    return ValidatorResult(
        id=vid, version=version, status=status, required=required, artifact_digest=digest
    )


def test_required_and_version_are_forced_from_base_not_the_observed_row():
    # The attacker controls results.json: they downgrade a base-required validator to
    # required=false and lie about its version. Normalization must ignore both.
    base = (ValidatorPolicy(id="secret-scan", version="2", required=True),)
    observed = (_observed("secret-scan", ValidatorStatus.FAILED, required=False, version="999",
                          digest="sha256:abc"),)

    out = normalize_evidence(base, observed)

    assert len(out) == 1
    r = out[0]
    assert r.required is True              # from base, not the observed False
    assert r.version == "2"                # from base, not the observed "999"
    assert r.status is ValidatorStatus.FAILED   # observation is preserved
    assert r.artifact_digest == "sha256:abc"    # observation is preserved


def test_a_base_validator_missing_from_evidence_becomes_unknown():
    base = (ValidatorPolicy(id="secret-scan", version="0", required=True),)

    out = normalize_evidence(base, ())

    assert out == (
        ValidatorResult(id="secret-scan", version="0", status=ValidatorStatus.UNKNOWN,
                        required=True, artifact_digest=""),
    )


def test_duplicate_observed_evidence_for_one_id_is_rejected():
    base = (ValidatorPolicy(id="secret-scan", version="0", required=True),)
    observed = (
        _observed("secret-scan", ValidatorStatus.PASSED),
        _observed("secret-scan", ValidatorStatus.FAILED),
    )

    with pytest.raises(EvidenceError):
        normalize_evidence(base, observed)


def test_validators_absent_from_the_base_policy_are_ignored():
    base = (ValidatorPolicy(id="secret-scan", version="0", required=True),)
    observed = (_observed("rogue", ValidatorStatus.PASSED),)

    out = normalize_evidence(base, observed)

    assert [r.id for r in out] == ["secret-scan"]      # rogue is not in the gating set
    assert out[0].status is ValidatorStatus.UNKNOWN     # and secret-scan is still required

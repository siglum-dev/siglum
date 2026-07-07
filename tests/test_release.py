import json

import pytest

from siglum.derive import assess
from siglum.models import GateIdentityPolicy
from siglum.predicate import build_predicate
from siglum.release import ReleaseCheckRejected, check_statement, load_gate_identity
from siglum.verdict import ValidatorStatus
from tests.test_derive import _b, _v


def _statement(status=ValidatorStatus.PASSED):
    return build_predicate(assess(_b([_v(status)])))


def _gate_identity(path=".github/workflows/seal.yml"):
    return GateIdentityPolicy(
        repository="o/r", workflow_path=path, protected_refs=("refs/heads/main",)
    )


def test_release_check_accepts_authority_matching_a_required_gate_identity():
    # A downstream verifier can demand the recorded authority match a specific gate identity.
    result = check_statement(_statement(), commit="h" * 40, gate_identity=_gate_identity())
    assert result.commit == "h" * 40


def test_release_check_rejects_authority_not_matching_a_stricter_gate_identity():
    # The recorded authority is for seal.yml; a downstream verifier demanding a different
    # workflow rejects it, independent of what the predicate's own gate_identity says.
    with pytest.raises(ReleaseCheckRejected, match="gate identity"):
        check_statement(
            _statement(), commit="h" * 40,
            gate_identity=_gate_identity(path=".github/workflows/OTHER.yml"),
        )


def test_load_gate_identity_round_trips(tmp_path):
    path = tmp_path / "gate-identity.toml"
    path.write_text(
        'repository = "o/r"\n'
        'workflow_path = ".github/workflows/siglum-seal-enforce.yml"\n'
        'protected_refs = ["refs/heads/main"]\n'
        'repository_id = "123"\n',
        encoding="utf-8",
    )
    gi = load_gate_identity(path)
    assert gi.repository == "o/r"
    assert gi.protected_refs == ("refs/heads/main",)


def test_release_check_accepts_merge_eligible_matching_commit():
    stmt = _statement()
    result = check_statement(stmt, commit="h" * 40)
    assert result.commit == "h" * 40
    assert result.decision_hash == stmt["predicate"]["decision_hash"]


def test_release_check_rejects_subject_mismatch():
    with pytest.raises(ReleaseCheckRejected, match="attestation subject"):
        check_statement(_statement(), commit="x" * 40)


def test_release_check_rejects_failed_predicate():
    with pytest.raises(ReleaseCheckRejected, match="not merge-eligible"):
        check_statement(_statement(ValidatorStatus.FAILED), commit="h" * 40)


def test_release_check_rejects_tampered_decision_hash():
    stmt = json.loads(json.dumps(_statement()))
    stmt["predicate"]["decision_hash"] = "0" * 64
    with pytest.raises(Exception, match="decision_hash does not rederive"):
        check_statement(stmt, commit="h" * 40)


def test_release_check_accepts_the_real_signed_statement_shape():
    # sealing.seal signs a statement whose subject digest is the decision_hash (sha256), not
    # a gitCommit. Release verification must accept that real shape, reading the commit from
    # the predicate body.
    from siglum.sealing.seal import _signing_statement

    a = assess(_b([_v(ValidatorStatus.PASSED)]))
    stmt = _signing_statement(a)
    assert "sha256" in stmt["subject"][0]["digest"]
    result = check_statement(stmt, commit=a.bundle.change.head_sha)
    assert result.commit == a.bundle.change.head_sha

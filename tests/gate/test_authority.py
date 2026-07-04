"""The gate verifies its OWN run identity from the verified OIDC token. The unconditional
floor (authority_from_claims) requires a workflow in the gated repository on a hosted runner, or
the gate fails closed: this kills cross-repo token replay, fork-workflow impersonation, and
self-hosted tampering. The tight check (require_gate_identity) additionally pins the exact gate
workflow + protected ref + immutable repo id, and drives structural independence."""
import pytest

from siglum.gate.authority import authority_from_claims, require_gate_identity
from siglum.gate.errors import GateRefused
from siglum.models import GateIdentityPolicy


def _claims(repo="o/r", wref="o/r/.github/workflows/seal.yml@refs/heads/main",
            runner="github-hosted", repo_id="123"):
    return {"repository": repo, "job_workflow_ref": wref, "runner_environment": runner,
            "repository_id": repo_id}


def _expected(repo="o/r", repo_id="123", path=".github/workflows/seal.yml",
              refs=("refs/heads/main",)):
    return GateIdentityPolicy(repository=repo, workflow_path=path, protected_refs=refs,
                              repository_id=repo_id)


def test_accepts_a_token_from_this_repo_on_a_hosted_runner():
    a = authority_from_claims(_claims(), gated_repo="o/r")
    assert a.repository == "o/r"
    assert a.runner_class == "github-hosted"


def test_extracts_repository_id_and_pinned_ref_from_claims():
    a = authority_from_claims(_claims(repo_id="999"), gated_repo="o/r")
    assert a.repository_id == "999"
    assert a.ref == "refs/heads/main"
    assert a.workflow_ref == "o/r/.github/workflows/seal.yml@refs/heads/main"


def test_require_gate_identity_passes_for_the_org_pinned_gate():
    a = authority_from_claims(_claims(), gated_repo="o/r")
    require_gate_identity(a, _expected())  # must not raise


def test_require_gate_identity_fails_closed_on_a_different_workflow():
    a = authority_from_claims(
        _claims(wref="o/r/.github/workflows/evil.yml@refs/heads/main"), gated_repo="o/r"
    )
    with pytest.raises(GateRefused):
        require_gate_identity(a, _expected())


def test_rejects_a_token_from_a_different_repository():
    with pytest.raises(GateRefused):
        authority_from_claims(_claims(repo="attacker/x"), gated_repo="o/r")


def test_rejects_a_workflow_that_is_not_in_this_repository():
    with pytest.raises(GateRefused):
        authority_from_claims(
            _claims(wref="other/x/.github/workflows/w.yml@refs/heads/main"), gated_repo="o/r"
        )


def test_rejects_a_self_hosted_runner():
    with pytest.raises(GateRefused):
        authority_from_claims(_claims(runner="self-hosted"), gated_repo="o/r")

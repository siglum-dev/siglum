"""The gate self-verifies the attestation it just signed against an identity policy pinned
to the exact org-pinned seal workflow, not merely the repository. A different workflow in the
same repo must not be able to produce a signature the gate accepts."""
from siglum.gate.run import expected_signer_identities, gate_self_verify_policy
from siglum.models import GateIdentityPolicy

ISSUER = "https://token.actions.githubusercontent.com"
SEAL = ".github/workflows/siglum-seal-enforce.yml"


def _gid(repo="o/r", path=SEAL, refs=("refs/heads/main",)):
    return GateIdentityPolicy(repository=repo, workflow_path=path, protected_refs=refs)


def test_expected_signer_identities_one_per_protected_ref():
    gid = _gid(refs=("refs/heads/main", "refs/heads/release"))
    assert expected_signer_identities(gid) == (
        f"https://github.com/o/r/{SEAL}@refs/heads/main",
        f"https://github.com/o/r/{SEAL}@refs/heads/release",
    )


def test_self_verify_policy_pins_the_workflow_identity_when_gate_identity_present():
    pol = gate_self_verify_policy("o/r", _gid())
    assert pol.issuers == (ISSUER,)
    assert pol.repository_patterns == ("o/r",)
    assert pol.subject_patterns == (f"https://github.com/o/r/{SEAL}@refs/heads/main",)


def test_self_verify_policy_is_repo_only_without_a_gate_identity():
    # Independence is opt-in; without a gate identity the sealer can only pin the repository.
    pol = gate_self_verify_policy("o/r", None)
    assert pol.repository_patterns == ("o/r",)
    assert pol.subject_patterns == ()

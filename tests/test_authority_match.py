"""The tight gate-identity match: structural independence is SATISFIED only when
the verified run authority is the org-pinned gate workflow on a protected ref. This is the one
shared predicate used both by the runtime fail-closed and by the recomputable independence
derivation, so the recorded verdict can never drift from the rule that was enforced."""
from siglum.authority import gate_identity_matches, gate_identity_mismatch
from siglum.models import GateIdentityPolicy, ValidatorAuthority


def _auth(
    repo="o/r",
    repo_id="123",
    wref="o/r/.github/workflows/seal.yml@refs/heads/main",
    runner="github-hosted",
):
    ref = wref.partition("@")[2]
    return ValidatorAuthority(
        repository=repo, repository_id=repo_id, workflow_ref=wref, ref=ref, runner_class=runner
    )


def _expected(repo="o/r", repo_id="123", path=".github/workflows/seal.yml", refs=("refs/heads/main",)):
    return GateIdentityPolicy(
        repository=repo, workflow_path=path, protected_refs=refs, repository_id=repo_id
    )


def test_matches_the_org_pinned_gate_on_a_protected_ref():
    assert gate_identity_mismatch(_auth(), _expected()) is None
    assert gate_identity_matches(_auth(), _expected()) is True


def test_rejects_a_different_workflow_in_the_same_repo():
    auth = _auth(wref="o/r/.github/workflows/evil.yml@refs/heads/main")
    assert gate_identity_matches(auth, _expected()) is False


def test_rejects_a_non_protected_ref():
    auth = _auth(wref="o/r/.github/workflows/seal.yml@refs/pull/7/merge")
    assert gate_identity_matches(auth, _expected()) is False


def test_rejects_a_mismatched_repository_id_when_required():
    assert gate_identity_matches(_auth(repo_id="999"), _expected(repo_id="123")) is False


def test_skips_repository_id_check_when_expected_is_unset():
    assert gate_identity_matches(_auth(repo_id="anything"), _expected(repo_id="")) is True


def test_rejects_a_self_hosted_runner():
    assert gate_identity_matches(_auth(runner="self-hosted"), _expected()) is False


def test_rejects_a_different_repository():
    assert gate_identity_matches(_auth(repo="attacker/x"), _expected(repo="o/r")) is False


def test_protected_ref_is_taken_from_workflow_ref_not_the_separate_ref_field():
    # A split identity whose workflow_ref pins a PR ref but whose .ref field claims a
    # protected ref must NOT match. The protected-ref check derives from workflow_ref alone.
    split = ValidatorAuthority(
        repository="o/r", repository_id="123",
        workflow_ref="o/r/.github/workflows/seal.yml@refs/pull/7/merge",
        ref="refs/heads/main",  # lies; independent of workflow_ref
        runner_class="github-hosted",
    )
    assert gate_identity_matches(split, _expected()) is False


def test_rejects_a_workflow_ref_not_prefixed_by_the_repository():
    # Offline: a workflow_ref lacking the "<repo>/" prefix must not match even if the bare
    # path equals the expected workflow_path. Brings the matcher to runtime-floor parity.
    bare = ValidatorAuthority(
        repository="o/r", repository_id="123",
        workflow_ref=".github/workflows/seal.yml@refs/heads/main",  # no "o/r/" prefix
        ref="refs/heads/main", runner_class="github-hosted",
    )
    assert gate_identity_matches(bare, _expected()) is False

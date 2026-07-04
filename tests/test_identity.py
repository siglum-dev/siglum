import pytest
from siglum.sealing.identity import IdentityPolicy
from siglum.sealing.verify_signed import AttestationRejected, _validate_identity_policy

_ISS = "https://token.actions.githubusercontent.com"


def _pol(subject_patterns=(), repository_patterns=(), issuers=(_ISS,),
         require_runner_environment=None):
    return IdentityPolicy(policy_id="p", issuers=issuers,
                          subject_patterns=subject_patterns,
                          repository_patterns=repository_patterns,
                          require_runner_environment=require_runner_environment)


def test_empty_issuers_is_constructed_rejected():
    with pytest.raises(ValueError):
        IdentityPolicy(policy_id="p", issuers=())


def test_exact_policy_is_translatable():
    _validate_identity_policy(_pol(
        subject_patterns=("https://github.com/o/r/.github/workflows/seal.yml@refs/heads/main",),
        repository_patterns=("o/r",),
        require_runner_environment="github-hosted",
    ))  # must not raise


def test_multiple_issuers_are_rejected_not_silently_narrowed():
    # The sigstore translation can enforce exactly one issuer; accepting a multi-issuer
    # policy and enforcing only the first would be a policy that lies about its strictness.
    with pytest.raises(AttestationRejected, match="one issuer"):
        _validate_identity_policy(_pol(issuers=(_ISS, "https://other")))


def test_pattern_characters_are_rejected_not_matched_exactly():
    # sigstore's GitHubWorkflowRepository and Identity are exact matchers; a pattern would
    # never match and the policy would look configured while permanently failing.
    with pytest.raises(AttestationRejected, match="pattern"):
        _validate_identity_policy(_pol(repository_patterns=("o/*",)))
    with pytest.raises(AttestationRejected, match="pattern"):
        _validate_identity_policy(_pol(subject_patterns=("repo:o/r:*",)))


def test_multiple_repository_pins_are_rejected():
    with pytest.raises(AttestationRejected, match="one repository"):
        _validate_identity_policy(_pol(repository_patterns=("o/r", "o/s")))

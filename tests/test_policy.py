import pytest

from siglum.policy import (
    POLICY_PATH,
    PolicyError,
    anchored_paths,
    default_policy,
    parse_policy_bytes,
)


def test_default_policy_is_independence_opt_in():
    # Independence is opt-in: the bare default works on validators alone, and you turn
    # independence on by configuring a [gate_identity]. See test_parses_a_tight_gate_identity.
    policy = default_policy()
    assert policy.independence_required is False
    assert policy.gate_identity is None
    assert policy.required_validator_ids() == ("secret-scan",)
    assert POLICY_PATH in anchored_paths(policy)
    assert ".github/workflows/siglum-gather.yml" in anchored_paths(policy)


def test_parse_policy_derives_required_validators_and_anchor_closure():
    policy = parse_policy_bytes(
        b"""
version = 1
policy_id = "payments"
anchor_paths = ["Makefile"]

[[validators]]
id = "secret-scan"
version = "0"
required = true
anchor_paths = [".github/workflows/scan.yml"]

[[validators]]
id = "lint"
version = "1"
required = false
"""
    )
    assert policy.policy_id == "payments"
    assert policy.required_validator_ids() == ("secret-scan",)
    assert anchored_paths(policy) == (
        ".github/workflows/scan.yml",
        ".siglum/policy.toml",
        "Makefile",
    )
    assert len(policy.policy_ref().policy_hash) == 64


def test_policy_rejects_duplicate_validators():
    with pytest.raises(PolicyError, match="duplicate validator"):
        parse_policy_bytes(
            b"""
[[validators]]
id = "secret-scan"

[[validators]]
id = "secret-scan"
"""
        )


def test_policy_rejects_paths_outside_repo():
    with pytest.raises(PolicyError, match="inside the repository"):
        parse_policy_bytes(
            b"""
[[validators]]
id = "secret-scan"
anchor_paths = ["../escape"]
"""
        )


_GATE_IDENTITY_POLICY = b"""
independence_required = true

[[validators]]
id = "secret-scan"

[gate_identity]
repository = "o/r"
workflow_path = ".github/workflows/siglum-seal-enforce.yml"
protected_refs = ["refs/heads/main"]
repository_id = "12345"
"""


def test_parses_a_tight_gate_identity():
    p = parse_policy_bytes(_GATE_IDENTITY_POLICY)
    assert p.independence_required is True
    assert p.gate_identity is not None
    assert p.gate_identity.repository == "o/r"
    assert p.gate_identity.workflow_path == ".github/workflows/siglum-seal-enforce.yml"
    assert p.gate_identity.protected_refs == ("refs/heads/main",)
    assert p.gate_identity.repository_id == "12345"


def test_independence_required_without_gate_identity_is_rejected_at_load():
    with pytest.raises(PolicyError, match="gate_identity"):
        parse_policy_bytes(
            b"""
independence_required = true

[[validators]]
id = "secret-scan"
"""
        )


def test_rejects_a_wildcard_workflow_path():
    body = _GATE_IDENTITY_POLICY.replace(
        b".github/workflows/siglum-seal-enforce.yml", b".github/workflows/*.yml"
    )
    with pytest.raises(PolicyError, match="exact path"):
        parse_policy_bytes(body)


def test_rejects_empty_protected_refs():
    body = _GATE_IDENTITY_POLICY.replace(b'["refs/heads/main"]', b"[]")
    with pytest.raises(PolicyError, match="protected_refs"):
        parse_policy_bytes(body)


def test_rejects_a_bare_branch_name_as_protected_ref():
    body = _GATE_IDENTITY_POLICY.replace(b'"refs/heads/main"', b'"main"')
    with pytest.raises(PolicyError, match="branch or tag"):
        parse_policy_bytes(body)


def test_gate_identity_is_covered_by_the_policy_hash():
    h1 = parse_policy_bytes(_GATE_IDENTITY_POLICY).policy_ref().policy_hash
    moved = _GATE_IDENTITY_POLICY.replace(b"refs/heads/main", b"refs/heads/release")
    h2 = parse_policy_bytes(moved).policy_ref().policy_hash
    assert h1 != h2


def test_rejects_a_gate_identity_block_without_independence_required():
    # Configuring the identity but not requiring independence would silently DISABLE it. The
    # two settings must agree: both present, or neither.
    body = _GATE_IDENTITY_POLICY.replace(b"independence_required = true\n", b"")
    with pytest.raises(PolicyError, match="independence_required"):
        parse_policy_bytes(body)


def test_rejects_a_head_controlled_pull_request_ref():
    # A refs/pull/... ref is a full ref but head-controlled, so it is not a branch or tag and
    # must not be a valid independence target.
    body = _GATE_IDENTITY_POLICY.replace(b'"refs/heads/main"', b'"refs/pull/7/merge"')
    with pytest.raises(PolicyError, match="branch or tag"):
        parse_policy_bytes(body)


def test_policy_hash_is_reproducible_from_the_policy_bytes_alone():
    # An external verifier holding only the policy file can recompute policy_hash by
    # reparsing it; nothing repository-state-dependent is folded in.
    assert (
        parse_policy_bytes(_GATE_IDENTITY_POLICY).policy_ref().policy_hash
        == parse_policy_bytes(_GATE_IDENTITY_POLICY).policy_ref().policy_hash
    )

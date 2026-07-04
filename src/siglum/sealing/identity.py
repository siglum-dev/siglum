"""Identity model for sealing: the signer (from the Fulcio cert at verify time) and the
policy it must match. A policy with no issuers is rejected at construction; the "no policy
at all" fail-closed gate lives in verify_signed.

The policy is enforced by Sigstore's own exact-match policy classes (see
verify_signed._sigstore_policy). There is deliberately no second matcher here: a parallel
implementation with looser semantics (patterns, multiple issuers) would drift from what is
actually enforced and read stricter than it is."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SignerIdentity:
    issuer: str
    subject: str
    repository: str | None = None
    workflow_ref: str | None = None
    runner_environment: str | None = None


@dataclass(frozen=True, slots=True)
class IdentityPolicy:
    policy_id: str
    issuers: tuple[str, ...]
    subject_patterns: tuple[str, ...] = ()
    repository_patterns: tuple[str, ...] = ()
    require_runner_environment: str | None = None

    def __post_init__(self) -> None:
        if not self.policy_id:
            raise ValueError("policy_id must not be empty")
        if not self.issuers:
            raise ValueError("issuers must not be empty (a policy with no issuers fails closed)")


@dataclass(frozen=True, slots=True)
class IdentityMatch:
    matched: bool
    policy_id: str
    identity: SignerIdentity
    reason: str

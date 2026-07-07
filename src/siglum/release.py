"""Release-side validation gate.

A merge gate does not automatically protect publishing. This module checks that the
commit being released has a Siglum validation predicate that is internally consistent,
merge-eligible, and bound to the exact commit. Signed-bundle verification composes with
the existing Sigstore verifier; unsigned predicates are allowed only for explicit dry runs.
"""
from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from siglum.authority import gate_identity_mismatch, ref_of
from siglum.models import GateIdentityPolicy, ValidatorAuthority
from siglum.predicate import PREDICATE_TYPE
from siglum.sealing.identity import IdentityPolicy
from siglum.sealing.verify_signed import (
    AttestationRejected,
    check_decision_integrity,
    verify_signed_bundle,
)


class ReleaseCheckRejected(Exception):
    """The release subject does not have an acceptable Siglum validation proof."""


@dataclass(frozen=True, slots=True)
class ReleaseCheckResult:
    commit: str
    decision_hash: str
    policy_hash: str


def check_statement(
    statement: dict[str, Any],
    *,
    commit: str,
    gate_identity: GateIdentityPolicy | None = None,
) -> ReleaseCheckResult:
    if statement.get("predicateType") != PREDICATE_TYPE:
        raise ReleaseCheckRejected("not a Siglum validation attestation")
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        raise ReleaseCheckRejected("malformed Siglum predicate")
    check_decision_integrity(predicate)

    subject_commit = _subject_commit(statement)
    if subject_commit != commit:
        raise ReleaseCheckRejected(f"attestation subject {subject_commit!r} != release {commit!r}")
    if predicate.get("merge_eligible") is not True:
        raise ReleaseCheckRejected("Siglum predicate is not merge-eligible")
    if predicate.get("verdict") != "PASS" or predicate.get("coverage") != "FULL":
        raise ReleaseCheckRejected("Siglum predicate is not PASS with FULL coverage")
    if predicate.get("independence") == "UNMET":
        raise ReleaseCheckRejected("Siglum predicate has unmet independence")

    # A downstream verifier can apply its OWN, stricter gate identity against the recorded
    # authority, independent of (and not trusting) the gate_identity the predicate itself carries.
    if gate_identity is not None:
        _require_recorded_gate_identity(predicate, gate_identity)

    policy = predicate.get("policy")
    policy_hash = policy.get("policy_hash", "") if isinstance(policy, dict) else ""
    return ReleaseCheckResult(
        commit=commit,
        decision_hash=str(predicate["decision_hash"]),
        policy_hash=str(policy_hash),
    )


def check_signed_bundle(
    bundle_json: str,
    *,
    commit: str,
    identity_policy: IdentityPolicy,
    trust: str = "staging",
    gate_identity: GateIdentityPolicy | None = None,
) -> ReleaseCheckResult:
    try:
        verified = verify_signed_bundle(bundle_json, identity_policy=identity_policy, trust=trust)
    except AttestationRejected as exc:
        raise ReleaseCheckRejected(str(exc)) from exc
    return check_statement(verified.statement, commit=commit, gate_identity=gate_identity)


def _require_recorded_gate_identity(
    predicate: dict[str, Any], expected: GateIdentityPolicy
) -> None:
    auth_raw = predicate.get("validator_authority")
    if not isinstance(auth_raw, dict):
        raise ReleaseCheckRejected("attestation has no recorded validator authority")
    workflow_ref = str(auth_raw.get("workflow_ref", ""))
    authority = ValidatorAuthority(
        repository=str(auth_raw.get("repository", "")),
        repository_id=str(auth_raw.get("repository_id", "")),
        workflow_ref=workflow_ref,
        ref=ref_of(workflow_ref),  # derived, never trust the stated ref
        runner_class=str(auth_raw.get("runner_class", "")),
    )
    reason = gate_identity_mismatch(authority, expected)
    if reason is not None:
        raise ReleaseCheckRejected(
            f"attestation gate identity does not match the required policy: {reason}"
        )


def load_statement(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict) and "statement" in payload and isinstance(payload["statement"], dict):
        return payload["statement"]
    if isinstance(payload, dict):
        return payload
    raise ReleaseCheckRejected("attestation file must contain a JSON object")


def load_identity_policy(path: Path) -> IdentityPolicy:
    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    return IdentityPolicy(
        policy_id=str(raw.get("policy_id", "release")),
        issuers=tuple(str(v) for v in raw.get("issuers", ())),
        subject_patterns=tuple(str(v) for v in raw.get("subject_patterns", ())),
        repository_patterns=tuple(str(v) for v in raw.get("repository_patterns", ())),
        require_runner_environment=(
            str(raw["require_runner_environment"])
            if raw.get("require_runner_environment") is not None
            else None
        ),
    )


def load_gate_identity(path: Path) -> GateIdentityPolicy:
    """Load the downstream-required gate identity from TOML. This is the verifier's own
    expectation, applied to the recorded authority independent of the predicate's own block."""
    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    repository = raw.get("repository")
    workflow_path = raw.get("workflow_path")
    refs = raw.get("protected_refs", [])
    if not isinstance(repository, str) or not repository:
        raise ReleaseCheckRejected("gate identity policy: repository must be a non-empty string")
    if not isinstance(workflow_path, str) or not workflow_path:
        raise ReleaseCheckRejected("gate identity policy: workflow_path must be a non-empty string")
    if not isinstance(refs, list) or not all(isinstance(r, str) and r for r in refs):
        raise ReleaseCheckRejected("gate identity policy: protected_refs must be non-empty strings")
    return GateIdentityPolicy(
        repository=repository,
        workflow_path=workflow_path,
        protected_refs=tuple(refs),
        repository_id=str(raw.get("repository_id", "")),
    )


def _subject_commit(statement: dict[str, Any]) -> str:
    """The commit the attestation is about, read from the predicate body (predicate.change),
    which the decision_hash and the signature both cover.

    The signed statement produced by sealing.seal uses the decision_hash as its subject
    digest, because Sigstore accepts only SHA-2 subject digests. The git commit therefore
    lives in the predicate, not in the subject digest. Reading it from predicate.change works
    for both the unsigned predicate and the real signed bundle, and binds the released commit
    to the hash that was actually verified."""
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        raise ReleaseCheckRejected("attestation has no predicate")
    change = predicate.get("change")
    if not isinstance(change, dict):
        raise ReleaseCheckRejected("attestation predicate has no change")
    commit = change.get("merge_candidate_sha") or change.get("head_sha")
    if not commit:
        raise ReleaseCheckRejected("attestation has no subject commit")
    return str(commit)

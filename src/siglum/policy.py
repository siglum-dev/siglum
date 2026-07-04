"""Policy parsing and canonicalization.

The policy is the base-anchored contract for a Siglum decision: which validators are
gate-critical, whether structural independence (the org-pinned gate identity) is required,
and which files can change the meaning of the evidence. Head changes to these paths are
override attempts.
"""
from __future__ import annotations

import hashlib
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from siglum.canonical import canonical_json
from siglum.models import GateIdentityPolicy, PolicyRef

POLICY_PATH = ".siglum/policy.toml"


class PolicyError(ValueError):
    """Raised when a policy file is malformed or unsafe."""


@dataclass(frozen=True, slots=True)
class ValidatorPolicy:
    id: str
    version: str
    required: bool = True
    kind: str = "builtin"
    anchor_paths: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Policy:
    policy_id: str
    version: int
    independence_required: bool
    validators: tuple[ValidatorPolicy, ...]
    anchor_paths: tuple[str, ...]
    gate_identity: GateIdentityPolicy | None = None
    approval_required: bool = False

    def required_validator_ids(self) -> tuple[str, ...]:
        return tuple(v.id for v in self.validators if v.required)

    def policy_ref(self) -> PolicyRef:
        return PolicyRef(
            policy_id=self.policy_id,
            policy_hash=policy_hash(self),
            independence_required=self.independence_required,
            approval_required=self.approval_required,
        )


def default_policy() -> Policy:
    """The bare default: a working gate on validators alone. Independence is opt-in and is
    enabled by setting independence_required=true together with a [gate_identity] block (which
    is rejected at load if absent or loose). The demo scaffold generates that block by default."""
    return Policy(
        policy_id="default",
        version=1,
        independence_required=False,
        validators=(
            ValidatorPolicy(
                id="secret-scan",
                version="0",
                required=True,
                kind="builtin",
                anchor_paths=(".github/workflows/siglum-gather.yml",),
            ),
        ),
        anchor_paths=(POLICY_PATH, ".github/workflows/siglum-seal-enforce.yml"),
    )


def load_policy(path: Path) -> Policy:
    try:
        return parse_policy_bytes(path.read_bytes(), source=str(path))
    except OSError as exc:
        raise PolicyError(f"cannot read policy {path}: {exc}") from exc


def parse_policy_bytes(data: bytes, *, source: str = POLICY_PATH) -> Policy:
    try:
        raw = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise PolicyError(f"{source}: invalid TOML: {exc}") from exc
    return parse_policy(raw, source=source)


def parse_policy(raw: dict[str, Any], *, source: str = POLICY_PATH) -> Policy:
    policy_id = _string(raw, "policy_id", default="default", source=source)
    version = _int(raw, "version", default=1, source=source)
    if version != 1:
        raise PolicyError(f"{source}: unsupported policy version {version}")

    independence_required = _bool(raw, "independence_required", default=False, source=source)
    approval_required = _bool(raw, "approval_required", default=False, source=source)
    validators_raw = raw.get("validators")
    if not isinstance(validators_raw, list) or not validators_raw:
        raise PolicyError(f"{source}: policy must define at least one [[validators]] entry")

    validators: list[ValidatorPolicy] = []
    seen: set[str] = set()
    for i, item in enumerate(validators_raw):
        if not isinstance(item, dict):
            raise PolicyError(f"{source}: validators[{i}] must be a table")
        vid = _string(item, "id", source=f"{source}: validators[{i}]")
        if vid in seen:
            raise PolicyError(f"{source}: duplicate validator id {vid!r}")
        seen.add(vid)
        validators.append(
            ValidatorPolicy(
                id=vid,
                version=_string(item, "version", default="0", source=f"{source}: validators[{i}]"),
                required=_bool(item, "required", default=True, source=f"{source}: validators[{i}]"),
                kind=_string(item, "kind", default="builtin", source=f"{source}: validators[{i}]"),
                anchor_paths=_paths(
                    item.get("anchor_paths", ()), source=f"{source}: validators[{i}].anchor_paths"
                ),
            )
        )

    top_anchor_paths = _paths(raw.get("anchor_paths", ()), source=f"{source}: anchor_paths")
    gate_identity = _gate_identity(raw.get("gate_identity"), independence_required, source=source)
    return Policy(
        policy_id=policy_id,
        version=version,
        independence_required=independence_required,
        validators=tuple(validators),
        anchor_paths=_dedupe_paths((POLICY_PATH, *top_anchor_paths)),
        gate_identity=gate_identity,
        approval_required=approval_required,
    )


def _gate_identity(
    raw: Any, independence_required: bool, *, source: str
) -> GateIdentityPolicy | None:
    """Parse the [gate_identity] block tight-by-construction. Required (rejected at load) when
    independence is required; rejects wildcards and non-ref protected refs so a loose identity
    fails at load rather than silently blocking every PR at runtime."""
    if raw is None:
        if independence_required:
            raise PolicyError(
                f"{source}: independence_required is true but [gate_identity] is not configured"
            )
        return None
    # The two settings must agree: a [gate_identity] without independence_required would silently
    # disable the independence the operator clearly intended to configure.
    if not independence_required:
        raise PolicyError(
            f"{source}: [gate_identity] is set but independence_required is not true "
            "(configure both, or neither)"
        )
    if not isinstance(raw, dict):
        raise PolicyError(f"{source}: [gate_identity] must be a table")
    gsrc = f"{source}: [gate_identity]"
    workflow_path = _string(raw, "workflow_path", source=gsrc)
    if "*" in workflow_path or "?" in workflow_path:
        raise PolicyError(f"{gsrc}: workflow_path must be an exact path, not a pattern")
    repository_id = raw.get("repository_id", "")
    if not isinstance(repository_id, str):
        raise PolicyError(f"{gsrc}: repository_id must be a string")
    return GateIdentityPolicy(
        repository=_string(raw, "repository", source=gsrc),
        workflow_path=workflow_path,
        protected_refs=_protected_refs(raw.get("protected_refs"), source=gsrc),
        repository_id=repository_id,
    )


def _protected_refs(value: Any, *, source: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise PolicyError(f"{source}: protected_refs must be a non-empty list of refs")
    refs: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise PolicyError(f"{source}: each protected ref must be a non-empty string")
        if "*" in item or "?" in item:
            raise PolicyError(f"{source}: protected ref {item!r} must be exact, not a pattern")
        # Allowlist branches and tags only. Head-controlled namespaces (refs/pull/...) and any
        # unknown namespace are rejected, so independence can only be SATISFIED on a branch or
        # tag ref. Whether that ref is ACTUALLY branch-protected is validated by setup check.
        if not (item.startswith("refs/heads/") or item.startswith("refs/tags/")):
            raise PolicyError(
                f"{source}: protected ref {item!r} must be a branch or tag "
                "(refs/heads/... or refs/tags/...)"
            )
        refs.append(item)
    return tuple(refs)


def anchored_paths(policy: Policy) -> tuple[str, ...]:
    paths: list[str] = [*policy.anchor_paths]
    for validator in policy.validators:
        paths.extend(validator.anchor_paths)
    return _dedupe_paths(paths)


def policy_hash(policy: Policy) -> str:
    return hashlib.sha256(canonical_json(_canonical_policy(policy))).hexdigest()


def _canonical_policy(policy: Policy) -> dict[str, Any]:
    return {
        "policy_id": policy.policy_id,
        "version": policy.version,
        "independence_required": policy.independence_required,
        "approval_required": policy.approval_required,
        "anchor_paths": list(policy.anchor_paths),
        "validators": [
            {
                "id": v.id,
                "version": v.version,
                "required": v.required,
                "kind": v.kind,
                "anchor_paths": list(v.anchor_paths),
            }
            for v in policy.validators
        ],
        "gate_identity": _canonical_gate_identity(policy.gate_identity),
    }


def _canonical_gate_identity(gi: GateIdentityPolicy | None) -> dict[str, Any] | None:
    if gi is None:
        return None
    return {
        "repository": gi.repository,
        "workflow_path": gi.workflow_path,
        "protected_refs": list(gi.protected_refs),
        "repository_id": gi.repository_id,
    }


def _string(
    raw: dict[str, Any], key: str, *, source: str, default: str | None = None
) -> str:
    value = raw.get(key, default)
    if not isinstance(value, str) or not value:
        raise PolicyError(f"{source}: {key} must be a non-empty string")
    return value


def _int(raw: dict[str, Any], key: str, *, source: str, default: int) -> int:
    value = raw.get(key, default)
    if not isinstance(value, int):
        raise PolicyError(f"{source}: {key} must be an integer")
    return value


def _bool(raw: dict[str, Any], key: str, *, source: str, default: bool) -> bool:
    value = raw.get(key, default)
    if not isinstance(value, bool):
        raise PolicyError(f"{source}: {key} must be true or false")
    return value


def _paths(value: Any, *, source: str) -> tuple[str, ...]:
    if value in (None, ()):
        return ()
    if not isinstance(value, list | tuple):
        raise PolicyError(f"{source}: must be a list of relative paths")
    paths: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise PolicyError(f"{source}: each path must be a non-empty string")
        if item.startswith("/") or item.startswith("../") or "/../" in item or item == "..":
            raise PolicyError(f"{source}: path {item!r} must stay inside the repository")
        paths.append(item)
    return tuple(paths)


def _dedupe_paths(paths: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    return tuple(sorted(dict.fromkeys(paths)))

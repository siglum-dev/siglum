"""Authoritative validator-evidence normalization (trusted, gate-side).

The gather artifact (results.json) crosses the trust boundary, so the trusted gate must
not take any verdict-relevant field from it. `required` and the pinned `version` for every
validator come from the base policy; the artifact may only supply observations (`status`
and `artifact_digest`). A base-required validator that is absent becomes UNKNOWN, and any
validator not declared by the base policy is ignored. This closes the laundering path where
a head-controlled results.json downgrades a base-required validator to `required=false`.
"""
from __future__ import annotations

from siglum.models import ValidatorResult
from siglum.policy import ValidatorPolicy
from siglum.verdict import ValidatorStatus


class EvidenceError(ValueError):
    """The untrusted evidence violated an integrity rule (e.g. duplicate validator ids)."""


def normalize_evidence(
    base_validators: tuple[ValidatorPolicy, ...],
    observed: tuple[ValidatorResult, ...],
) -> tuple[ValidatorResult, ...]:
    by_id: dict[str, ValidatorResult] = {}
    for row in observed:
        if row.id in by_id:
            raise EvidenceError(f"duplicate validator evidence for id {row.id!r}")
        by_id[row.id] = row

    normalized: list[ValidatorResult] = []
    for spec in base_validators:
        obs = by_id.get(spec.id)
        normalized.append(
            ValidatorResult(
                id=spec.id,
                version=spec.version,                                  # authoritative: base
                required=spec.required,                                # authoritative: base
                status=obs.status if obs is not None else ValidatorStatus.UNKNOWN,
                artifact_digest=obs.artifact_digest if obs is not None else "",
            )
        )
    return tuple(normalized)

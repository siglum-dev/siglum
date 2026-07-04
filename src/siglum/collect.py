"""Run a set of validators over one context and assemble the EvidenceBundle the core needs.
Pure orchestration: it adds no trust; the verdict still comes from siglum.derive.assess.

STAGED CAPABILITY: tested, but the in-CI gate does not call this today (gate/run.py builds
its bundle from the gather artifact plus the base policy). This is the entry point for a
future local one-process runner."""
from __future__ import annotations

from collections.abc import Sequence

from siglum.models import EvidenceBundle, GateIdentityPolicy, PolicyRef, ValidatorAuthority
from siglum.validators.base import ValidationContext, Validator


def collect_evidence(
    *,
    ctx: ValidationContext,
    policy: PolicyRef,
    validators: Sequence[Validator],
    validator_authority: ValidatorAuthority,
    change_author: str = "",
    gate_identity: GateIdentityPolicy | None = None,
) -> EvidenceBundle:
    results = tuple(v.run(ctx) for v in validators)
    return EvidenceBundle(
        change=ctx.change,
        policy=policy,
        validators=results,
        validator_authority=validator_authority,
        change_author=change_author,
        gate_identity=gate_identity,
    )

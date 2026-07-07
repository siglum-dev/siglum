"""Break-glass override: an auditable, justification-required gate decision.

STAGED CAPABILITY: fully tested, but the gate does not consult override_allowed() today,
so merge-despite-FAIL is not reachable at runtime. The design: an override is recorded
INSIDE the attestation ("OVERRIDE by X for reason Y") and never rewrites the verdict, so
an auditor sees both the FAIL and who waived it. A cannot-override class
(signing/identity and independence) is structural and not waivable by the change author
(spec section 10)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from siglum.findings import Finding

# Rules that break-glass can never wave through.
CANNOT_OVERRIDE_RULES: frozenset[str] = frozenset(
    {
        "SIG-SIGNING-IDENTITY",   # a signing/identity verification failure
        "SIG-INDEPENDENCE-GAP",   # four-eyes is structural, not author-waivable
    }
)


@dataclass(frozen=True, slots=True)
class Override:
    actor: str
    reason: str


def override_allowed(active_findings: tuple[Finding, ...], override: Override) -> bool:
    if not override.reason.strip():
        return False
    return not any(f.rule_id in CANNOT_OVERRIDE_RULES for f in active_findings)


def apply_override(predicate: dict[str, Any], override: Override) -> dict[str, Any]:
    """Return a NEW predicate dict with the override recorded under predicate['override'].
    Does not change verdict/coverage/merge_eligible."""
    new = dict(predicate)
    body = dict(new["predicate"])
    body["override"] = {
        "actor": override.actor,
        "reason": override.reason,
        "note": f"OVERRIDE by {override.actor} for reason: {override.reason}",
    }
    new["predicate"] = body
    return new

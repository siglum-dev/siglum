"""Verification: an Assessment cannot assert its own pass.

`recompute` re-derives the verdict from the evidence; `verify` confirms the stored verdict,
coverage, independence, merge_eligible, and decision_hash all match the recomputation.
Any mismatch means the object was hand-edited or corrupted: raise, never pass.
"""
from __future__ import annotations

from siglum.derive import SCHEMA_VERSION, assess
from siglum.models import Assessment, EvidenceBundle


class AssessmentTampered(Exception):
    """Stored decision fields do not match a recomputation from the evidence."""


def recompute(bundle: EvidenceBundle, schema_version: str = SCHEMA_VERSION) -> Assessment:
    return assess(bundle, schema_version=schema_version)


def verify(a: Assessment) -> None:
    fresh = recompute(a.bundle, schema_version=a.schema_version)
    mismatches = [
        name
        for name in ("verdict", "coverage", "independence", "merge_eligible", "decision_hash")
        if getattr(a, name) != getattr(fresh, name)
    ]
    if mismatches:
        raise AssessmentTampered(f"decision fields do not recompute: {', '.join(mismatches)}")

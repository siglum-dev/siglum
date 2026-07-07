"""Lockstep conformance: the decision fields are hand-mirrored in four places
(derive._decision_payload, predicate.build_predicate, verify_signed._bundle_from_predicate,
and the policy canonical form). These tests catch drift mechanically: a field added to one
serialization but not the others fails here, before it can become a silent fail-open.
See CONTRIBUTING.md ("the lockstep rule")."""
from __future__ import annotations

import dataclasses

import pytest

from siglum.derive import assess
from siglum.models import Change, EvidenceBundle, GateIdentityPolicy, PolicyRef
from siglum.predicate import build_predicate
from siglum.sealing.verify_signed import _bundle_from_predicate
from siglum.verdict import ValidatorStatus
from tests.test_derive import _authority, _v

_GID = GateIdentityPolicy(
    repository="o/r",
    workflow_path=".github/workflows/siglum-seal-enforce.yml",
    protected_refs=("refs/heads/main", "refs/tags/v1"),
    repository_id="123",
)


def _bundles() -> list[EvidenceBundle]:
    """Representative corners: gate identity on/off, merge candidate on/off, multiple
    validators out of order, empty and filled anchored hash."""
    base = EvidenceBundle(
        change=Change(repo="o/r", base_sha="b" * 40, head_sha="h" * 40, merge_base="m" * 40),
        policy=PolicyRef(policy_id="default", policy_hash="d" * 64,
                         anchored_inputs_hash="c" * 64),
        validators=(_v(ValidatorStatus.PASSED, vid="zzz"), _v(ValidatorStatus.FAILED, vid="aaa")),
        validator_authority=_authority(),
        change_author="alice",
    )
    queued = dataclasses.replace(
        base,
        change=dataclasses.replace(base.change, merge_candidate_sha="c" * 40),
        policy=PolicyRef(
            policy_id="strict", policy_hash="e" * 64, independence_required=True,
            anchored_inputs_hash="f" * 64,
        ),
        gate_identity=_GID,
    )
    return [base, queued]


@pytest.mark.parametrize("bundle", _bundles(), ids=["plain", "queued-independent"])
def test_predicate_round_trips_to_an_identical_bundle(bundle):
    # build_predicate -> _bundle_from_predicate must reproduce the exact input bundle, so
    # the offline verifier rederives from the same evidence the gate assessed. Equality is
    # field-complete: any field one side serializes and the other drops fails here.
    predicate = build_predicate(assess(bundle))["predicate"]
    assert _bundle_from_predicate(predicate) == bundle


@pytest.mark.parametrize("bundle", _bundles(), ids=["plain", "queued-independent"])
def test_round_tripped_bundle_rederives_the_same_decision_hash(bundle):
    original = assess(bundle)
    rederived = assess(_bundle_from_predicate(build_predicate(original)["predicate"]))
    assert rederived.decision_hash == original.decision_hash
    assert rederived.merge_eligible == original.merge_eligible


def test_every_policy_ref_field_appears_in_the_predicate_policy_block():
    # A field added to PolicyRef but not serialized would silently vanish from the signed
    # evidence (and from the decision hash via the payload mirror).
    bundle = _bundles()[1]
    block = build_predicate(assess(bundle))["predicate"]["policy"]
    field_names = {f.name for f in dataclasses.fields(PolicyRef)}
    # approval_required is a gate PRECONDITION, deliberately not a recorded verdict field.
    assert field_names - {"approval_required"} == set(block)


def test_every_change_field_appears_in_the_predicate_change_block():
    bundle = _bundles()[1]
    block = build_predicate(assess(bundle))["predicate"]["change"]
    assert {f.name for f in dataclasses.fields(Change)} == set(block)

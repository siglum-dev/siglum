import dataclasses
import pytest
from siglum.models import (
    Change, PolicyRef, ValidatorResult, EvidenceBundle, Assessment, ValidatorAuthority,
)
from siglum.verdict import Verdict, Coverage, Independence, ValidatorStatus


def _bundle() -> EvidenceBundle:
    return EvidenceBundle(
        change=Change(repo="o/r", base_sha="b" * 40, head_sha="h" * 40, merge_base="m" * 40),
        policy=PolicyRef(policy_id="default", policy_hash="p" * 64, independence_required=False),
        validators=(
            ValidatorResult(id="tests", version="1", status=ValidatorStatus.PASSED,
                            required=True, artifact_digest="sha256:" + "a" * 64),
        ),
        validator_authority=ValidatorAuthority(
            repository="o/r", repository_id="1",
            workflow_ref="o/r/.github/workflows/seal.yml@refs/heads/main",
            ref="refs/heads/main", runner_class="github-hosted",
        ),
        change_author="alice",
    )


def test_models_are_frozen():
    b = _bundle()
    with pytest.raises(dataclasses.FrozenInstanceError):
        b.change.repo = "x"  # type: ignore[misc]


def test_assessment_holds_derived_fields():
    a = Assessment(
        bundle=_bundle(), verdict=Verdict.PASS, coverage=Coverage.FULL,
        independence=Independence.NOT_REQUIRED, merge_eligible=True,
        coverage_gaps=(), decision_hash="x" * 64,
    )
    assert a.merge_eligible is True

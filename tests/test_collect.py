from pathlib import Path
from siglum.collect import collect_evidence
from siglum.validators.base import ValidationContext
from siglum.validators.command import CommandValidator
from siglum.validators.secrets import SecretScanValidator
from siglum.models import Change, PolicyRef, ValidatorAuthority
from siglum.derive import assess
from siglum.verdict import Verdict, Coverage


def _ctx(tmp_path: Path) -> ValidationContext:
    (tmp_path / "ok.py").write_text("x = 1\n")
    return ValidationContext(
        change=Change(repo="o/r", base_sha="b"*40, head_sha="h"*40, merge_base="m"*40),
        workspace=tmp_path, changed_files=("ok.py",),
    )


def test_collect_runs_all_and_feeds_assess(tmp_path):
    ctx = _ctx(tmp_path)
    bundle = collect_evidence(
        ctx=ctx,
        policy=PolicyRef(policy_id="default", policy_hash="p"*64),
        validators=[CommandValidator("tests", "1", True, ["true"]), SecretScanValidator()],
        validator_authority=ValidatorAuthority(
            repository="o/r", repository_id="1",
            workflow_ref="o/r/.github/workflows/seal.yml@refs/heads/main",
            ref="refs/heads/main", runner_class="github-hosted",
        ),
        change_author="alice",
    )
    assert len(bundle.validators) == 2
    a = assess(bundle)
    assert a.verdict == Verdict.PASS and a.coverage == Coverage.FULL and a.merge_eligible

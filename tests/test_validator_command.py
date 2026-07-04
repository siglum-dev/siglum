from pathlib import Path
from siglum.validators.base import ValidationContext, sha256_hex
from siglum.validators.command import CommandValidator
from siglum.models import Change
from siglum.verdict import ValidatorStatus


def _ctx(tmp_path: Path) -> ValidationContext:
    return ValidationContext(
        change=Change(repo="o/r", base_sha="b"*40, head_sha="h"*40, merge_base="m"*40),
        workspace=tmp_path,
        changed_files=("a.py",),
    )


def test_sha256_hex_prefixed():
    assert sha256_hex(b"") == "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_context_carries_change_and_workspace(tmp_path):
    ctx = _ctx(tmp_path)
    assert ctx.change.repo == "o/r" and ctx.workspace == tmp_path


def test_exit_zero_is_passed(tmp_path):
    v = CommandValidator(id="tests", version="1", required=True, argv=["true"])
    r = v.run(_ctx(tmp_path))
    assert r.status == ValidatorStatus.PASSED and r.artifact_digest.startswith("sha256:")


def test_nonzero_exit_is_failed(tmp_path):
    v = CommandValidator(id="tests", version="1", required=True, argv=["false"])
    assert v.run(_ctx(tmp_path)).status == ValidatorStatus.FAILED


def test_timeout_is_errored_not_pass(tmp_path):
    v = CommandValidator(id="slow", version="1", required=True,
                         argv=["sh", "-c", "sleep 5"], timeout_s=1)
    assert v.run(_ctx(tmp_path)).status == ValidatorStatus.ERRORED


def test_missing_binary_is_errored(tmp_path):
    v = CommandValidator(id="x", version="1", required=True, argv=["definitely-not-a-binary-xyz"])
    assert v.run(_ctx(tmp_path)).status == ValidatorStatus.ERRORED

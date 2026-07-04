from pathlib import Path
from siglum.validators.base import ValidationContext
from siglum.validators.secrets import SecretScanValidator
from siglum.models import Change
from siglum.verdict import ValidatorStatus


def _ctx(tmp_path: Path, files) -> ValidationContext:
    return ValidationContext(
        change=Change(repo="o/r", base_sha="b"*40, head_sha="h"*40, merge_base="m"*40),
        workspace=tmp_path, changed_files=tuple(files),
    )


def test_clean_tree_passes(tmp_path):
    (tmp_path / "ok.py").write_text("x = 1\n")
    v = SecretScanValidator()
    assert v.run(_ctx(tmp_path, ["ok.py"])).status == ValidatorStatus.PASSED


def test_aws_key_is_failed(tmp_path):
    (tmp_path / "leak.py").write_text('KEY = "AKIA' + "A"*16 + '"\n')
    v = SecretScanValidator()
    assert v.run(_ctx(tmp_path, ["leak.py"])).status == ValidatorStatus.FAILED


def test_only_scans_changed_files(tmp_path):
    (tmp_path / "leak.py").write_text('AKIA' + "A"*16 + "\n")
    v = SecretScanValidator()
    # leak.py exists but is not in changed_files -> not scanned -> PASS
    assert v.run(_ctx(tmp_path, ["other.py"])).status == ValidatorStatus.PASSED


def test_deleted_changed_file_is_skipped_not_errored(tmp_path):
    # A file in the diff that no longer exists at head (a deletion) has nothing to scan.
    from siglum.validators.secrets import SecretScanValidator
    from siglum.validators.base import ValidationContext
    from siglum.models import Change
    from siglum.verdict import ValidatorStatus

    ctx = ValidationContext(
        change=Change(repo="o/r", base_sha="b" * 40, head_sha="h" * 40, merge_base="m" * 40),
        workspace=tmp_path, changed_files=("gone.txt",),
    )
    assert SecretScanValidator().run(ctx).status is ValidatorStatus.PASSED


def test_unreadable_changed_file_fails_closed_as_errored(tmp_path):
    # A file that exists but cannot be read is missing evidence: the scan must not
    # silently skip it and pass.
    import os
    import pytest
    from siglum.validators.secrets import SecretScanValidator
    from siglum.validators.base import ValidationContext
    from siglum.models import Change
    from siglum.verdict import ValidatorStatus

    if os.geteuid() == 0:
        pytest.skip("root can read anything; the permission fixture cannot apply")
    locked = tmp_path / "locked.txt"
    locked.write_text("AKIA" + "A" * 16)
    locked.chmod(0)
    try:
        ctx = ValidationContext(
            change=Change(repo="o/r", base_sha="b" * 40, head_sha="h" * 40, merge_base="m" * 40),
            workspace=tmp_path, changed_files=("locked.txt",),
        )
        result = SecretScanValidator().run(ctx)
        assert result.status is ValidatorStatus.ERRORED
        assert result.artifact_digest == ""
    finally:
        locked.chmod(0o644)

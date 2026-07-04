import json

import pytest

from siglum.audit.github import parse_repo_config
from siglum.audit.scan import audit
from siglum.demo_scaffold import DemoScaffoldError, scaffold_demo
from siglum.policy import anchored_paths, load_policy


def test_scaffold_demo_writes_fixture_and_expected_audit_gap(tmp_path):
    result = scaffold_demo(tmp_path / "miasma", repo="acme/payments")
    root = result.root
    expected = {
        "README.md",
        "demo/README.md",
        "demo/prevention.patch",
        "demo/prevention-pr.md",
        "demo/local-rehearsal.sh",
        ".github/workflows/ci.yml",
        ".github/workflows/siglum-gather.yml",
        ".github/workflows/siglum-seal-enforce.yml",
        ".siglum/policy.toml",
        "identity-policy.toml",
        "siglum-audit-config.json",
        "siglum-setup-config.json",
        "service/auth.py",
        "tests/test_auth.py",
    }
    written = {str(path.relative_to(root)) for path in result.files}
    assert expected <= written

    payload = json.loads((root / "siglum-audit-config.json").read_text(encoding="utf-8"))
    report = audit(parse_repo_config(payload))
    assert [f.code for f in report.findings] == ["PR_EDITABLE_WORKFLOW"]
    assert report.findings[0].target == ".github/workflows/ci.yml"


def test_scaffold_policy_anchors_siglum_workflows(tmp_path):
    root = scaffold_demo(tmp_path / "miasma", repo="acme/payments").root
    policy = load_policy(root / ".siglum/policy.toml")
    assert policy.independence_required is True
    # Independence-on requires a tight [gate_identity]; the scaffold generates it by default.
    assert policy.gate_identity is not None
    assert policy.gate_identity.repository == "acme/payments"
    assert policy.gate_identity.workflow_path == ".github/workflows/siglum-seal-enforce.yml"
    assert policy.gate_identity.protected_refs == ("refs/heads/main",)
    assert policy.required_validator_ids() == ("secret-scan",)
    assert anchored_paths(policy) == (
        ".github/workflows/siglum-gather.yml",
        ".github/workflows/siglum-seal-enforce.yml",
        ".siglum/policy.toml",
    )


def test_scaffold_refuses_non_empty_directory_without_force(tmp_path):
    root = tmp_path / "miasma"
    root.mkdir()
    (root / "keep.txt").write_text("do not overwrite", encoding="utf-8")
    with pytest.raises(DemoScaffoldError):
        scaffold_demo(root)
    assert (root / "keep.txt").read_text(encoding="utf-8") == "do not overwrite"

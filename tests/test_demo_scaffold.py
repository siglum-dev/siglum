import json

import pytest

from siglum.audit.github import parse_repo_config
from siglum.audit.scan import audit
from siglum.demo_scaffold import DemoScaffoldError, scaffold_demo
from siglum.policy import anchored_paths, load_policy


def test_scaffold_demo_writes_fixture_and_expected_audit_gap(tmp_path):
    result = scaffold_demo(tmp_path / "gate-proof", repo="acme/payments")
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
    root = scaffold_demo(tmp_path / "gate-proof", repo="acme/payments").root
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


def test_scaffold_siglum_workflows_model_the_reference_discipline(tmp_path):
    # The generated gate workflows follow the same rules as the reference workflows in
    # workflows/: actions pinned by commit digest, and event values passed through env
    # so no run script interpolates ${{ github.event.* }} directly. The ci.yml fixture
    # is exempt on purpose: it is the intentionally vulnerable pre-Siglum workflow.
    root = scaffold_demo(tmp_path / "gate-proof", repo="acme/payments").root
    gather = (root / ".github/workflows/siglum-gather.yml").read_text(encoding="utf-8")
    seal = (root / ".github/workflows/siglum-seal-enforce.yml").read_text(encoding="utf-8")

    assert "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0" in gather
    assert "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a" in gather
    assert "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c" in seal
    for text in (gather, seal):
        assert "@v4" not in text

    # Event values reach the diff through env vars, never through direct interpolation.
    assert 'git diff --name-only "$BASE_SHA" "$HEAD_SHA"' in gather
    assert "${{ github.event" not in gather.split("run: |")[1]
    # siglum.validators.run reads GITHUB_BASE_SHA for the Change record it emits.
    assert "GITHUB_BASE_SHA: ${{ github.event.pull_request.base.sha }}" in gather

    ci = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "actions/checkout@v4" in ci


def test_scaffold_refuses_non_empty_directory_without_force(tmp_path):
    root = tmp_path / "gate-proof"
    root.mkdir()
    (root / "keep.txt").write_text("do not overwrite", encoding="utf-8")
    with pytest.raises(DemoScaffoldError):
        scaffold_demo(root)
    assert (root / "keep.txt").read_text(encoding="utf-8") == "do not overwrite"

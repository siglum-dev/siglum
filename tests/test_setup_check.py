import json

from siglum.audit.github import parse_repo_config
from siglum.demo_scaffold import scaffold_demo
from siglum.setup_check import (
    GATHER,
    IDENTITY,
    POLICY,
    SEAL,
    SetupSnapshot,
    check_setup,
    load_local_snapshot,
    render_markdown,
    report_json,
)


def test_scaffolded_demo_is_setup_ready_after_install_fixture(tmp_path):
    root = scaffold_demo(tmp_path / "probe", repo="example-org/siglum-probe").root
    report = check_setup(load_local_snapshot(root))
    assert report.is_ready()
    assert {c.code for c in report.checks} >= {
        "SIGLUM_REQUIRED_CHECK",
        "POLICY_ANCHORS",
        "GATHER_PACKAGE_SOURCE",
        "SEAL_NO_HEAD_CHECKOUT",
        "SEAL_PACKAGE_SOURCE",
        "SEAL_APP_SECRETS",
        "IDENTITY_POLICY",
    }
    assert "Ready for live demo" in render_markdown(report)


def test_setup_check_rejects_missing_source_restriction(tmp_path):
    root = scaffold_demo(tmp_path / "probe").root
    payload = json.loads((root / "siglum-setup-config.json").read_text(encoding="utf-8"))
    payload["required_checks"][0]["source_restricted"] = False
    snapshot = SetupSnapshot(
        repo_config=parse_repo_config(payload),
        files={
            POLICY: (root / POLICY).read_text(encoding="utf-8"),
            GATHER: (root / GATHER).read_text(encoding="utf-8"),
            SEAL: (root / SEAL).read_text(encoding="utf-8"),
            IDENTITY: (root / IDENTITY).read_text(encoding="utf-8"),
        },
    )
    report = check_setup(snapshot)
    assert not report.is_ready()
    failed = [c for c in report.checks if not c.ok]
    assert failed[0].code == "SIGLUM_REQUIRED_CHECK"
    assert "source-restricted" in failed[0].detail


def test_setup_check_rejects_seal_checkout_head(tmp_path):
    root = scaffold_demo(tmp_path / "probe").root
    seal = root / SEAL
    seal.write_text(
        seal.read_text(encoding="utf-8") + "\n      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    report = check_setup(load_local_snapshot(root))
    failures = {c.code: c.detail for c in report.checks if not c.ok}
    assert failures["SEAL_NO_HEAD_CHECKOUT"] == "seal job must not use actions/checkout"


def test_setup_report_json_marks_ready(tmp_path):
    root = scaffold_demo(tmp_path / "probe").root
    payload = report_json(check_setup(load_local_snapshot(root)))
    assert payload["ready"] is True
    assert payload["repo"] == "siglum/gate-proof-demo"


# --- preflight mirrors the runtime identity and enforcement checks ---------
def _snapshot(root, *, files=None, payload=None):
    cfg_payload = payload or json.loads(
        (root / "siglum-setup-config.json").read_text(encoding="utf-8")
    )
    text = files or {
        p: (root / p).read_text(encoding="utf-8") for p in (POLICY, GATHER, SEAL, IDENTITY)
    }
    return SetupSnapshot(repo_config=parse_repo_config(cfg_payload), files=text)


def _checks(report):
    return {c.code: c for c in report.checks}


def test_required_check_must_match_the_expected_app_id(tmp_path):
    # Enforcement mirror: with an expected app id, the preflight requires the siglum check to be restricted
    # to THAT app specifically, not just any app.
    root = scaffold_demo(tmp_path / "probe").root
    payload = json.loads((root / "siglum-setup-config.json").read_text(encoding="utf-8"))
    payload["required_checks"][0]["app_id"] = 42
    snap = _snapshot(root, payload=payload)
    assert _checks(check_setup(snap, expected_app_id=42))["SIGLUM_REQUIRED_CHECK"].ok
    bad = _checks(check_setup(snap, expected_app_id=999))["SIGLUM_REQUIRED_CHECK"]
    assert not bad.ok and "Siglum App" in bad.detail


def test_gate_identity_repository_must_match_the_gated_repo(tmp_path):
    root = scaffold_demo(tmp_path / "probe", repo="o/r").root
    policy = (root / POLICY).read_text(encoding="utf-8").replace(
        'repository = "o/r"', 'repository = "o/other"'
    )
    files = {POLICY: policy, **{p: (root / p).read_text(encoding="utf-8")
                                for p in (GATHER, SEAL, IDENTITY)}}
    report = check_setup(_snapshot(root, files=files))
    chk = _checks(report)["GATE_IDENTITY_REPO"]
    assert not chk.ok and "o/other" in chk.detail


def test_gate_identity_refs_must_be_the_protected_default_branch(tmp_path):
    root = scaffold_demo(tmp_path / "probe", repo="o/r").root
    policy = (root / POLICY).read_text(encoding="utf-8").replace(
        '["refs/heads/main"]', '["refs/heads/release"]'
    )
    files = {POLICY: policy, **{p: (root / p).read_text(encoding="utf-8")
                                for p in (GATHER, SEAL, IDENTITY)}}
    report = check_setup(_snapshot(root, files=files))
    chk = _checks(report)["GATE_IDENTITY_PROTECTED_REFS"]
    assert not chk.ok and "release" in chk.detail


def test_gate_identity_workflow_path_must_be_the_seal_workflow(tmp_path):
    # The runtime matches the actual run's workflow against gate_identity.workflow_path; a policy
    # pinning a different workflow passed the old preflight but fails closed at runtime.
    root = scaffold_demo(tmp_path / "probe", repo="o/r").root
    policy = (root / POLICY).read_text(encoding="utf-8").replace(
        'workflow_path = ".github/workflows/siglum-seal-enforce.yml"',
        'workflow_path = ".github/workflows/other.yml"',
    )
    files = {POLICY: policy, **{p: (root / p).read_text(encoding="utf-8")
                                for p in (GATHER, SEAL, IDENTITY)}}
    chk = _checks(check_setup(_snapshot(root, files=files)))["GATE_IDENTITY_WORKFLOW"]
    assert not chk.ok and "other.yml" in chk.detail


def test_gate_identity_pinned_repository_id_is_disclosed_as_runtime_only(tmp_path):
    # repository_id is looser by design: the runtime enforces it when pinned, but the preflight
    # has no numeric repo id to compare. Disclose it (never silently pass as verified) without an
    # un-clearable failure that would push operators to drop the more-secure pin.
    root = scaffold_demo(tmp_path / "probe", repo="o/r").root
    policy = (root / POLICY).read_text(encoding="utf-8").replace(
        'protected_refs = ["refs/heads/main"]',
        'protected_refs = ["refs/heads/main"]\nrepository_id = "12345"',
    )
    files = {POLICY: policy, **{p: (root / p).read_text(encoding="utf-8")
                                for p in (GATHER, SEAL, IDENTITY)}}
    report = check_setup(_snapshot(root, files=files))
    chk = _checks(report)["GATE_IDENTITY_REPO_ID"]
    assert chk.ok and "12345" in chk.detail and "runtime" in chk.detail
    assert report.is_ready()  # disclosed, not a failure


def test_gate_identity_repository_id_is_verified_when_the_snapshot_has_it(tmp_path):
    # When the snapshot carries the numeric repo id, the preflight verifies a pinned repository_id
    # numerically, completing the runtime identity mirror rather than only disclosing it.
    root = scaffold_demo(tmp_path / "probe", repo="o/r").root
    policy = (root / POLICY).read_text(encoding="utf-8").replace(
        'protected_refs = ["refs/heads/main"]',
        'protected_refs = ["refs/heads/main"]\nrepository_id = "12345"',
    )
    payload = json.loads((root / "siglum-setup-config.json").read_text(encoding="utf-8"))
    payload["repository_id"] = "12345"
    files = {POLICY: policy, **{p: (root / p).read_text(encoding="utf-8")
                                for p in (GATHER, SEAL, IDENTITY)}}
    chk = _checks(check_setup(_snapshot(root, files=files, payload=payload)))["GATE_IDENTITY_REPO_ID"]
    assert chk.ok and "12345" in chk.detail and "verified against" in chk.detail


def test_gate_identity_repository_id_mismatch_fails(tmp_path):
    root = scaffold_demo(tmp_path / "probe", repo="o/r").root
    policy = (root / POLICY).read_text(encoding="utf-8").replace(
        'protected_refs = ["refs/heads/main"]',
        'protected_refs = ["refs/heads/main"]\nrepository_id = "12345"',
    )
    payload = json.loads((root / "siglum-setup-config.json").read_text(encoding="utf-8"))
    payload["repository_id"] = "999"
    files = {POLICY: policy, **{p: (root / p).read_text(encoding="utf-8")
                                for p in (GATHER, SEAL, IDENTITY)}}
    report = check_setup(_snapshot(root, files=files, payload=payload))
    chk = _checks(report)["GATE_IDENTITY_REPO_ID"]
    assert not chk.ok and "999" in chk.detail and "12345" in chk.detail
    assert not report.is_ready()


def test_gate_identity_non_numeric_repository_id_pin_fails(tmp_path):
    # A GitHub repo id is numeric; a non-numeric pin can never match the runtime OIDC id. Even if a
    # user-editable local config echoes the same non-numeric value, the preflight must not verify it.
    root = scaffold_demo(tmp_path / "probe", repo="o/r").root
    policy = (root / POLICY).read_text(encoding="utf-8").replace(
        'protected_refs = ["refs/heads/main"]',
        'protected_refs = ["refs/heads/main"]\nrepository_id = "abc"',
    )
    payload = json.loads((root / "siglum-setup-config.json").read_text(encoding="utf-8"))
    payload["repository_id"] = "abc"
    files = {POLICY: policy, **{p: (root / p).read_text(encoding="utf-8")
                                for p in (GATHER, SEAL, IDENTITY)}}
    report = check_setup(_snapshot(root, files=files, payload=payload))
    chk = _checks(report)["GATE_IDENTITY_REPO_ID"]
    assert not chk.ok and "numeric" in chk.detail
    assert not report.is_ready()


def test_scaffold_passes_the_gate_identity_checks(tmp_path):
    root = scaffold_demo(tmp_path / "probe", repo="o/r").root
    checks = _checks(check_setup(load_local_snapshot(root)))
    assert checks["GATE_IDENTITY_REPO"].ok
    assert checks["GATE_IDENTITY_WORKFLOW"].ok
    assert checks["GATE_IDENTITY_PROTECTED_REFS"].ok
    assert "GATE_IDENTITY_REPO_ID" not in checks  # scaffold does not pin the optional id

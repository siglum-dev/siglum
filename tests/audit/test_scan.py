from siglum.audit.model import (
    RequiredCheck, WorkflowFile, RepoConfig, GapSeverity, AuditFinding, AuditReport,
)
from siglum.audit.scan import audit


def test_clean_report_is_clean():
    r = AuditReport(repo="o/r", findings=())
    assert r.is_clean() is True


def test_finding_carries_code_target_severity():
    f = AuditFinding(code="SPOOFABLE_CHECK", target="ci", severity=GapSeverity.HIGH, detail="x")
    assert (f.code, f.target, f.severity) == ("SPOOFABLE_CHECK", "ci", GapSeverity.HIGH)


def _cfg(**kw) -> RepoConfig:
    base: dict[str, object] = dict(
        repo="o/r", required_checks=(), workflows=(), admin_bypass_allowed=False
    )
    base.update(kw)
    return RepoConfig(**base)  # type: ignore[arg-type]


def test_commit_status_required_check_is_spoofable():
    cfg = _cfg(required_checks=(
        RequiredCheck("ci", enforcement="commit_status", source_restricted=False),))
    codes = {f.code for f in audit(cfg).findings}
    assert "SPOOFABLE_CHECK" in codes


def test_app_check_run_source_restricted_is_not_flagged():
    cfg = _cfg(required_checks=(
        RequiredCheck("siglum", enforcement="app_check_run", source_restricted=True),))
    assert audit(cfg).is_clean()


def test_pr_editable_gate_workflow_is_flagged():
    cfg = _cfg(workflows=(
        WorkflowFile("ci.yml", pr_editable=True, continue_on_error=False,
                     path_filters=(), produces_checks=("ci",)),))
    f = next(f for f in audit(cfg).findings if f.code == "PR_EDITABLE_WORKFLOW")
    assert f.severity == GapSeverity.HIGH and "ci" in f.detail


def test_continue_on_error_is_silent_skip():
    cfg = _cfg(workflows=(
        WorkflowFile("ci.yml", pr_editable=False, continue_on_error=True,
                     path_filters=(), produces_checks=("ci",)),))
    assert any(f.code == "SILENT_SKIP" for f in audit(cfg).findings)


def test_path_filters_are_silent_skip():
    cfg = _cfg(workflows=(
        WorkflowFile("ci.yml", pr_editable=False, continue_on_error=False,
                     path_filters=("docs/**",), produces_checks=("ci",)),))
    assert any(f.code == "SILENT_SKIP" for f in audit(cfg).findings)


def test_admin_bypass_is_flagged_low():
    cfg = _cfg(admin_bypass_allowed=True)
    f = next(f for f in audit(cfg).findings if f.code == "ADMIN_BYPASS")
    assert f.severity == GapSeverity.LOW


def test_unprotected_default_branch_is_flagged_high():
    cfg = _cfg(protected=False, default_branch="main")
    f = next(f for f in audit(cfg).findings if f.code == "UNPROTECTED_DEFAULT_BRANCH")
    assert f.severity == GapSeverity.HIGH and "main" in f.target


def test_protected_repo_is_not_flagged_unprotected():
    cfg = _cfg(protected=True)
    assert not any(f.code == "UNPROTECTED_DEFAULT_BRANCH" for f in audit(cfg).findings)


def test_unreadable_protection_is_reported_as_unverified_not_unprotected():
    # A non-admin token gets 403 on the branch-protection read. That is "could not
    # verify", never a HIGH "unprotected" claim about a repo that may be locked down.
    cfg = _cfg(protected=False, protection_readable=False, default_branch="main")
    findings = audit(cfg).findings
    assert not any(f.code == "UNPROTECTED_DEFAULT_BRANCH" for f in findings)
    f = next(f for f in findings if f.code == "PROTECTION_UNVERIFIED")
    assert f.severity == GapSeverity.MEDIUM
    assert "could not" in f.detail
    assert "admin" in f.detail.lower()


def test_ruleset_protection_with_unreadable_classic_protection_is_clean():
    # Rulesets alone can prove protection; an unreadable classic-protection endpoint then
    # warrants no finding at all.
    cfg = _cfg(protected=True, protection_readable=False)
    codes = {f.code for f in audit(cfg).findings}
    assert "UNPROTECTED_DEFAULT_BRANCH" not in codes
    assert "PROTECTION_UNVERIFIED" not in codes


def test_findings_are_deterministically_sorted():
    cfg = _cfg(
        admin_bypass_allowed=True,
        required_checks=(RequiredCheck("ci", "commit_status", False),),
    )
    findings = audit(cfg).findings
    assert list(findings) == sorted(findings, key=lambda f: (f.code, f.target))

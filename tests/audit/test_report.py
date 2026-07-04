from siglum.audit.model import RepoConfig, RequiredCheck, AuditReport
from siglum.audit.scan import audit
from siglum.audit.report import render_markdown, sample_attestation


def test_markdown_lists_each_finding_and_repo():
    cfg = RepoConfig(repo="o/r",
                     required_checks=(RequiredCheck("ci", "commit_status", False),),
                     workflows=(), admin_bypass_allowed=True)
    md = render_markdown(audit(cfg))
    assert "o/r" in md
    assert "SPOOFABLE_CHECK" in md and "ADMIN_BYPASS" in md


def test_clean_report_says_so():
    md = render_markdown(AuditReport(repo="o/r", findings=()))
    assert "No evidence gaps" in md


def test_sample_attestation_is_a_real_predicate():
    stmt = sample_attestation(repo="o/r", head_sha="h" * 40)
    assert stmt["predicateType"] == "https://siglum.dev/ValidationAttestation/v0.3"
    assert stmt["subject"][0]["digest"]["gitCommit"] == "h" * 40
    assert stmt["predicate"]["verdict"] == "PASS"

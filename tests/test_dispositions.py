from datetime import UTC, datetime
from siglum.dispositions import (
    Disposition, load_dispositions, save_dispositions,
    add_disposition, revoke_disposition, expired_dispositions, active_dispositions,
    apply_dispositions,
)
from siglum.findings import Finding, Severity


def _f(fp: str) -> Finding:
    return Finding(fingerprint=fp, rule_id="R", validator_id="v", message="m",
                   severity=Severity.LOW)


def test_roundtrip_file_io(tmp_path):
    p = tmp_path / "d.json"
    ds = (Disposition("fp1", reason="flaky", actor="alice", expires=None),)
    save_dispositions(p, ds)
    assert load_dispositions(p) == ds


def test_missing_file_is_empty(tmp_path):
    assert load_dispositions(tmp_path / "nope.json") == ()


def test_add_replaces_same_fingerprint():
    existing = (Disposition("fp1", "old", "alice"),)
    updated = add_disposition(existing, Disposition("fp1", "new", "bob"))
    assert len(updated) == 1 and updated[0].reason == "new"


def test_revoke_removes_by_fingerprint():
    existing = (Disposition("fp1", "r", "a"), Disposition("fp2", "r", "a"))
    assert {d.issue_fingerprint for d in revoke_disposition(existing, "fp1")} == {"fp2"}


def test_expiry_in_the_past_is_expired():
    past = "2000-01-01T00:00:00+00:00"
    ds = (Disposition("fp1", "r", "a", expires=past),)
    assert expired_dispositions(ds, now=datetime.now(UTC)) == ds
    assert active_dispositions(ds, now=datetime.now(UTC)) == ()


def test_unparseable_expiry_is_treated_as_expired():
    ds = (Disposition("fp1", "r", "a", expires="not-a-date"),)
    assert expired_dispositions(ds) == ds  # fail-closed: a broken waiver protects nothing


def test_apply_dispositions_suppresses_active_only():
    findings = (_f("fp1"), _f("fp2"))
    past = "2000-01-01T00:00:00+00:00"
    ds = (
        Disposition("fp1", "accepted", "alice", expires=None),     # active -> suppress fp1
        Disposition("fp2", "accepted", "alice", expires=past),     # expired -> fp2 stays
    )
    kept, suppressed = apply_dispositions(findings, ds)
    assert {f.fingerprint for f in kept} == {"fp2"}
    assert {f.fingerprint for f in suppressed} == {"fp1"}

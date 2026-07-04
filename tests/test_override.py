from siglum.override import (
    Override, CANNOT_OVERRIDE_RULES, override_allowed, apply_override,
)
from siglum.findings import Finding, Severity


def _f(rule: str) -> Finding:
    return Finding(fingerprint="fp", rule_id=rule, validator_id="v",
                   message="m", severity=Severity.HIGH)


def _predicate() -> dict[str, object]:
    return {"predicateType": "https://siglum.dev/ValidationAttestation/v0.3",
            "predicate": {"verdict": "FAIL", "merge_eligible": False}}


def test_override_requires_a_reason():
    assert override_allowed((), Override(actor="alice", reason="")) is False
    assert override_allowed((), Override(actor="alice", reason="hotfix")) is True


def test_cannot_override_independence_or_signing():
    assert "SIG-INDEPENDENCE-GAP" in CANNOT_OVERRIDE_RULES
    findings = (_f("SIG-INDEPENDENCE-GAP"),)
    assert override_allowed(findings, Override("alice", "please")) is False


def test_apply_override_records_inside_predicate_without_flipping_verdict():
    pred = _predicate()
    out = apply_override(pred, Override(actor="alice", reason="prod outage"))
    rec = out["predicate"]["override"]
    assert rec["actor"] == "alice" and "prod outage" in rec["note"]
    # The verdict is NOT silently rewritten. The override is recorded beside it.
    assert out["predicate"]["verdict"] == "FAIL"
    assert out["predicate"]["merge_eligible"] is False
    # Input is not mutated (pure).
    assert "override" not in pred["predicate"]  # type: ignore[operator]

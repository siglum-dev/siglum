from siglum.derive import assess
from siglum.derive_findings import derive_findings, COVERAGE_GAP_RULE, INDEPENDENCE_GAP_RULE
from siglum.override import override_allowed, Override
from tests.test_derive import _b, _v          # reuse the core builders
from siglum.verdict import ValidatorStatus


def test_clean_assessment_has_no_findings():
    a = assess(_b([_v(ValidatorStatus.PASSED)]))
    assert derive_findings(a) == ()


def test_coverage_gap_becomes_a_finding():
    a = assess(_b([_v(ValidatorStatus.SKIPPED)]))      # INCOMPLETE coverage
    rules = {f.rule_id for f in derive_findings(a)}
    assert COVERAGE_GAP_RULE in rules


def test_independence_unmet_is_a_cannot_override_finding():
    a = assess(_b([_v(ValidatorStatus.PASSED)], independence_required=True,
                  gate_identity=None))                   # required but unprovable -> UNMET
    findings = derive_findings(a)
    assert any(f.rule_id == INDEPENDENCE_GAP_RULE for f in findings)
    # the loop is closed: break-glass cannot wave through an independence gap
    assert override_allowed(findings, Override("x", "please merge")) is False

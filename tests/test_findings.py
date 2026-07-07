from siglum.findings import Severity, Finding, FindingDiff, diff_findings


def _f(fp: str, rule: str = "R1", sev: Severity = Severity.MEDIUM) -> Finding:
    return Finding(fingerprint=fp, rule_id=rule, validator_id="secret-scan",
                   message=f"finding {fp}", severity=sev)


def test_severity_values_are_stable_strings():
    assert Severity.CRITICAL.value == "CRITICAL"


def test_diff_classifies_new_persistent_resolved():
    prev = (_f("a"), _f("b"))
    cur = (_f("b"), _f("c"))
    d = diff_findings(prev, cur)
    assert [f.fingerprint for f in d.new] == ["c"]
    assert [f.fingerprint for f in d.persistent] == ["b"]
    assert [f.fingerprint for f in d.resolved] == ["a"]


def test_diff_is_deterministically_sorted():
    cur = (_f("z"), _f("a"), _f("m"))
    d = diff_findings((), cur)
    assert [f.fingerprint for f in d.new] == ["a", "m", "z"]
    assert isinstance(d, FindingDiff)

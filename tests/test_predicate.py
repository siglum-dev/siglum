from siglum.predicate import build_predicate, STATEMENT_TYPE, PREDICATE_TYPE
from siglum.derive import assess
from tests.test_derive import _b, _v  # reuse builders
from siglum.verdict import ValidatorStatus


def test_predicate_is_in_toto_statement_shape():
    a = assess(_b([_v(ValidatorStatus.PASSED)]))
    stmt = build_predicate(a)
    assert stmt["_type"] == STATEMENT_TYPE
    assert stmt["predicateType"] == PREDICATE_TYPE
    assert stmt["subject"][0]["name"] == "o/r"
    assert stmt["subject"][0]["digest"]["gitCommit"] == "h" * 40
    assert stmt["predicate"]["verdict"] == "PASS"
    assert stmt["predicate"]["decision_hash"] == a.decision_hash
    # the verified authority + change author are published so an external verifier can
    # reconstruct the bundle and rederive the verdict
    assert stmt["predicate"]["change_author"] == "alice"
    assert stmt["predicate"]["validator_authority"]["repository"] == "o/r"
    assert stmt["predicate"]["validator_authority"]["ref"] == "refs/heads/main"


def test_predicate_subject_uses_merge_candidate_when_present():
    bundle = _b([_v(ValidatorStatus.PASSED)])
    object.__setattr__(bundle.change, "merge_candidate_sha", "c" * 40)
    stmt = build_predicate(assess(bundle))
    assert stmt["subject"][0]["digest"]["gitCommit"] == "c" * 40

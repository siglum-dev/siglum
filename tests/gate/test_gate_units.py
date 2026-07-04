import pytest
from siglum.derive import assess
from siglum.forge.base import ForgeReadError, VerifiedPr
from siglum.predicate import build_predicate
from siglum.gate.anchor import anchor_inputs
from siglum.gate.binding import bind_run, binding_into_predicate
from siglum.gate.runner import require_hosted_runner
from siglum.gate.mergeable_subject import select_subject_sha
from siglum.gate.orchestrate import trusted_author
from siglum.gate.enforce import conclude
from siglum.gate.errors import GateRefused
from siglum.verdict import ValidatorStatus
from tests.gate.fakes import (
    FakeProvider, run_ctx, merge_ctx, vr, bundle, anchored, binding_for, H,
)


# --- anchor -----------------------------------------------------------------
_POLICY = ".siglum/policy.toml"


def test_head_edit_is_recorded_by_reading_head_not_a_caller_digest():
    # The override is detected by reading the head version from the trusted forge.
    # No caller-supplied head digest is involved, so an untrusted gather cannot suppress it.
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(),
                      base_files={_POLICY: b"BASE"}, head_files={_POLICY: b"HEAD-EDIT"})
    ai = anchor_inputs(fp, "base", "head", paths=(_POLICY,))
    assert _POLICY in ai.head_overrides_detected
    # the head edit has ZERO effect on the verdict-bearing anchored hash (base only)
    clean = FakeProvider(run=run_ctx(), merge=merge_ctx(),
                         base_files={_POLICY: b"BASE"}, head_files={_POLICY: b"BASE"})
    assert ai.anchored_inputs_hash == anchor_inputs(
        clean, "base", "head", paths=(_POLICY,)
    ).anchored_inputs_hash


def test_head_matching_base_is_not_an_override():
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(),
                      base_files={_POLICY: b"SAME"}, head_files={_POLICY: b"SAME"})
    assert anchor_inputs(fp, "base", "head", paths=(_POLICY,)).head_overrides_detected == ()


def test_head_deleting_an_anchored_file_present_at_base_is_an_override():
    # base has the file, head 404s it: a head that removes a gate-critical input is an override.
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(),
                      base_files={_POLICY: b"BASE"}, head_files={})
    assert _POLICY in anchor_inputs(fp, "base", "head", paths=(_POLICY,)).head_overrides_detected


def test_head_read_failure_fails_closed():
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(),
                      base_files={_POLICY: b"BASE"}, head_read_error=True)
    with pytest.raises(ForgeReadError):
        anchor_inputs(fp, "base", "head", paths=(_POLICY,))


def test_absent_at_base_and_head_is_deterministic():
    fp = FakeProvider(run=run_ctx(), merge=merge_ctx(), base_files={}, head_files={})
    a = anchor_inputs(fp, "base", "head", paths=(_POLICY,))
    b = anchor_inputs(fp, "base", "head", paths=(_POLICY,))
    assert a.anchored_inputs_hash == b.anchored_inputs_hash


# --- trusted author --------------------------------------------------------
def test_trusted_author_prefers_the_verified_pr():
    # The App-fetched PR author (trusted) is recorded over the event-supplied fallback.
    assert trusted_author(VerifiedPr(head_sha="s", author="bob"), "event-actor") == "bob"


def test_trusted_author_falls_back_when_no_verified_pr():
    # No single PR (merge_group, push): keep the event-supplied author (audit only).
    assert trusted_author(None, "event-actor") == "event-actor"


# --- binding ----------------------------------------------------------------
def test_bind_run_sorts_validators():
    b = bind_run(run_ctx(), merge_ctx(), anchored(), bundle([vr("zzz", "2"), vr("aaa", "1")]))
    assert b.validator_versions == (("aaa", "1"), ("zzz", "2"))
    assert b.run_attempt == "1"


def test_binding_into_predicate_keeps_decision_hash():
    a = assess(bundle([vr("tests")]))
    pred = build_predicate(a)
    out = binding_into_predicate(pred, binding_for(a))
    assert out["predicate"]["run_binding"]["run_id"] == "r1"
    assert out["predicate"]["decision_hash"] == a.decision_hash   # binding is provenance, not verdict


# --- runner / mergeable subject ----------------------------------------------
def test_require_hosted_runner():
    require_hosted_runner(run_ctx("github-hosted"))   # ok
    with pytest.raises(GateRefused):
        require_hosted_runner(run_ctx("self-hosted"))
    with pytest.raises(GateRefused):
        require_hosted_runner(run_ctx("unknown"))


def test_select_subject_prefers_merge_candidate():
    assert select_subject_sha(merge_ctx(candidate="c" * 40)) == "c" * 40
    assert select_subject_sha(merge_ctx(candidate=None)) == H


# --- enforce ----------------------------------------------------------------
def test_conclude_success_only_when_merge_eligible():
    a = assess(bundle([vr("tests")]))
    assert conclude(a, binding_for(a)).conclusion == "success"


def test_incomplete_coverage_is_failure_and_names_skipped():
    a = assess(bundle([vr("tests"), vr("scan", status=ValidatorStatus.SKIPPED)]))
    c = conclude(a, binding_for(a))
    assert c.conclusion == "failure" and "scan" in c.summary


def test_unmet_independence_is_failure():
    # Independence required but no expected gate identity to match -> UNMET -> failure.
    a = assess(bundle([vr("tests")], independence_required=True, gate_identity=None))
    assert conclude(a, binding_for(a)).conclusion == "failure"


def test_errored_is_action_required():
    a = assess(bundle([vr("tests", status=ValidatorStatus.ERRORED)]))
    assert conclude(a, binding_for(a)).conclusion == "action_required"


def test_subject_mismatch_is_failure():
    a = assess(bundle([vr("tests")]))                 # change head == H
    other = bind_run(run_ctx(), merge_ctx(head="z" * 40), anchored(), a.bundle)
    assert conclude(a, other).conclusion == "failure"

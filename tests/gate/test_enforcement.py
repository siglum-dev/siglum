"""The gate self-audits its own enforcement and fails closed unless the `siglum` check is
actually required on a protected branch AND source-restricted to the Siglum App specifically.
A green check or a signed attestation must never outrun proof that the gate is really enforced."""
from siglum.audit.model import RepoConfig, RequiredCheck
from siglum.gate.enforcement import enforcement_mismatch

SIGLUM_APP = 42


def _cfg(checks, *, protected=True):
    return RepoConfig(
        repo="o/r", required_checks=tuple(checks), workflows=(),
        admin_bypass_allowed=False, protected=protected,
    )


def _check(context="siglum", app_id=SIGLUM_APP):
    return RequiredCheck(
        context=context, enforcement="app_check_run",
        source_restricted=app_id is not None, app_id=app_id,
    )


def test_passes_when_siglum_is_required_and_restricted_to_our_app():
    assert enforcement_mismatch(
        _cfg([_check()]), check_name="siglum", expected_app_id=SIGLUM_APP
    ) is None


def test_fails_when_siglum_is_not_a_required_check():
    reason = enforcement_mismatch(
        _cfg([_check(context="tests")]), check_name="siglum", expected_app_id=SIGLUM_APP
    )
    assert reason is not None and "required" in reason


def test_fails_when_siglum_is_required_but_not_restricted_to_any_app():
    reason = enforcement_mismatch(
        _cfg([_check(app_id=None)]), check_name="siglum", expected_app_id=SIGLUM_APP
    )
    assert reason is not None and "restrict" in reason


def test_fails_when_siglum_is_restricted_to_a_different_app():
    reason = enforcement_mismatch(
        _cfg([_check(app_id=999)]), check_name="siglum", expected_app_id=SIGLUM_APP
    )
    assert reason is not None


def test_fails_when_the_branch_is_not_protected():
    reason = enforcement_mismatch(
        _cfg([_check()], protected=False), check_name="siglum", expected_app_id=SIGLUM_APP
    )
    assert reason is not None and "protected" in reason


def test_fails_when_app_id_matches_but_check_is_not_source_restricted():
    # Defensive: an app_id set while source_restricted is false is inconsistent. The predicate
    # must require both, not just an app-id match.
    inconsistent = RequiredCheck(
        context="siglum", enforcement="commit_status", source_restricted=False, app_id=SIGLUM_APP
    )
    reason = enforcement_mismatch(
        _cfg([inconsistent]), check_name="siglum", expected_app_id=SIGLUM_APP
    )
    assert reason is not None


def test_unreadable_protection_gives_an_actionable_reason():
    # When the protection read itself was forbidden, the fail-closed reason must say the
    # config could not be read (and how to fix it), not claim the branch is unprotected.
    cfg = RepoConfig(
        repo="o/r", required_checks=(), workflows=(), admin_bypass_allowed=False,
        protected=False, protection_readable=False,
    )
    reason = enforcement_mismatch(cfg, check_name="siglum", expected_app_id=SIGLUM_APP)
    assert reason is not None
    assert "could not be read" in reason
    assert "Administration" in reason

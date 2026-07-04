from typing import Any
from siglum.audit.github import parse_repo_config, parse_workflow, parse_rulesets
from siglum.audit.model import RepoConfig


def _payload() -> dict[str, object]:
    # Captured-shape fixture mirroring the fields fetch_repo_config assembles from the
    # rulesets + required-status-checks + workflow-file APIs.
    return {
        "repo": "o/r",
        "required_checks": [
            {"context": "ci", "enforcement": "commit_status", "source_restricted": False},
            {"context": "siglum", "enforcement": "app_check_run", "source_restricted": True},
        ],
        "workflows": [
            {"path": "ci.yml", "pr_editable": True, "continue_on_error": False,
             "path_filters": ["docs/**"], "produces_checks": ["ci"]},
        ],
        "admin_bypass_allowed": True,
    }


def test_parse_builds_repo_config():
    cfg = parse_repo_config(_payload())
    assert isinstance(cfg, RepoConfig) and cfg.repo == "o/r"
    assert len(cfg.required_checks) == 2 and len(cfg.workflows) == 1
    assert cfg.workflows[0].path_filters == ("docs/**",)
    assert cfg.admin_bypass_allowed is True


def test_parse_defaults_missing_fields_safely():
    cfg = parse_repo_config({"repo": "o/r"})
    assert cfg.required_checks == () and cfg.workflows == () and cfg.admin_bypass_allowed is False
    assert cfg.protected is True and cfg.default_branch == "main"
    # requires_review defaults to False (fail closed: no proof the branch requires a review)
    assert cfg.requires_review is False


def test_parse_reads_requires_review():
    assert parse_repo_config({"repo": "o/r", "requires_review": True}).requires_review is True


def test_parse_reads_protected_and_default_branch():
    cfg = parse_repo_config({"repo": "o/r", "protected": False, "default_branch": "trunk"})
    assert cfg.protected is False and cfg.default_branch == "trunk"


def test_parse_workflow_handles_on_boolean_gotcha_and_matches_required():
    # pyyaml parses a bare `on:` key as the boolean True
    doc: dict[object, object] = {
        True: {"pull_request": {"branches": ["main"]}},
        "jobs": {"backend": {"name": "Backend"}, "extra": {"name": "Lint"}},
    }
    w = parse_workflow(".github/workflows/ci.yml", doc, required_contexts={"Backend"})
    assert w["pr_editable"] is True
    assert w["produces_checks"] == ["Backend"]            # Lint isn't required -> excluded


def test_parse_workflow_detects_continue_on_error_and_path_filters():
    doc: dict[object, object] = {
        "on": {"pull_request": {"paths": ["src/**"]}},
        "jobs": {"t": {"name": "T", "continue-on-error": True}},
    }
    w = parse_workflow(".github/workflows/ci.yml", doc, required_contexts=set())
    assert w["continue_on_error"] is True and w["path_filters"] == ["src/**"]


def test_parse_rulesets_extracts_spoofable_check_and_bypass():
    # exact shape returned by the GitHub rulesets API (from the live fixture)
    details: list[dict[str, Any]] = [{
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "bypass_actors": [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}],
        "rules": [{"type": "required_status_checks",
                   "parameters": {"required_status_checks": [{"context": "build"}]}}],
    }]
    info = parse_rulesets(details, "main")
    assert info["protected"] is True and info["admin_bypass_allowed"] is True
    chk = info["required_checks"][0]
    assert chk["context"] == "build" and chk["source_restricted"] is False  # no integration_id


def test_parse_rulesets_app_pinned_check_is_source_restricted():
    details: list[dict[str, Any]] = [{
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"]}},
        "rules": [{"type": "required_status_checks",
                   "parameters": {"required_status_checks": [{"context": "ci", "integration_id": 15368}]}}],
    }]
    assert parse_rulesets(details, "main")["required_checks"][0]["source_restricted"] is True


def _pr_rule(**params: Any) -> dict[str, Any]:
    # bypass_actors present and empty == provably no bypass (a read-only token that cannot see
    # the list omits the key, which the parser treats as unknown -> fail closed).
    return {
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"]}},
        "bypass_actors": [],
        "rules": [{"type": "pull_request", "parameters": params}],
    }


def test_parse_rulesets_requires_review_needs_a_current_approval():
    # A review count alone is NOT enough. Without stale-review dismissal or
    # last-push approval, approve-A-then-force-push-B still satisfies the rule, so the queued head
    # may carry no current approval. requires_review must demand a CURRENT approval.
    assert parse_rulesets([_pr_rule(required_approving_review_count=1)], "main")["requires_review"] is False


def test_parse_rulesets_review_with_stale_dismissal_requires_review():
    rs = _pr_rule(required_approving_review_count=1, dismiss_stale_reviews_on_push=True)
    assert parse_rulesets([rs], "main")["requires_review"] is True


def test_parse_rulesets_review_with_last_push_approval_requires_review():
    rs = _pr_rule(required_approving_review_count=1, require_last_push_approval=True)
    assert parse_rulesets([rs], "main")["requires_review"] is True


def test_parse_rulesets_zero_required_reviews_is_not_requires_review():
    rs = _pr_rule(required_approving_review_count=0, dismiss_stale_reviews_on_push=True)
    assert parse_rulesets([rs], "main")["requires_review"] is False


def test_parse_rulesets_excluded_branch_does_not_apply():
    # A ruleset that targets ~ALL but excludes the branch must not count.
    rs = {
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~ALL"], "exclude": ["refs/heads/main"]}},
        "rules": [
            {"type": "pull_request",
             "parameters": {"required_approving_review_count": 1, "require_last_push_approval": True}},
            {"type": "required_status_checks",
             "parameters": {"required_status_checks": [{"context": "ci"}]}},
        ],
    }
    info = parse_rulesets([rs], "main")
    assert info["requires_review"] is False
    assert info["protected"] is False
    assert info["required_checks"] == []


def test_parse_rulesets_pattern_exclude_does_not_apply():
    # Exclude entries can be fnmatch patterns, not just literal refs.
    rs = {
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~ALL"], "exclude": ["refs/heads/mai*"]}},
        "rules": [{"type": "pull_request",
                   "parameters": {"required_approving_review_count": 1, "require_last_push_approval": True}}],
    }
    assert parse_rulesets([rs], "main")["requires_review"] is False


def test_parse_rulesets_review_with_bypass_actors_does_not_prove_approval():
    # A ruleset whose review rule can be bypassed cannot prove every
    # admitted PR carried an approval, so it does not set requires_review.
    rs = {
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"]}},
        "bypass_actors": [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}],
        "rules": [{"type": "pull_request",
                   "parameters": {"required_approving_review_count": 1, "require_last_push_approval": True}}],
    }
    assert parse_rulesets([rs], "main")["requires_review"] is False


def test_parse_rulesets_unknown_bypass_does_not_prove_approval():
    # GitHub omits bypass_actors unless the caller has write access to the
    # ruleset, and siglum audits read-only. A missing list is UNKNOWN, not "no bypass", so it must
    # not prove approval (fail closed). Only a present-and-empty list proves no bypass.
    rs = {
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"]}},
        # no bypass_actors key at all
        "rules": [{"type": "pull_request",
                   "parameters": {"required_approving_review_count": 1, "require_last_push_approval": True}}],
    }
    assert parse_rulesets([rs], "main")["requires_review"] is False


def test_parse_rulesets_ignores_disabled_and_off_target():
    details: list[dict[str, Any]] = [
        {"enforcement": "disabled", "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"]}},
         "rules": [{"type": "required_status_checks",
                    "parameters": {"required_status_checks": [{"context": "x"}]}}]},
        {"enforcement": "active", "conditions": {"ref_name": {"include": ["refs/heads/release"]}},
         "rules": [{"type": "deletion"}]},
    ]
    info = parse_rulesets(details, "main")
    assert info["protected"] is False and info["required_checks"] == []

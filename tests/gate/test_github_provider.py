from typing import Any

import pytest

from siglum.forge.base import ForgeReadError
from siglum.forge.github import approved_sha_from_reviews, parse_context, GitHubProvider


def test_parse_context_from_pull_request_event():
    env: dict[str, str] = {
        "GITHUB_RUN_ID": "99", "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_EVENT_NAME": "pull_request_target", "GITHUB_SHA": "s" * 40,
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_WORKFLOW_REF": "o/r/.github/workflows/gate.yml@refs/heads/main",
    }
    event: dict[str, Any] = {
        "pull_request": {"number": 7, "head": {"sha": "h" * 40},
                         "base": {"sha": "b" * 40}, "user": {"login": "alice"}}
    }
    run, merge = parse_context(env, event)
    assert run.run_attempt == "2" and run.runner_environment == "github-hosted"
    assert run.event_name == "pull_request_target"
    assert merge.head_sha == "h" * 40 and merge.base_sha == "b" * 40
    assert merge.merge_candidate_sha is None


def test_parse_context_merge_group_binds_candidate():
    env: dict[str, str] = {"GITHUB_EVENT_NAME": "merge_group", "RUNNER_ENVIRONMENT": "github-hosted"}
    event: dict[str, Any] = {"merge_group": {"head_sha": "c" * 40, "base_sha": "b" * 40}}
    _run, merge = parse_context(env, event)
    assert merge.merge_candidate_sha == "c" * 40 and merge.head_sha == "c" * 40


def test_provider_oidc_fails_closed_without_a_verified_id_token():
    # No fabrication: with no Actions id-token available, the provider fails closed rather
    # than inventing an identity from the editable GITHUB_ACTOR env var.
    env: dict[str, str] = {"GITHUB_ACTOR": "mallory", "GITHUB_REPOSITORY": "o/r",
                           "RUNNER_ENVIRONMENT": "github-hosted"}
    p = GitHubProvider.from_env(env, {}, "tok")
    with pytest.raises(ForgeReadError):
        p.oidc_claims()
    assert p.run_context().runner_environment == "github-hosted"


def test_enforcement_config_normalizes_fetch_errors_to_forge_read_error(monkeypatch):
    # Any failure to read the enforcement config must surface as ForgeReadError so the gate's
    # self-audit posts a fail-closed failure rather than crashing without a check.
    from siglum.audit.github import GitHubFetchError
    from siglum.forge import github

    def boom(repo: str, token: str) -> Any:
        raise GitHubFetchError("cannot read repo config")

    monkeypatch.setattr(github, "fetch_repo_config", boom)
    p = github.GitHubProvider("o/r", "tok", {}, {}, app_id=42)
    with pytest.raises(ForgeReadError):
        p.enforcement_config()


def test_provider_pr_number_from_event():
    p = GitHubProvider.from_env(
        {"GITHUB_REPOSITORY": "o/r"},
        {"pull_request": {"number": 12}},
        "tok",
    )
    assert p._pr_number() == 12


def test_upsert_pr_comment_patches_existing_marker():
    class CapturingProvider(GitHubProvider):
        def __init__(self):
            super().__init__("o/r", "tok", {}, {"pull_request": {"number": 12}})
            self.patched: list[tuple[str, dict[str, Any]]] = []
            self.posted: list[tuple[str, dict[str, Any]]] = []

        def _get(self, url: str) -> Any | None:
            assert url.endswith("/issues/12/comments?per_page=100")
            return [{"url": "https://api.github.com/comment/1", "body": "old <!-- siglum -->"}]

        def _patch(self, url: str, body: dict[str, Any]) -> None:
            self.patched.append((url, body))

        def _post(self, url: str, body: dict[str, Any]) -> None:
            self.posted.append((url, body))

    provider = CapturingProvider()
    provider.upsert_pr_comment(marker="<!-- siglum -->", body="new body")
    assert provider.patched == [
        ("https://api.github.com/comment/1", {"body": "<!-- siglum -->\nnew body"})
    ]
    assert provider.posted == []


# --- approved_sha_from_reviews: per-reviewer approval standing (resolves the dismissal gap) ---
def _review(state: str, commit: str, user: str = "alice") -> dict[str, Any]:
    return {"state": state, "commit_id": commit, "user": {"login": user}}


def test_approved_sha_single_approval():
    assert approved_sha_from_reviews([_review("APPROVED", "h" * 40)]) == "h" * 40


def test_approved_sha_dismissed_approval_does_not_count():
    # An approval that was later DISMISSED no longer counts (its state is now DISMISSED).
    reviews = [_review("APPROVED", "h" * 40), _review("DISMISSED", "h" * 40)]
    assert approved_sha_from_reviews(reviews) is None


def test_approved_sha_one_reviewers_dismissal_does_not_wipe_another():
    reviews = [
        _review("APPROVED", "h" * 40, user="alice"),
        _review("DISMISSED", "h" * 40, user="bob"),
    ]
    assert approved_sha_from_reviews(reviews) == "h" * 40


def test_approved_sha_outstanding_changes_requested_blocks():
    reviews = [
        _review("APPROVED", "h" * 40, user="alice"),
        _review("CHANGES_REQUESTED", "h" * 40, user="bob"),
    ]
    assert approved_sha_from_reviews(reviews) is None


def test_approved_sha_changes_then_approve_by_same_reviewer_counts():
    reviews = [
        _review("CHANGES_REQUESTED", "h" * 40, user="alice"),
        _review("APPROVED", "h" * 40, user="alice"),
    ]
    assert approved_sha_from_reviews(reviews) == "h" * 40


def test_approved_sha_comment_after_approval_does_not_revoke():
    reviews = [
        _review("APPROVED", "h" * 40, user="alice"),
        _review("COMMENTED", "h" * 40, user="alice"),
    ]
    assert approved_sha_from_reviews(reviews) == "h" * 40


def test_approved_sha_unattributable_changes_requested_still_blocks():
    # GitHub's review.user is nullable (a deleted reviewer). A CHANGES_REQUESTED must still block even
    # when it cannot be attributed to a reviewer, so the gate is never weakened.
    reviews = [
        _review("APPROVED", "h" * 40, user="alice"),
        {"state": "CHANGES_REQUESTED", "commit_id": "h" * 40, "user": None},
    ]
    assert approved_sha_from_reviews(reviews) is None


def test_approved_sha_unattributable_approval_does_not_grant():
    # An approval with no reviewer cannot grant approval (no one to attribute it to).
    assert approved_sha_from_reviews([{"state": "APPROVED", "commit_id": "h" * 40, "user": None}]) is None


def test_approved_sha_empty_is_none():
    assert approved_sha_from_reviews([]) is None


# --- merge base (the compare API is the source, never the base tip) -----------
def test_merge_base_from_compare_reads_the_sha():
    from siglum.forge.github import merge_base_from_compare
    assert merge_base_from_compare({"merge_base_commit": {"sha": "m" * 40}}) == "m" * 40


@pytest.mark.parametrize("payload", [None, {}, {"merge_base_commit": {}},
                                     {"merge_base_commit": {"sha": ""}},
                                     {"merge_base_commit": "m" * 40}])
def test_merge_base_from_compare_fails_closed_on_bad_shapes(payload):
    from siglum.forge.github import merge_base_from_compare
    with pytest.raises(ForgeReadError):
        merge_base_from_compare(payload)


def test_merge_context_refines_the_merge_base_once_via_compare():
    class CompareProvider(GitHubProvider):
        def __init__(self):
            event = {"pull_request": {"number": 1, "head": {"sha": "h" * 40},
                                      "base": {"sha": "b" * 40}}}
            super().__init__("o/r", "tok", {}, event)
            self.compare_calls = 0

        def _get(self, url: str) -> Any | None:
            assert url.endswith(f"/repos/o/r/compare/{'b' * 40}...{'h' * 40}")
            self.compare_calls += 1
            return {"merge_base_commit": {"sha": "m" * 40}}

    p = CompareProvider()
    assert p.merge_context().merge_base == "m" * 40
    assert p.merge_context().merge_base == "m" * 40   # memoized
    assert p.compare_calls == 1
    assert p.merge_context().base_sha == "b" * 40     # base tip is unchanged


def test_merge_context_without_both_shas_skips_the_compare():
    p = GitHubProvider("o/r", "tok", {"GITHUB_SHA": "s" * 40}, {})
    # no PR/merge_group event: base is empty, so there is nothing to compare against
    assert p.merge_context().merge_base == ""


def test_changed_files_at_the_api_cap_reports_no_usable_list():
    # GitHub's PR file list caps at 3000 entries. At the cap
    # the list may be truncated, so the provider must report "no usable list" and let the
    # gate fall back to scanning the whole head tree, never scan a partial change as whole.
    class CappedProvider(GitHubProvider):
        def __init__(self):
            super().__init__("o/r", "tok", {}, {"pull_request": {"number": 5}})

        def _get(self, url: str) -> Any | None:
            page = int(url.rsplit("page=", 1)[1])
            if page <= 30:
                return [{"filename": f"f{page}-{i}.txt"} for i in range(100)]
            return []

    assert CappedProvider().changed_files() == ()


def test_changed_files_below_the_cap_is_returned_in_full():
    class SmallProvider(GitHubProvider):
        def __init__(self):
            super().__init__("o/r", "tok", {}, {"pull_request": {"number": 5}})

        def _get(self, url: str) -> Any | None:
            return [{"filename": "a.txt"}, {"filename": "b.txt"}]

    assert SmallProvider().changed_files() == ("a.txt", "b.txt")


def test_parse_context_records_the_workflow_file_sha_not_the_trigger_sha():
    # The binding's workflow_ref_sha means "the commit the
    # workflow file was loaded from" (GITHUB_WORKFLOW_SHA); recording the triggering
    # commit (GITHUB_SHA) would bind the attestation to the wrong revision.
    env = {"GITHUB_SHA": "t" * 40, "GITHUB_WORKFLOW_SHA": "w" * 40,
           "RUNNER_ENVIRONMENT": "github-hosted"}
    run, _merge = parse_context(env, {})
    assert run.workflow_ref_sha == "w" * 40

"""GitHub adapter. parse_repo_config(), parse_workflow(), and parse_rulesets() are pure and
unit-tested; fetch_repo_config() does read-only GETs against the GitHub REST API (branch
protection, rulesets, and workflow files) and hands the normalized payload to the same parser
the tests exercise. Branch-protection and ruleset facts are merged into one RepoConfig.

Read-only only: no writes, no git merges."""
from __future__ import annotations

import base64
import fnmatch
import json
import urllib.error
import urllib.request
from typing import Any

import yaml

from siglum.audit.model import RepoConfig, RequiredCheck, WorkflowFile

_API = "https://api.github.com"
_GITHUB_ACTIONS_APP_ID = 15368


class GitHubFetchError(RuntimeError):
    """GitHub repo configuration could not be fetched."""


class GitHubForbiddenError(GitHubFetchError):
    """GitHub returned 403: the token lacks permission for this resource. Distinct from a
    404 absence, so a caller can report "could not verify" instead of "not configured"."""


def parse_repo_config(payload: dict[str, Any]) -> RepoConfig:
    checks = tuple(
        RequiredCheck(
            context=str(c["context"]),
            enforcement=str(c.get("enforcement", "unknown")),
            source_restricted=bool(c.get("source_restricted", False)),
            app_id=c["app_id"] if isinstance(c.get("app_id"), int) else None,
        )
        for c in payload.get("required_checks", [])
    )
    workflows = tuple(
        WorkflowFile(
            path=str(w["path"]),
            pr_editable=bool(w.get("pr_editable", False)),
            continue_on_error=bool(w.get("continue_on_error", False)),
            path_filters=tuple(str(p) for p in w.get("path_filters", [])),
            produces_checks=tuple(str(c) for c in w.get("produces_checks", [])),
        )
        for w in payload.get("workflows", [])
    )
    return RepoConfig(
        repo=str(payload["repo"]),
        required_checks=checks,
        workflows=workflows,
        admin_bypass_allowed=bool(payload.get("admin_bypass_allowed", False)),
        default_branch=str(payload.get("default_branch", "main")),
        protected=bool(payload.get("protected", True)),
        requires_review=bool(payload.get("requires_review", False)),
        repository_id=str(payload.get("repository_id", "")),
        protection_readable=bool(payload.get("protection_readable", True)),
    )


def parse_workflow(
    path: str, doc: dict[object, object], required_contexts: set[str]
) -> dict[str, Any]:
    """Pure: turn a parsed workflow YAML into the WorkflowFile payload shape.

    Note the YAML 1.1 gotcha: a bare `on:` key parses as the boolean True, so we look up
    both "on" and True (the doc therefore has mixed key types)."""
    on = doc.get("on", doc.get(True)) or {}
    if isinstance(on, str):
        events: dict[str, Any] = {on: {}}
    elif isinstance(on, list):
        events = {str(e): {} for e in on}
    elif isinstance(on, dict):
        events = on
    else:
        events = {}

    pr_editable = "pull_request" in events
    pr_cfg = events.get("pull_request")
    path_filters: tuple[str, ...] = ()
    if isinstance(pr_cfg, dict):
        pf = pr_cfg.get("paths") or pr_cfg.get("paths-ignore") or []
        path_filters = tuple(str(p) for p in pf)

    continue_on_error = False
    produced: set[str] = set()
    jobs = doc.get("jobs") or {}
    if isinstance(jobs, dict):
        for jid, job in jobs.items():
            if not isinstance(job, dict):
                continue
            produced.add(str(job.get("name") or jid))
            if job.get("continue-on-error") is True:
                continue_on_error = True
            for step in job.get("steps") or []:
                if isinstance(step, dict) and step.get("continue-on-error") is True:
                    continue_on_error = True

    return {
        "path": path,
        "pr_editable": pr_editable,
        "continue_on_error": continue_on_error,
        "path_filters": list(path_filters),
        # only the produced checks that are actually REQUIRED matter for the gate
        "produces_checks": sorted(produced & required_contexts),
    }


def parse_rulesets(details: list[dict[str, Any]], default_branch: str) -> dict[str, Any]:
    """Pure: extract protection facts from active repo rulesets that target the default
    branch. A required status check with no integration_id is satisfiable by any source
    (spoofable); bypass_actors means the gate can be bypassed."""
    protected = False
    checks: list[dict[str, Any]] = []
    admin_bypass = False
    requires_review = False
    branch_ref = f"refs/heads/{default_branch}"
    for rs in details:
        if rs.get("enforcement") != "active":
            continue
        ref_name = (rs.get("conditions") or {}).get("ref_name") or {}
        include = ref_name.get("include") or []
        exclude = ref_name.get("exclude") or []
        if not ("~DEFAULT_BRANCH" in include or "~ALL" in include or branch_ref in include):
            continue
        # An exclude match makes the condition fail, so the ruleset does not apply. exclude entries
        # can be fnmatch patterns, not just literal refs, so match accordingly (fail closed: an
        # excluded branch must not count toward protection). Known limitation: Python fnmatch lets
        # `*` cross `/`, unlike GitHub's FNM_PATHNAME, so a slashy branch could be over-excluded;
        # that is fail closed for requires_review, and the merge_group proof is default-branch only.
        # The include side is matched literally for the same fail-closed reason.
        if any(fnmatch.fnmatch(branch_ref, pat) for pat in exclude):
            continue
        rules = rs.get("rules") or []
        if rules:
            protected = True
        if rs.get("bypass_actors"):
            admin_bypass = True
        # Proving no bypass needs the bypass list. GitHub omits bypass_actors unless the caller has
        # write access to the ruleset, and this audit is read-only, so a MISSING list is unknown,
        # not "no bypass". Only a present-and-empty list proves the rule cannot be bypassed.
        bypass_known_empty = "bypass_actors" in rs and not rs["bypass_actors"]
        for rule in rules:
            if rule.get("type") == "pull_request":
                params = rule.get("parameters") or {}
                count = params.get("required_approving_review_count", 0)
                # A review count alone is not enough: without stale-review dismissal or last-push
                # approval, the queued head can carry a stale approval for earlier content. And a
                # bypassable (or unknown-bypass) rule does not prove every admitted PR was approved.
                # Require a CURRENT, provably non-bypassable approval (adversarial review).
                current = bool(
                    params.get("dismiss_stale_reviews_on_push")
                    or params.get("require_last_push_approval")
                )
                if isinstance(count, int) and count >= 1 and current and bypass_known_empty:
                    requires_review = True
                continue
            if rule.get("type") != "required_status_checks":
                continue
            for chk in (rule.get("parameters") or {}).get("required_status_checks") or []:
                iid = chk.get("integration_id")
                restricted = iid is not None and iid != 0
                checks.append(
                    {
                        "context": chk.get("context", ""),
                        "enforcement": "app_check_run" if restricted else "commit_status",
                        "source_restricted": restricted,
                        "app_id": iid if restricted else None,
                    }
                )
    return {
        "protected": protected,
        "required_checks": checks,
        "admin_bypass_allowed": admin_bypass,
        "requires_review": requires_review,
    }


def fetch_repo_config(repo: str, token: str) -> RepoConfig:
    """Assemble a RepoConfig from the GitHub branch-protection + ruleset + workflow APIs.
    Read-only."""
    return parse_repo_config(_fetch_payload(repo, token))


def fetch_repo_file(repo: str, path: str, token: str, *, ref: str | None = None) -> str | None:
    """Read a repo file through the GitHub contents API as text. Read-only."""
    suffix = f"?ref={ref}" if ref else ""
    data = _api_get(f"{_API}/repos/{repo}/contents/{path}{suffix}", token)
    if not isinstance(data, dict) or "content" not in data:
        return None
    return base64.b64decode(data["content"]).decode("utf-8", "replace")


def _api_get(url: str, token: str) -> Any | None:  # pragma: no cover
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "siglum-audit",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # 404 is the only genuine absence. 403 means the token cannot see the resource, which
        # must never read as "not configured", so it raises a typed error the caller can
        # turn into an honest "could not verify".
        if exc.code == 404:
            return None
        if exc.code == 403:
            raise GitHubForbiddenError(
                f"GET {url} returned 403: the token lacks permission for this resource"
            ) from exc
        raise


def _fetch_payload(repo: str, token: str) -> dict[str, Any]:
    info = _api_get(f"{_API}/repos/{repo}", token) or {}
    if not info:
        raise GitHubFetchError(f"cannot read GitHub repo {repo!r}; check repo slug and token access")
    branch = info.get("default_branch", "main")

    # 1. classic branch protection (reading it needs repo Administration read; 404 if none).
    # A 403 marks the protection facts unreadable rather than absent.
    protection_readable = True
    try:
        prot = _api_get(f"{_API}/repos/{repo}/branches/{branch}/protection", token)
    except GitHubForbiddenError:
        prot = None
        protection_readable = False
    protected = prot is not None
    required_checks: list[dict[str, Any]] = []
    admin_bypass = False
    requires_review = False
    if isinstance(prot, dict):
        reviews = prot.get("required_pull_request_reviews") or {}
        allowances = reviews.get("bypass_pull_request_allowances") or {}
        review_bypass = any(allowances.get(k) for k in ("users", "teams", "apps"))
        # A current, non-bypassable approval: a review is required, the approval cannot be for
        # earlier content than the queued head (stale dismissal or last-push approval), and no
        # actor may bypass the review requirement (adversarial review).
        if (
            int(reviews.get("required_approving_review_count", 0) or 0) >= 1
            and (reviews.get("dismiss_stale_reviews") or reviews.get("require_last_push_approval"))
            and not review_bypass
        ):
            requires_review = True
        for chk in (prot.get("required_status_checks") or {}).get("checks", []):
            app_id = chk.get("app_id")
            restricted = app_id is not None and app_id != -1
            required_checks.append(
                {
                    "context": chk.get("context", ""),
                    # pinned to a specific app (e.g. GitHub Actions) => not status-spoofable
                    "enforcement": "app_check_run" if restricted else "commit_status",
                    "source_restricted": restricted,
                    "app_id": app_id if restricted else None,
                }
            )
        admin_bypass = not (prot.get("enforce_admins") or {}).get("enabled", False)

    # 2. rulesets (readable without admin); fetch detail per ruleset, merge in. A 403 here
    # means the other source of protection facts is also unreadable.
    details: list[dict[str, Any]] = []
    try:
        rs_list = _api_get(f"{_API}/repos/{repo}/rulesets", token)
        if isinstance(rs_list, list):
            for rs in rs_list:
                detail = _api_get(f"{_API}/repos/{repo}/rulesets/{rs.get('id')}", token)
                if isinstance(detail, dict):
                    details.append(detail)
    except GitHubForbiddenError:
        protection_readable = False
    rs_info = parse_rulesets(details, branch)
    protected = protected or rs_info["protected"]
    admin_bypass = admin_bypass or rs_info["admin_bypass_allowed"]
    requires_review = requires_review or rs_info["requires_review"]
    seen = {c["context"] for c in required_checks}
    for c in rs_info["required_checks"]:
        if c["context"] not in seen:
            required_checks.append(c)
            seen.add(c["context"])

    required_contexts = {c["context"] for c in required_checks}
    workflows: list[dict[str, Any]] = []
    try:
        listing = _api_get(f"{_API}/repos/{repo}/contents/.github/workflows", token)
    except GitHubForbiddenError:
        listing = None
    if isinstance(listing, list):
        for entry in listing:
            name = entry.get("name", "")
            if not name.endswith((".yml", ".yaml")):
                continue
            f = _api_get(f"{_API}/repos/{repo}/contents/.github/workflows/{name}", token)
            if not isinstance(f, dict) or "content" not in f:
                continue
            try:
                text = base64.b64decode(f["content"]).decode("utf-8", "replace")
                doc = yaml.safe_load(text) or {}
            except (ValueError, yaml.YAMLError):
                continue
            if isinstance(doc, dict):
                workflows.append(
                    parse_workflow(f".github/workflows/{name}", doc, required_contexts)
                )

    return {
        "repo": repo,
        "repository_id": str(info.get("id", "")),
        "default_branch": branch,
        "protected": protected,
        "protection_readable": protection_readable,
        "required_checks": required_checks,
        "workflows": workflows,
        "admin_bypass_allowed": admin_bypass,
        "requires_review": requires_review,
    }

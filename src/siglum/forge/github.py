"""GitHub App forge provider + Actions-environment binding.

`parse_context` is pure and unit-tested: it turns the GitHub Actions environment + event
payload into the RunContext/MergeContext the gate needs. The REST calls (read base files,
post the check-run) are the network seam.

post_check_run uses the Checks API (an App / Actions check-run), never POST /statuses. A
commit status is spoofable. At Standard tier this runs with GITHUB_TOKEN; the Sealed tier
swaps in a GitHub App with a verified OIDC identity + Sigstore signing."""
from __future__ import annotations

import dataclasses
import json
import urllib.error
import urllib.request
from collections.abc import Iterable
from typing import Any
from urllib.parse import quote

from siglum.audit.github import GitHubFetchError, fetch_repo_config
from siglum.audit.model import RepoConfig
from siglum.forge.base import CheckRun, ForgeReadError, MergeContext, RunContext, VerifiedPr
from siglum.forge.github_app import (
    GitHubAppAuthError,
    create_installation_token,
    credentials_from_env,
)
from siglum.forge.oidc import fetch_jwks, github_actions_spec, verify_token

_API = "https://api.github.com"


def _read_disposition(status: int) -> str:
    """How to treat a failed base read: a 404 is a genuine absence; every other status
    (auth, permission, rate limit, server error) fails closed rather than degrading."""
    return "absent" if status == 404 else "error"


def _file_bytes_from_contents(data: Any) -> bytes | None:
    """Decode a GitHub contents-API response into file bytes. `None` (a 404 surfaced by
    `_get`) is the only genuine absence. A 200 response that is not a normal file (a
    directory listing, a submodule, or a symlink) is an anomaly, so fail closed rather
    than treat it as 'the file is absent'.

    The contents API only inlines base64 content up to ~1MB; for larger files it returns
    `encoding: "none"` with an empty `content`. Decoding that as `b""` would let a changed
    large anchored file hash equal to base and hide a head override, so any non-base64
    encoding fails closed rather than reading as empty."""
    if data is None:
        return None
    if not isinstance(data, dict) or "content" not in data:
        raise ForgeReadError("path is not a readable file (directory, submodule, or symlink)")
    if data.get("encoding") != "base64":
        raise ForgeReadError(
            f"contents API returned encoding {data.get('encoding')!r}, not base64 "
            "(file too large to read inline); fail closed"
        )
    import base64

    return base64.b64decode(data["content"])


def parse_context(
    env: dict[str, str], event: dict[str, Any]
) -> tuple[RunContext, MergeContext]:
    """Pure: GitHub Actions env + event payload -> (RunContext, MergeContext)."""
    run = RunContext(
        run_id=env.get("GITHUB_RUN_ID", ""),
        run_attempt=env.get("GITHUB_RUN_ATTEMPT", "1"),
        workflow_path=env.get("GITHUB_WORKFLOW_REF", env.get("GITHUB_WORKFLOW", "")),
        # GITHUB_WORKFLOW_SHA is the commit the workflow FILE was loaded from;
        # GITHUB_SHA is the commit that triggered the run. The binding records the former,
        # and an honest empty beats recording the wrong commit.
        workflow_ref_sha=env.get("GITHUB_WORKFLOW_SHA", ""),
        event_name=env.get("GITHUB_EVENT_NAME", ""),
        # RUNNER_ENVIRONMENT is "github-hosted" on hosted runners, "self-hosted" otherwise
        runner_environment=env.get("RUNNER_ENVIRONMENT", "unknown"),
    )

    pr = event.get("pull_request") or {}
    mg = event.get("merge_group") or {}
    head = (pr.get("head") or {}).get("sha") or mg.get("head_sha") or env.get("GITHUB_SHA", "")
    base = (pr.get("base") or {}).get("sha") or mg.get("base_sha") or ""
    base_ref = mg.get("base_ref") or _ref_of_pr_base(pr) or ""
    merge = MergeContext(
        head_sha=head,
        base_sha=base,
        # Approximation only: the base branch tip, not the common ancestor. The provider's
        # merge_context() replaces it with the real merge base from the compare API before
        # the gate records it.
        merge_base=base,
        merge_candidate_sha=mg.get("head_sha"),
        approved_sha=None,
        base_ref=base_ref,
    )
    return run, merge


def merge_base_from_compare(data: Any) -> str:
    """The merge-base SHA from a GitHub compare-API payload. Fails closed on any shape that
    does not carry one: merge_base is recorded in the signed predicate, so an unreadable
    value must never silently degrade to an approximation."""
    if isinstance(data, dict):
        mb = data.get("merge_base_commit")
        if isinstance(mb, dict):
            sha = mb.get("sha")
            if isinstance(sha, str) and sha:
                return sha
    raise ForgeReadError("compare API response carries no merge_base_commit sha")


def _ref_of_pr_base(pr: dict[str, Any]) -> str:
    """The fully-qualified target ref of a pull request (the merge_group event already gives a
    full ref; a PR base only gives the short branch name)."""
    name = (pr.get("base") or {}).get("ref")
    return f"refs/heads/{name}" if name else ""


def _reviewer_key(review: dict[str, Any]) -> str | None:
    user = review.get("user")
    if not isinstance(user, dict):
        return None
    ident = user.get("id")
    if ident is not None:
        return f"id:{ident}"
    login = user.get("login")
    return f"login:{login}" if login else None


def approved_sha_from_reviews(reviews: Iterable[dict[str, Any]]) -> str | None:
    """The commit currently approved by review, or None, computed per reviewer.

    A reviewer's standing is their LATEST review with a decisive state (APPROVED, CHANGES_REQUESTED,
    or DISMISSED); COMMENTED and PENDING do not change it. The result is the commit of the most recent
    reviewer whose latest state is APPROVED. An outstanding CHANGES_REQUESTED (a reviewer whose latest
    decisive state is CHANGES_REQUESTED) blocks and returns None. A DISMISSED review is a withdrawn
    approval that no longer counts, and one reviewer's dismissal does not wipe another reviewer's
    approval; a null reviewer (which GitHub allows) cannot grant approval, but a null-reviewer
    CHANGES_REQUESTED still blocks. prove_approval binds the result to the head (force-push defense)."""
    latest: dict[str, tuple[int, str, str]] = {}  # reviewer -> (order, state, commit)
    blocked = False
    for order, review in enumerate(reviews):
        if not isinstance(review, dict):
            continue
        state = review.get("state")
        if state not in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
            continue
        reviewer = _reviewer_key(review)
        if reviewer is None:
            # GitHub's review.user is nullable (a deleted reviewer). An unattributable review cannot
            # be tracked per reviewer, but a CHANGES_REQUESTED must still block (never weaken the
            # gate); an unattributable APPROVED cannot grant approval, so it is ignored.
            if state == "CHANGES_REQUESTED":
                blocked = True
            continue
        latest[reviewer] = (order, str(state), str(review.get("commit_id") or ""))
    standings = list(latest.values())
    if blocked or any(state == "CHANGES_REQUESTED" for _, state, _ in standings):
        return None
    approvals = [(order, commit) for order, state, commit in standings if state == "APPROVED" and commit]
    return max(approvals)[1] if approvals else None


class GitHubProvider:
    """ForgeProvider backed by the GitHub REST API in an Actions run."""

    def __init__(
        self,
        repo: str,
        token: str,
        env: dict[str, str],
        event: dict[str, Any],
        *,
        app_id: int | None = None,
    ):
        self._repo = repo
        self._token = token
        self._env = env
        self._event = event
        self._app_id = app_id
        self._enforcement_config: RepoConfig | None = None
        self._merge_base_refined = False
        self._run, self._merge = parse_context(env, event)

    @classmethod
    def from_env(cls, env: dict[str, str], event: dict[str, Any], token: str) -> GitHubProvider:
        # Partial App credentials raise (fail closed) inside credentials_from_env. None means the
        # Standard tier (GITHUB_TOKEN, no self-audit); creds mean the Sealed tier.
        creds = credentials_from_env(env)
        if creds is None:
            return cls(env.get("GITHUB_REPOSITORY", ""), token, env, event)
        if not creds.app_id.isdigit():
            raise GitHubAppAuthError(f"GitHub App id must be numeric, got {creds.app_id!r}")
        return cls(
            env.get("GITHUB_REPOSITORY", ""),
            create_installation_token(creds),
            env,
            event,
            app_id=int(creds.app_id),
        )

    def expected_app_id(self) -> int | None:
        return self._app_id

    def enforcement_config(self) -> RepoConfig:
        # Any failure to read the enforcement config must fail closed via ForgeReadError, so the
        # gate posts a failure rather than crashing (which could leave a prior green check).
        # Memoized: the merge_group approval proof and the enforcement self-audit both read it in one run.
        if self._enforcement_config is None:
            try:
                self._enforcement_config = fetch_repo_config(self._repo, self._token)
            except (GitHubFetchError, urllib.error.URLError, OSError, ValueError) as exc:
                raise ForgeReadError(f"could not read the enforcement config: {exc}") from exc
        return self._enforcement_config

    def run_context(self) -> RunContext:
        return self._run

    def merge_context(self) -> MergeContext:
        # The event's base sha is the base branch TIP, not the common ancestor. The predicate
        # records merge_base, so read the real one once from the compare API, failing closed
        # on any read problem. Events without both SHAs (e.g. a bare push) keep the
        # parse_context approximation.
        if not self._merge_base_refined:
            m = self._merge
            if m.base_sha and m.head_sha:
                data = self._get(
                    f"{_API}/repos/{self._repo}/compare/{m.base_sha}...{m.head_sha}"
                )
                self._merge = dataclasses.replace(
                    m, merge_base=merge_base_from_compare(data)
                )
            self._merge_base_refined = True
        return self._merge

    def verified_pr(self) -> VerifiedPr | None:  # pragma: no cover
        # Fetch the PR with the gate's token so the head sha and author are trusted-side
        # facts, not values read from the event payload. None for events with no single PR.
        number = self._pr_number()
        if number is None:
            return None
        data = self._get(f"{_API}/repos/{self._repo}/pulls/{number}")
        if not isinstance(data, dict):
            raise ForgeReadError("PR metadata is not a readable object")
        head = data.get("head")
        head_sha = head.get("sha") if isinstance(head, dict) else None
        if not isinstance(head_sha, str) or not head_sha:
            raise ForgeReadError("PR metadata has no head sha")
        user = data.get("user")
        author = user.get("login") if isinstance(user, dict) else None
        return VerifiedPr(head_sha=head_sha, author=str(author or ""))

    def approved_head_sha(self) -> str | None:  # pragma: no cover
        # The approved SHA from the PR's review state, read with the gate's own token.
        # Called by the gate only when the base policy requires approval proof.
        number = self._pr_number()
        if number is None:
            return None
        # Collect all review pages, then compute the approved SHA per reviewer (the pure logic in
        # approved_sha_from_reviews). prove_approval binds the result to the head.
        reviews: list[dict[str, Any]] = []
        page = 1
        while True:
            batch = self._get(
                f"{_API}/repos/{self._repo}/pulls/{number}/reviews?per_page=100&page={page}"
            )
            if not isinstance(batch, list) or not batch:
                break
            reviews.extend(r for r in batch if isinstance(r, dict))
            if len(batch) < 100:
                break
            page += 1
        return approved_sha_from_reviews(reviews)

    def oidc_claims(self) -> dict[str, object]:  # pragma: no cover
        # Sealed tier: mint this job's Actions id-token and VERIFY it (signature, issuer,
        # audience, expiry) before any claim is trusted. No fabrication from env.
        audience = self._env.get("SIGLUM_OIDC_AUDIENCE", "siglum")
        spec = github_actions_spec(audience)
        token = self._mint_id_token(audience)
        return verify_token(token, spec, jwks=fetch_jwks(spec.jwks_uri, issuer=spec.issuer))

    def _mint_id_token(self, audience: str) -> str:  # pragma: no cover
        url = self._env.get("ACTIONS_ID_TOKEN_REQUEST_URL")
        bearer = self._env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        if not url or not bearer:
            raise ForgeReadError(
                "no Actions OIDC token available; the Sealed gate requires id-token: write"
            )
        req = urllib.request.Request(
            f"{url}&audience={quote(audience)}",
            headers={"Authorization": f"Bearer {bearer}", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                value = json.loads(resp.read().decode("utf-8")).get("value")
        except (urllib.error.URLError, json.JSONDecodeError) as exc:
            raise ForgeReadError(f"minting the Actions OIDC token failed: {exc}") from exc
        if not isinstance(value, str) or not value:
            raise ForgeReadError("Actions OIDC token response had no value")
        return value

    # GitHub's "list pull request files" API returns at most this many entries, however
    # many pages are fetched. At the cap the list may be TRUNCATED, and a truncated list
    # must never be scanned as if it were complete.
    _CHANGED_FILES_API_CAP = 3000

    def changed_files(self) -> tuple[str, ...]:
        pr = self._event.get("pull_request") or {}
        number = pr.get("number")
        if number is None:
            return ()
        files: list[str] = []
        page = 1
        while True:
            data = self._get(
                f"{_API}/repos/{self._repo}/pulls/{number}/files?per_page=100&page={page}"
            )
            if not isinstance(data, list) or not data:
                break
            files.extend(str(f["filename"]) for f in data)
            if len(data) < 100:
                break
            page += 1
        if len(files) >= self._CHANGED_FILES_API_CAP:
            # Possibly truncated: a secret could sit in an unreturned file. Report "no
            # usable list" so the caller falls back to scanning the whole head tree
            # (fail closed), instead of passing a scan that skipped part of the change.
            return ()
        return tuple(files)

    def read_base_file(self, path: str, *, at_sha: str) -> bytes | None:  # pragma: no cover
        return self._read_file_at(path, at_sha)

    def read_head_file(self, path: str, *, at_sha: str) -> bytes | None:  # pragma: no cover
        # Same contents read, at the PR head sha. For a fork PR the head sha is reachable in
        # the base repo via refs/pull/N/head, so this resolves without checking out head.
        return self._read_file_at(path, at_sha)

    def _read_file_at(self, path: str, sha: str) -> bytes | None:  # pragma: no cover
        return _file_bytes_from_contents(
            self._get(f"{_API}/repos/{self._repo}/contents/{path}?ref={sha}")
        )

    def base_readable(self, at_sha: str) -> bool:  # pragma: no cover
        # A readable base commit confirms a 404 on a base file is a genuine absence, not a
        # hidden permission failure. A permission/server error raises ForgeReadError in _get.
        return self._get(f"{_API}/repos/{self._repo}/commits/{at_sha}") is not None

    def post_check_run(self, run: CheckRun) -> None:  # pragma: no cover
        body = {
            "name": run.name,
            "head_sha": run.head_sha,
            "status": "completed",
            "conclusion": run.conclusion.conclusion,
            "output": {"title": run.conclusion.title, "summary": run.conclusion.summary},
        }
        self._post(f"{_API}/repos/{self._repo}/check-runs", body)

    def upsert_pr_comment(self, *, marker: str, body: str) -> None:  # pragma: no cover
        number = self._pr_number()
        if number is None:
            return
        full_body = f"{marker}\n{body}"
        comments = self._get(f"{_API}/repos/{self._repo}/issues/{number}/comments?per_page=100")
        if isinstance(comments, list):
            for comment in comments:
                if not isinstance(comment, dict):
                    continue
                existing_body = comment.get("body")
                url = comment.get("url")
                if isinstance(existing_body, str) and marker in existing_body and isinstance(url, str):
                    self._patch(url, {"body": full_body})
                    return
        self._post(f"{_API}/repos/{self._repo}/issues/{number}/comments", {"body": full_body})

    def _pr_number(self) -> int | None:
        pr = self._event.get("pull_request") or {}
        number = pr.get("number")
        return int(number) if isinstance(number, int) else None

    # --- thin REST helpers (network) ----------------------------------------
    def _headers(self) -> dict[str, str]:  # pragma: no cover
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "siglum-gate",
        }

    def _get(self, url: str) -> Any | None:  # pragma: no cover
        req = urllib.request.Request(url, headers=self._headers())
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if _read_disposition(exc.code) == "absent":
                return None
            raise ForgeReadError(f"GET {url} failed: HTTP {exc.code}") from exc
        except (urllib.error.URLError, json.JSONDecodeError) as exc:
            # Network/timeout/malformed-JSON: a read failure, not an absence. Fail closed.
            raise ForgeReadError(f"GET {url} failed: {exc}") from exc

    def _post(self, url: str, body: dict[str, Any]) -> None:  # pragma: no cover
        req = urllib.request.Request(
            url, data=json.dumps(body).encode("utf-8"), headers=self._headers(), method="POST"
        )
        with urllib.request.urlopen(req, timeout=20):
            pass

    def _patch(self, url: str, body: dict[str, Any]) -> None:  # pragma: no cover
        req = urllib.request.Request(
            url, data=json.dumps(body).encode("utf-8"), headers=self._headers(), method="PATCH"
        )
        with urllib.request.urlopen(req, timeout=20):
            pass

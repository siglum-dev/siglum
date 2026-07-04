"""Forge seam: a thin provider boundary so GitHub assumptions never leak into gate logic.
Pure types + a Protocol. The GitHub implementation lives in forge/github.py; tests use a
FakeProvider over in-memory fixtures."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from siglum.audit.model import RepoConfig


@dataclass(frozen=True, slots=True)
class RunContext:
    run_id: str
    run_attempt: str
    workflow_path: str            # e.g. .github/workflows/siglum-seal-enforce.yml
    workflow_ref_sha: str         # the SHA the workflow file was loaded from
    event_name: str               # pull_request | merge_group | ...
    runner_environment: str       # "github-hosted" | "self-hosted" | "unknown"


@dataclass(frozen=True, slots=True)
class MergeContext:
    head_sha: str
    base_sha: str
    merge_base: str
    merge_candidate_sha: str | None = None   # merge_group SHA; None outside the merge queue
    approved_sha: str | None = None          # the SHA a required review approved
    base_ref: str = ""                       # target ref, e.g. refs/heads/main (merge_group proof)


@dataclass(frozen=True, slots=True)
class VerifiedPr:
    """The pull request as fetched from the forge with the gate's own token (trusted-side),
    not read from the event payload. Used to confirm the event head is still the current PR
    head and to record the author from a trusted source (audit only)."""
    head_sha: str
    author: str


@dataclass(frozen=True, slots=True)
class CheckConclusion:
    conclusion: str               # "success" | "failure" | "action_required"
    title: str
    summary: str


@dataclass(frozen=True, slots=True)
class CheckRun:
    name: str                     # the source-restricted context name
    head_sha: str
    conclusion: CheckConclusion


class ForgeReadError(Exception):
    """A base read failed for a reason that is NOT 'file absent' (auth, permission,
    rate limit, server error). The gate fails closed on this; it never degrades to a
    weaker default policy when it cannot confirm what the base actually says."""


class ForgeProvider(Protocol):
    """Thin boundary. GitHub assumptions never leak past this into gate logic."""

    def run_context(self) -> RunContext: ...
    def merge_context(self) -> MergeContext: ...
    def approved_head_sha(self) -> str | None:
        """The SHA the pull request's current review state approves, or None when there is no
        current approval (or no pull request). Called only when the base policy requires
        approval proof; a policy that does not require it never consults review state. Raises
        ForgeReadError on a read failure (fail closed)."""
        ...
    def verified_pr(self) -> VerifiedPr | None:
        """The current PR fetched with the gate's token (head sha + author). None for events
        with no single pull request (merge_group, push). Raises ForgeReadError on a read
        failure (fail closed)."""
        ...
    def read_base_file(self, path: str, *, at_sha: str) -> bytes | None:
        """Read a file at the PROTECTED BASE sha. Returns None iff the file is absent
        (404); raises ForgeReadError on any other failure."""
        ...
    def read_head_file(self, path: str, *, at_sha: str) -> bytes | None:
        """Read a file at the PR HEAD sha via the API (no checkout). Returns None iff the
        file is absent (404); raises ForgeReadError on any other failure. The trusted gate
        derives head digests itself with this, so a security-relevant head digest is never
        trusted from the untrusted gather artifact."""
        ...
    def base_readable(self, at_sha: str) -> bool:
        """True iff the protected base commit is readable. Used to distinguish a genuine
        'file absent' (404) from a hidden permission failure before trusting an absence."""
        ...
    def oidc_claims(self) -> dict[str, object]:
        """Verified OIDC claims for authority_from_claims() (the gate's run identity)."""
        ...

    def expected_app_id(self) -> int | None:
        """The Siglum App id at the Sealed tier, used to self-audit that the `siglum` check is
        restricted to THIS app. None at the Standard tier (no App), which skips the self-audit."""
        ...

    def enforcement_config(self) -> RepoConfig:
        """The active branch-protection + ruleset config for the gated repo's default branch,
        so the gate can confirm its own check is required and source-restricted."""
        ...
    def post_check_run(self, run: CheckRun) -> None:
        """Post via the GitHub App (source-restricted), never a commit status."""
        ...
    def upsert_pr_comment(self, *, marker: str, body: str) -> None:
        """Create or update the Siglum PR explanation. No-op when there is no PR."""
        ...

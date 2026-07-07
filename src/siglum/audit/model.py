"""Data model for the evidence-gap audit. Populated from the GitHub API (github.py)
but the model (and the scan over it) is pure and forge-agnostic."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class GapSeverity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True, slots=True)
class RequiredCheck:
    context: str
    enforcement: str          # "app_check_run" | "commit_status" | "unknown"
    source_restricted: bool   # the ruleset restricts which app/source may satisfy it
    app_id: int | None = None  # the specific GitHub App id it is restricted to (None = any source)


@dataclass(frozen=True, slots=True)
class WorkflowFile:
    path: str                          # .github/workflows/ci.yml
    pr_editable: bool                  # a PR can change it and it still runs (not base-anchored)
    continue_on_error: bool            # a required job carries continue-on-error
    path_filters: tuple[str, ...]      # paths/paths-ignore that let the run skip
    produces_checks: tuple[str, ...]   # required contexts this workflow satisfies


@dataclass(frozen=True, slots=True)
class RepoConfig:
    repo: str
    required_checks: tuple[RequiredCheck, ...]
    workflows: tuple[WorkflowFile, ...]
    admin_bypass_allowed: bool
    default_branch: str = "main"
    protected: bool = True       # default branch has branch protection or a ruleset
    requires_review: bool = False  # the protected default branch requires an approving review
    repository_id: str = ""        # the numeric GitHub repo id, when known (gate-identity mirror)
    # False when the protection facts themselves could not be read (403 on branch protection or
    # rulesets). protected=False then means "not proven", never "proven absent".
    protection_readable: bool = True


@dataclass(frozen=True, slots=True)
class AuditFinding:
    # UNPROTECTED_DEFAULT_BRANCH | SPOOFABLE_CHECK | PR_EDITABLE_WORKFLOW | SILENT_SKIP |
    # ADMIN_BYPASS
    code: str
    target: str      # the check context or workflow path
    severity: GapSeverity
    detail: str


@dataclass(frozen=True, slots=True)
class AuditReport:
    repo: str
    findings: tuple[AuditFinding, ...]

    def is_clean(self) -> bool:
        return not self.findings

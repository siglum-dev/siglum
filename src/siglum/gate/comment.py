"""PR comment rendering for Siglum gate outcomes."""
from __future__ import annotations

from siglum.authority import ref_of, workflow_path_of
from siglum.forge.base import CheckConclusion
from siglum.models import ValidatorAuthority
from siglum.verdict import Independence

SIGLUM_COMMENT_MARKER = "<!-- siglum:gate-comment:v1 -->"


def format_authority(
    authority: ValidatorAuthority, *, independence: Independence | None = None
) -> str:
    """The verified gate run and which identity policy it matched, so a misconfiguration
    (wrong workflow, wrong ref, unmatched identity) is visible on the PR, not just in logs."""
    path = workflow_path_of(authority.workflow_ref, authority.repository)
    ref = ref_of(authority.workflow_ref)
    lines = [
        f"**Verified gate run:** `{authority.repository}` "
        f"`{path}` @ `{ref}` ({authority.runner_class})",
    ]
    if independence is not None:
        lines.append(f"**Independence:** {_independence_label(independence)}")
    return "\n".join(lines)


def _independence_label(independence: Independence) -> str:
    if independence is Independence.SATISFIED:
        return "satisfied (the run matched the org-pinned gate identity)"
    if independence is Independence.UNMET:
        return "UNMET (the run did not match the org-pinned gate identity)"
    return "not required (no gate identity pinned)"


def render_pr_comment(conclusion: CheckConclusion, *, authority_section: str = "") -> str:
    status = _status_label(conclusion.conclusion)
    parts = [
        "### Siglum gate",
        "",
        f"**Outcome:** {status}",
        "",
        f"**{conclusion.title}**",
        "",
        "```text",
        conclusion.summary.strip() or "No additional details.",
        "```",
        "",
    ]
    if authority_section:
        parts.extend([authority_section, ""])
    parts.append(_next_step(conclusion))
    return "\n".join(parts)


def _status_label(conclusion: str) -> str:
    if conclusion == "success":
        return "merge eligible"
    if conclusion == "action_required":
        return "action required"
    return "blocked"


def _next_step(conclusion: CheckConclusion) -> str:
    if conclusion.conclusion == "success":
        return "Siglum found complete, passing evidence for this change."
    if "base-anchored inputs changed" in conclusion.title:
        return (
            "Restore the gate-critical policy or workflow change, or land that change through "
            "a separate trusted update before rerunning this PR."
        )
    if "coverage gaps" in conclusion.summary:
        return "Run or restore the missing required validator evidence, then rerun Siglum."
    if conclusion.conclusion == "action_required":
        return "A required validator errored. Fix the validator failure and rerun Siglum."
    return "Fix the failing required evidence, then rerun Siglum."

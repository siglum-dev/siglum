"""The evidence-gap rules. Each rule answers a question a maintainer can verify in
their own repo: can this required check be spoofed? can the head edit its own gate?
can a scanner silently skip? can an admin bypass? Pure over RepoConfig."""
from __future__ import annotations

from siglum.audit.model import AuditFinding, AuditReport, GapSeverity, RepoConfig


def audit(config: RepoConfig) -> AuditReport:
    findings: list[AuditFinding] = []

    # The strongest gap: nothing is required at all. An unprotected default branch lets any
    # change merge with no validation, strictly worse than a spoofable check. But that claim
    # is only honest when the protection facts were actually readable: a 403 on the protection
    # read (a non-admin token) is "could not verify", never a HIGH about a repo that may be
    # locked down.
    if not config.protected:
        if config.protection_readable:
            findings.append(
                AuditFinding(
                    code="UNPROTECTED_DEFAULT_BRANCH",
                    target=config.default_branch,
                    severity=GapSeverity.HIGH,
                    detail=(
                        f"default branch '{config.default_branch}' has no branch protection or "
                        f"ruleset; any change can be merged or pushed with no validation"
                    ),
                )
            )
        else:
            findings.append(
                AuditFinding(
                    code="PROTECTION_UNVERIFIED",
                    target=config.default_branch,
                    severity=GapSeverity.MEDIUM,
                    detail=(
                        f"branch protection for '{config.default_branch}' could not be read "
                        "with this token (HTTP 401/403), so this audit cannot tell whether the "
                        "branch is protected. To verify it, rerun with a token that has "
                        "repository admin (Administration read) access. If you cannot get "
                        "one, ask a repo admin to run the audit or to confirm the branch "
                        "protection settings directly."
                    ),
                )
            )

    for c in config.required_checks:
        if c.enforcement == "commit_status" or not c.source_restricted:
            findings.append(
                AuditFinding(
                    code="SPOOFABLE_CHECK",
                    target=c.context,
                    severity=GapSeverity.HIGH,
                    detail=(
                        f"required check '{c.context}' is satisfiable by an unrestricted "
                        f"status (enforcement={c.enforcement}, source_restricted="
                        f"{c.source_restricted}); any token with status:write can post a pass"
                    ),
                )
            )

    for w in config.workflows:
        if w.pr_editable and w.produces_checks:
            findings.append(
                AuditFinding(
                    code="PR_EDITABLE_WORKFLOW",
                    target=w.path,
                    severity=GapSeverity.HIGH,
                    detail=(
                        f"'{w.path}' satisfies required checks {list(w.produces_checks)} but is "
                        f"editable in PRs; a head can rewrite its own gate"
                    ),
                )
            )
        if w.continue_on_error:
            findings.append(
                AuditFinding(
                    code="SILENT_SKIP",
                    target=w.path,
                    severity=GapSeverity.MEDIUM,
                    detail=f"'{w.path}' has continue-on-error; a required job can fail without failing the check",
                )
            )
        if w.path_filters:
            findings.append(
                AuditFinding(
                    code="SILENT_SKIP",
                    target=w.path,
                    severity=GapSeverity.MEDIUM,
                    detail=(
                        f"'{w.path}' path filters {list(w.path_filters)} let the workflow skip and "
                        f"report success on filtered changes"
                    ),
                )
            )

    if config.admin_bypass_allowed:
        findings.append(
            AuditFinding(
                code="ADMIN_BYPASS",
                target=config.repo,
                severity=GapSeverity.LOW,
                detail="admins can bypass required checks (in scope to note, out of scope to defend)",
            )
        )

    findings.sort(key=lambda f: (f.code, f.target))
    return AuditReport(repo=config.repo, findings=tuple(findings))

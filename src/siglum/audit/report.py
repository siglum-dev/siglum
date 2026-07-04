"""Render the audit as markdown the maintainer reads against their own repo, and emit
one REAL sample attestation (the predicate over a synthetic clean change) so the
ask is concrete, not a mock."""
from __future__ import annotations

from typing import Any

from siglum.audit.model import AuditReport
from siglum.derive import assess
from siglum.models import (
    Change,
    EvidenceBundle,
    GateIdentityPolicy,
    PolicyRef,
    ValidatorAuthority,
    ValidatorResult,
)
from siglum.predicate import build_predicate
from siglum.verdict import ValidatorStatus


def render_markdown(report: AuditReport) -> str:
    lines = [f"# Siglum evidence-gap audit: `{report.repo}`", ""]
    if report.is_clean():
        lines.append("No evidence gaps found in the scanned configuration.")
        return "\n".join(lines) + "\n"
    lines.append(f"Found {len(report.findings)} gap(s):")
    lines.append("")
    lines.append("| Severity | Code | Target | Detail |")
    lines.append("|---|---|---|---|")
    for f in report.findings:
        detail = f.detail.replace("|", "\\|")
        lines.append(f"| {f.severity.value} | {f.code} | `{f.target}` | {detail} |")
    return "\n".join(lines) + "\n"


def sample_attestation(repo: str, head_sha: str) -> dict[str, Any]:
    """A real signed-shape predicate (unsigned here; the signing path signs it) over a synthetic
    clean change, so the maintainer sees exactly what a passing attestation looks like."""
    bundle = EvidenceBundle(
        change=Change(repo=repo, base_sha="0" * 40, head_sha=head_sha, merge_base="0" * 40),
        policy=PolicyRef(policy_id="sample", policy_hash="0" * 64, independence_required=True,
                         anchored_inputs_hash="0" * 64),
        validators=(
            ValidatorResult(id="tests", version="1", status=ValidatorStatus.PASSED,
                            required=True, artifact_digest="sha256:" + "0" * 64),
            ValidatorResult(id="secret-scan", version="0", status=ValidatorStatus.PASSED,
                            required=True, artifact_digest="sha256:" + "0" * 64),
        ),
        validator_authority=ValidatorAuthority(
            repository=repo, repository_id="0",
            workflow_ref=f"{repo}/.github/workflows/siglum-seal-enforce.yml@refs/heads/main",
            ref="refs/heads/main", runner_class="github-hosted",
        ),
        change_author="author",
        gate_identity=GateIdentityPolicy(
            repository=repo, workflow_path=".github/workflows/siglum-seal-enforce.yml",
            protected_refs=("refs/heads/main",), repository_id="0",
        ),
    )
    return build_predicate(assess(bundle))

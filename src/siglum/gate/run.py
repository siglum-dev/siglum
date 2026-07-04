"""`python -m siglum.gate.run`, the in-CI gate entry point.

Reads the GitHub Actions environment, runs the read-only validators over the PR's changed
files (safe under pull_request_target: a secret scan never executes head code), derives the
verdict, and posts the `siglum` check-run. Exit code 0 iff merge-eligible.

Standard/base-controlled tier: the workflow that invokes this is the BASE version (head
can't edit it), but identity is the Actions actor (not a verified OIDC token) and the
attestation is not signed. The Sealed tier adds the GitHub App identity + Sigstore."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any
from dataclasses import dataclass

from siglum.forge.base import CheckConclusion, CheckRun, ForgeReadError, MergeContext
from siglum.forge.github import GitHubProvider
from siglum.forge.github_app import GitHubAppAuthError
from siglum.forge.oidc import TokenVerifyError
from siglum.gate.evidence import EvidenceError
from siglum.gate.orchestrate import CHECK_RUN_NAME, GateInputs, Sealer, run_gate
from siglum.models import Assessment, Change, GateIdentityPolicy
from siglum.sealing.identity import IdentityPolicy
from siglum.sealing.seal import SignedAttestation
from siglum.policy import (
    POLICY_PATH,
    Policy,
    PolicyError,
    anchored_paths,
    default_policy,
    load_policy,
    parse_policy_bytes,
)
from siglum.validators.base import ValidationContext
from siglum.validators.secrets import SecretScanValidator
from siglum.verdict import ValidatorStatus


@dataclass(frozen=True, slots=True)
class LoadedResults:
    validators: tuple[Any, ...]


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    token = os.environ.get("GITHUB_TOKEN", "")
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    event = json.loads(Path(event_path).read_text()) if event_path else {}
    env = dict(os.environ)

    try:
        provider = GitHubProvider.from_env(env, event, token)
    except GitHubAppAuthError as exc:
        # Partial/invalid Sealed App credentials. Fail closed: do not silently degrade to
        # GITHUB_TOKEN. No check is posted, so a required `siglum` check stays unsatisfied.
        print("[siglum] failure: Siglum: GitHub App credentials are misconfigured")
        print(str(exc))
        return 1
    repo = env.get("GITHUB_REPOSITORY", "")
    # SIGLUM_WORKSPACE points at the head checkout to scan. GITHUB_WORKSPACE is reserved and
    # cannot be reliably overridden per-step, so we use a dedicated var (falling back to it).
    workspace = Path(env.get("SIGLUM_WORKSPACE") or env.get("GITHUB_WORKSPACE") or ".").resolve()

    # Subject for a posted failure, derived from the event so a failure check can be posted
    # even when a later trusted read fails.
    subject = (
        (event.get("merge_group") or {}).get("head_sha")
        or ((event.get("pull_request") or {}).get("head") or {}).get("sha")
        or env.get("GITHUB_SHA", "")
    )
    try:
        merge = provider.merge_context()
        subject = merge.merge_candidate_sha or merge.head_sha
        conclusion = _gate(provider, args, merge, repo, workspace, event, env)
    except (ForgeReadError, TokenVerifyError, PolicyError, EvidenceError) as exc:
        # A base read failed for a non-404 reason, the gate's OIDC identity could not be
        # verified, the base policy is malformed, or the (untrusted, head-shapeable) results
        # artifact is malformed. Every one of these fails closed with a posted failure check
        # rather than a bare traceback, a weaker policy, or an unverified identity.
        conclusion = CheckConclusion("failure", "Siglum: could not establish trusted inputs", str(exc))
        provider.post_check_run(
            CheckRun(name=CHECK_RUN_NAME, head_sha=subject, conclusion=conclusion)
        )
    print(f"[siglum] {conclusion.conclusion}: {conclusion.title}")
    print(conclusion.summary)
    return 0 if conclusion.conclusion == "success" else 1


def _gate(
    provider: GitHubProvider,
    args: argparse.Namespace,
    merge: MergeContext,
    repo: str,
    workspace: Path,
    event: dict[str, Any],
    env: dict[str, str],
) -> CheckConclusion:
    policy = _load_base_policy(provider, merge.base_sha, args.policy)
    policy_ref = policy.policy_ref()
    policy_anchor_paths = anchored_paths(policy)

    change = Change(
        repo=repo, base_sha=merge.base_sha, head_sha=merge.head_sha,
        merge_base=merge.merge_base, merge_candidate_sha=merge.merge_candidate_sha,
    )

    loaded = _load_results(args.results)
    if loaded is None:
        # Read-only validator only, safe to run over untrusted head content. Prefer the
        # PR's changed files; fall back to the whole head tree. Never fail OPEN: an empty
        # changed-files list (e.g. a token without pull-requests:read) must NOT mean
        # "nothing to scan, pass", so scan the checked-out head instead. When --results is
        # supplied (the seal-enforce job), no changed-files read happens at all.
        changed = provider.changed_files() or _all_files(workspace)
        scanner = SecretScanValidator()
        ctx = ValidationContext(change=change, workspace=workspace, changed_files=changed)
        results = (scanner.run(ctx),)
    else:
        results = loaded.validators

    pr = event.get("pull_request") or {}
    author = (pr.get("user") or {}).get("login") or env.get("GITHUB_ACTOR", "")

    # The expected gate identity comes from the base-anchored policy. It is None unless the
    # policy opts into independence with a [gate_identity] block, which is rejected at load if
    # loose, so independence is enforced against an org-pinned identity head cannot edit.
    inputs = GateInputs(
        repo=repo,
        # Pass the parsed PolicyRef straight through; rebuilding it by hand previously dropped
        # new flags (e.g. approval_required), bypassing the corresponding gate stop.
        policy=policy_ref,
        base_validators=policy.validators,
        anchored_paths=policy_anchor_paths,
        validator_results=results,
        change_author=author,
        gate_identity=policy.gate_identity,
    )
    # Sign + self-verify before publishing a green check, at the Sealed tier only (the App
    # is present and the seal-enforce workflow provides the Sigstore OIDC credential).
    sealer = (
        _build_sealer(repo, policy.gate_identity)
        if provider.expected_app_id() is not None
        else None
    )
    return run_gate(provider, inputs, sealer=sealer)


GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"


def expected_signer_identities(expected: GateIdentityPolicy) -> tuple[str, ...]:
    """The Fulcio certificate SAN(s) the org-pinned seal workflow signs with, one per protected
    ref. For GitHub Actions the SAN is https://github.com/<job_workflow_ref>, i.e. the repository,
    workflow path, and ref together, so pinning it binds the signature to the exact gate workflow,
    not merely to some workflow in the repository."""
    return tuple(
        f"https://github.com/{expected.repository}/{expected.workflow_path}@{ref}"
        for ref in expected.protected_refs
    )


def gate_self_verify_policy(repo: str, gate_identity: GateIdentityPolicy | None) -> IdentityPolicy:
    """The identity policy the gate self-verifies its own signature against. When an org-pinned
    gate identity is configured (independence), pin the exact signer workflow SAN; otherwise pin
    the repository only (independence is opt-in, so there is no workflow to pin)."""
    if gate_identity is None:
        return IdentityPolicy(
            policy_id="gate-self-verify", issuers=(GITHUB_OIDC_ISSUER,), repository_patterns=(repo,)
        )
    return IdentityPolicy(
        policy_id="gate-self-verify",
        issuers=(GITHUB_OIDC_ISSUER,),
        repository_patterns=(gate_identity.repository,),
        subject_patterns=expected_signer_identities(gate_identity),
    )


def _build_sealer(repo: str, gate_identity: GateIdentityPolicy | None) -> Sealer:  # pragma: no cover
    """The Sealed-tier sealer: keyless-sign the verdict (with the run binding recorded in the
    signed statement), then self-verify the bundle against an identity policy pinned to the
    org-pinned seal workflow (or the repo when independence is off), before any green check.
    The runner is already enforced from the verified OIDC token by the runtime authority floor
    before signing, so the binding here pins the workflow identity."""
    from siglum.gate.binding import RunBinding, binding_payload
    from siglum.sealing.seal import seal
    from siglum.sealing.verify_signed import verify_signed_bundle

    policy = gate_self_verify_policy(repo, gate_identity)

    def sealer(assessment: Assessment, binding: RunBinding) -> SignedAttestation:
        attestation = seal(assessment, trust="staging", run_binding=binding_payload(binding))
        verify_signed_bundle(
            attestation.sigstore_bundle, identity_policy=policy, trust="staging"
        )
        return attestation

    return sealer


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="siglum gate run")
    parser.add_argument("--results", type=Path, help="validator results JSON from gather job")
    parser.add_argument("--policy", type=Path, help="fallback local policy path")
    return parser.parse_args(argv)


def _load_base_policy(provider: GitHubProvider, base_sha: str, fallback: Path | None) -> Policy:
    data = provider.read_base_file(POLICY_PATH, at_sha=base_sha)
    if data is not None:
        return parse_policy_bytes(data)
    # The policy file came back absent (404). Trust that only after confirming the base is
    # readable; otherwise a hidden permission failure could silently weaken the gate.
    if not provider.base_readable(base_sha):
        raise ForgeReadError(
            f"base {base_sha} is not readable; refusing to assume no policy (fail closed)"
        )
    if fallback is not None and fallback.exists():
        return load_policy(fallback)
    return default_policy()


def _load_results(path: Path | None) -> LoadedResults | None:
    """Parse the gather results artifact. It crosses the trust boundary (a hostile head can
    shape it), so any malformation raises EvidenceError, which main() turns into a posted
    failure check rather than a bare traceback with no check on the PR."""
    if path is None:
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise EvidenceError(f"results artifact {path} is not readable JSON: {exc}") from exc
    rows = payload.get("validators", payload) if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise EvidenceError("--results must contain a list or {'validators': [...]}")
    out = []
    for row in rows:
        if not isinstance(row, dict):
            raise EvidenceError("each validator result must be an object")
        try:
            out.append(
                _validator_result(
                    id=str(row["id"]),
                    version=str(row.get("version", "?")),
                    status=ValidatorStatus(str(row["status"])),
                    required=bool(row.get("required", True)),
                    artifact_digest=str(row.get("artifact_digest", "")),
                )
            )
        except (KeyError, ValueError) as exc:
            raise EvidenceError(f"malformed validator result {row!r}: {exc}") from exc
    # head_digests from the artifact are deliberately NOT read: the trusted gate derives head
    # digests itself at the head sha, so the gather supplies only validator results.
    return LoadedResults(validators=tuple(out))


def _validator_result(
    *, id: str, version: str, status: ValidatorStatus, required: bool, artifact_digest: str
) -> Any:
    from siglum.models import ValidatorResult

    return ValidatorResult(
        id=id, version=version, status=status, required=required, artifact_digest=artifact_digest
    )


def _all_files(workspace: Path) -> tuple[str, ...]:
    """Relative paths of every file under the head checkout (excluding .git)."""
    out: list[str] = []
    for p in workspace.rglob("*"):
        if p.is_file() and ".git" not in p.relative_to(workspace).parts:
            out.append(str(p.relative_to(workspace)))
    return tuple(out)


if __name__ == "__main__":
    raise SystemExit(main())

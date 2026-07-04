"""Readiness checks for a live Sealed Siglum install."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from siglum.audit.github import fetch_repo_config, fetch_repo_file, parse_repo_config
from siglum.audit.model import RepoConfig
from siglum.gate.enforcement import enforcement_mismatch
from siglum.policy import PolicyError, anchored_paths, parse_policy_bytes

POLICY = ".siglum/policy.toml"
GATHER = ".github/workflows/siglum-gather.yml"
SEAL = ".github/workflows/siglum-seal-enforce.yml"
IDENTITY = "identity-policy.toml"


@dataclass(frozen=True, slots=True)
class SetupSnapshot:
    repo_config: RepoConfig
    files: dict[str, str | None]


@dataclass(frozen=True, slots=True)
class SetupCheck:
    code: str
    ok: bool
    detail: str


@dataclass(frozen=True, slots=True)
class SetupReport:
    repo: str
    checks: tuple[SetupCheck, ...]

    def is_ready(self) -> bool:
        return all(c.ok for c in self.checks)


def check_setup(snapshot: SetupSnapshot, *, expected_app_id: int | None = None) -> SetupReport:
    checks = [
        _check_required_siglum(snapshot.repo_config, expected_app_id),
        *_check_policy(snapshot.files.get(POLICY)),
        *_check_gate_identity(snapshot.files.get(POLICY), snapshot.repo_config),
        *_check_gather(snapshot.files.get(GATHER)),
        *_check_seal(snapshot.files.get(SEAL)),
        _check_identity_policy(snapshot.files.get(IDENTITY)),
    ]
    return SetupReport(repo=snapshot.repo_config.repo, checks=tuple(checks))


def load_local_snapshot(root: Path) -> SetupSnapshot:
    root = root.resolve()
    setup_config = root / "siglum-setup-config.json"
    audit_config = root / "siglum-audit-config.json"
    config_path = setup_config if setup_config.exists() else audit_config
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    files = {path: _read_optional(root / path) for path in (POLICY, GATHER, SEAL, IDENTITY)}
    return SetupSnapshot(repo_config=parse_repo_config(payload), files=files)


def fetch_github_snapshot(repo: str, token: str) -> SetupSnapshot:
    files = {path: fetch_repo_file(repo, path, token) for path in (POLICY, GATHER, SEAL, IDENTITY)}
    return SetupSnapshot(repo_config=fetch_repo_config(repo, token), files=files)


def report_json(report: SetupReport) -> dict[str, object]:
    return {
        "repo": report.repo,
        "ready": report.is_ready(),
        "checks": [
            {"code": c.code, "ok": c.ok, "detail": c.detail}
            for c in report.checks
        ],
    }


def render_markdown(report: SetupReport) -> str:
    lines = [f"# Siglum setup check: `{report.repo}`", ""]
    lines.append("Ready for live demo." if report.is_ready() else "Not ready for live demo.")
    lines.extend(["", "| Status | Code | Detail |", "|---|---|---|"])
    for check in report.checks:
        status = "OK" if check.ok else "FAIL"
        detail = check.detail.replace("|", "\\|")
        lines.append(f"| {status} | {check.code} | {detail} |")
    return "\n".join(lines) + "\n"


def _check_required_siglum(config: RepoConfig, expected_app_id: int | None) -> SetupCheck:
    # When the operator supplies the Siglum App id, mirror the runtime enforcement self-audit exactly:
    # the check must be required on a protected branch AND source-restricted to THAT app id.
    if expected_app_id is not None:
        reason = enforcement_mismatch(config, check_name="siglum", expected_app_id=expected_app_id)
        if reason is not None:
            return SetupCheck("SIGLUM_REQUIRED_CHECK", False, reason)
        return SetupCheck(
            "SIGLUM_REQUIRED_CHECK",
            True,
            f"required check 'siglum' is enforced and restricted to the Siglum App {expected_app_id}",
        )
    # No app id supplied: confirm the weaker property (restricted to some app) and say so.
    siglum = [c for c in config.required_checks if c.context == "siglum"]
    if not siglum:
        return SetupCheck("SIGLUM_REQUIRED_CHECK", False, "required check 'siglum' is missing")
    if not any(c.source_restricted for c in siglum):
        return SetupCheck(
            "SIGLUM_REQUIRED_CHECK",
            False,
            "required check 'siglum' is not source-restricted to the Siglum GitHub App",
        )
    return SetupCheck(
        "SIGLUM_REQUIRED_CHECK",
        True,
        "required check 'siglum' is present and source-restricted (pass --app-id to verify the app)",
    )


def _check_gate_identity(text: str | None, config: RepoConfig) -> tuple[SetupCheck, ...]:
    """When the policy opts into independence, confirm the base-anchored [gate_identity]
    mirrors what the runtime identity match will require: it names the gated repo, pins the
    deployed seal workflow, and every protected ref is the actually-protected default branch. The parser
    validates the ref SHAPE at load; this confirms it is really protected. repository_id is looser
    by design (the runtime enforces it only when pinned); a non-numeric pin fails (a repo id is
    numeric), a numeric pin is verified against the snapshot's numeric repo id when present, else disclosed.
    A missing or unparseable policy is already reported by _check_policy, so this stays quiet there."""
    if text is None:
        return ()
    try:
        policy = parse_policy_bytes(text.encode("utf-8"))
    except PolicyError:
        return ()
    gid = policy.gate_identity
    if gid is None:
        return ()
    repo_ok = gid.repository == config.repo
    workflow_ok = gid.workflow_path == SEAL
    expected_ref = f"refs/heads/{config.default_branch}"
    # Each declared ref must be the protected default branch. RepoConfig only proves the default
    # branch is protected, so any other ref cannot be confirmed protected here (documented limit).
    bad_refs = [r for r in gid.protected_refs if r != expected_ref or not config.protected]
    checks = [
        SetupCheck(
            "GATE_IDENTITY_REPO",
            repo_ok,
            "gate identity names the gated repository"
            if repo_ok
            else f"gate identity repository {gid.repository!r} does not match the gated repo {config.repo!r}",
        ),
        SetupCheck(
            "GATE_IDENTITY_WORKFLOW",
            workflow_ok,
            f"gate identity pins the seal workflow {SEAL!r}"
            if workflow_ok
            else f"gate identity workflow_path {gid.workflow_path!r} is not the seal workflow {SEAL!r}",
        ),
        SetupCheck(
            "GATE_IDENTITY_PROTECTED_REFS",
            not bad_refs,
            f"gate identity refs are the protected default branch {expected_ref!r}"
            if not bad_refs
            else f"gate identity refs are not the protected default branch {expected_ref!r} "
            f"(protected={config.protected}): {', '.join(gid.protected_refs)}",
        ),
    ]
    if gid.repository_id:
        if not gid.repository_id.isdigit():
            # A GitHub repo id is numeric; a non-numeric pin can never match the runtime OIDC id, so
            # it is a malformed policy that would fail closed at runtime. A matching non-numeric value
            # in a user-editable local config must not read as verified, so fail it here.
            checks.append(
                SetupCheck(
                    "GATE_IDENTITY_REPO_ID",
                    False,
                    f"gate identity repository_id {gid.repository_id!r} is not a numeric GitHub repo id",
                )
            )
        elif config.repository_id.isdigit():
            # The snapshot carries a real numeric repo id, so verify the pin against it and complete
            # the runtime identity mirror.
            match = gid.repository_id == config.repository_id
            checks.append(
                SetupCheck(
                    "GATE_IDENTITY_REPO_ID",
                    match,
                    f"gate identity repository_id {gid.repository_id!r} is verified against the gated repo"
                    if match
                    else f"gate identity repository_id {gid.repository_id!r} does not match the gated "
                    f"repo id {config.repository_id!r}",
                )
            )
        else:
            # No trustworthy numeric repo id in this snapshot (a local config without it): disclose the
            # pin as runtime-enforced rather than fail, so a stronger pinned policy stays clearable.
            checks.append(
                SetupCheck(
                    "GATE_IDENTITY_REPO_ID",
                    True,
                    f"gate identity pins repository_id {gid.repository_id!r}; enforced at runtime, "
                    "not verified by this preflight",
                )
            )
    return tuple(checks)


def _check_policy(text: str | None) -> tuple[SetupCheck, ...]:
    if text is None:
        return (SetupCheck("POLICY", False, f"{POLICY} is missing"),)
    try:
        policy = parse_policy_bytes(text.encode("utf-8"))
    except PolicyError as exc:
        return (SetupCheck("POLICY", False, str(exc)),)
    paths = set(anchored_paths(policy))
    missing = sorted({POLICY, GATHER, SEAL} - paths)
    checks = [
        SetupCheck("POLICY", True, "policy parses"),
        SetupCheck(
            "POLICY_INDEPENDENCE",
            policy.independence_required,
            "independence_required is true"
            if policy.independence_required
            else "independence_required must be true for Sealed",
        ),
        SetupCheck(
            "POLICY_ANCHORS",
            not missing,
            "policy anchors Siglum policy and workflows"
            if not missing
            else f"policy does not anchor: {', '.join(missing)}",
        ),
    ]
    return tuple(checks)


def _check_gather(text: str | None) -> tuple[SetupCheck, ...]:
    if text is None:
        return (SetupCheck("GATHER_WORKFLOW", False, f"{GATHER} is missing"),)
    return (
        SetupCheck("GATHER_WORKFLOW", True, f"{GATHER} exists"),
        SetupCheck(
            "GATHER_PACKAGE_SOURCE",
            "SIGLUM_PACKAGE_SPEC" in text,
            "gather installs Siglum from explicit package source"
            if "SIGLUM_PACKAGE_SPEC" in text
            else "gather must use SIGLUM_PACKAGE_SPEC instead of an implicit package name",
        ),
        SetupCheck(
            "GATHER_VALIDATORS",
            (
                "siglum.validators.run" in text
                and "--changed-files" in text
                and "upload-artifact" in text
            ),
            "gather runs Siglum validators over changed files and uploads results"
            if (
                "siglum.validators.run" in text
                and "--changed-files" in text
                and "upload-artifact" in text
            )
            else "gather must run siglum.validators.run --changed-files and upload results.json",
        ),
    )


def _check_seal(text: str | None) -> tuple[SetupCheck, ...]:
    if text is None:
        return (SetupCheck("SEAL_WORKFLOW", False, f"{SEAL} is missing"),)
    no_head_checkout = "actions/checkout" not in text
    has_gate = "siglum.gate.run" in text and "--results" in text
    permissions = ("id-token: write", "checks: write", "issues: write", "contents: read")
    missing_permissions = [p for p in permissions if p not in text]
    secrets = (
        "SIGLUM_GITHUB_APP_ID",
        "SIGLUM_GITHUB_APP_INSTALLATION_ID",
        "SIGLUM_GITHUB_APP_PRIVATE_KEY",
    )
    missing_secrets = [s for s in secrets if s not in text]
    return (
        SetupCheck("SEAL_WORKFLOW", True, f"{SEAL} exists"),
        SetupCheck(
            "SEAL_NO_HEAD_CHECKOUT",
            no_head_checkout,
            "seal job does not checkout head"
            if no_head_checkout
            else "seal job must not use actions/checkout",
        ),
        SetupCheck(
            "SEAL_GATE_RUN",
            has_gate,
            "seal job runs siglum.gate.run with results"
            if has_gate
            else "seal job must run siglum.gate.run --results",
        ),
        SetupCheck(
            "SEAL_PACKAGE_SOURCE",
            "SIGLUM_PACKAGE_SPEC" in text,
            "seal installs Siglum from explicit package source"
            if "SIGLUM_PACKAGE_SPEC" in text
            else "seal must use SIGLUM_PACKAGE_SPEC instead of an implicit package name",
        ),
        SetupCheck(
            "SEAL_PERMISSIONS",
            not missing_permissions,
            "seal job declares required permissions"
            if not missing_permissions
            else f"seal job missing permissions: {', '.join(missing_permissions)}",
        ),
        SetupCheck(
            "SEAL_APP_SECRETS",
            not missing_secrets,
            "seal job declares Siglum GitHub App secrets"
            if not missing_secrets
            else f"seal job missing secrets: {', '.join(missing_secrets)}",
        ),
    )


def _check_identity_policy(text: str | None) -> SetupCheck:
    if text is None:
        return SetupCheck("IDENTITY_POLICY", False, f"{IDENTITY} is missing")
    ok = (
        "https://token.actions.githubusercontent.com" in text
        and "repository_patterns" in text
        and 'require_runner_environment = "github-hosted"' in text
    )
    return SetupCheck(
        "IDENTITY_POLICY",
        ok,
        "identity policy pins GitHub OIDC, repo, and hosted runner"
        if ok
        else "identity policy must pin GitHub OIDC issuer, repository, and hosted runner",
    )


def _read_optional(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None

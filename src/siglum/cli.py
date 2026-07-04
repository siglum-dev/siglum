"""Top-level Siglum command line."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from siglum.audit.github import GitHubFetchError, fetch_repo_config, parse_repo_config
from siglum.audit.report import render_markdown, sample_attestation
from siglum.audit.scan import audit
from siglum.demo_scaffold import DemoScaffoldError, scaffold_demo
from siglum.gate.run import main as gate_run_main
from siglum.policy import PolicyError, anchored_paths, default_policy, load_policy
from siglum.release import (
    ReleaseCheckRejected,
    check_signed_bundle,
    check_statement,
    load_gate_identity,
    load_identity_policy,
    load_statement,
)
from siglum.setup_check import (
    check_setup,
    fetch_github_snapshot,
    load_local_snapshot,
    render_markdown as render_setup_markdown,
    report_json as setup_report_json,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="siglum")
    sub = parser.add_subparsers(dest="command", required=True)

    audit_p = sub.add_parser("audit", help="scan a repository for evidence-gap risks")
    audit_p.add_argument("--repo", help="GitHub repo, e.g. owner/name")
    audit_p.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    audit_p.add_argument("--config", type=Path, help="local normalized RepoConfig JSON")
    audit_p.add_argument("--json", action="store_true", help="emit normalized JSON")
    audit_p.add_argument("--sample-attestation", action="store_true")
    audit_p.set_defaults(func=_audit)

    policy_p = sub.add_parser("policy", help="policy tools")
    policy_sub = policy_p.add_subparsers(dest="policy_command", required=True)
    lint_p = policy_sub.add_parser("lint", help="validate .siglum/policy.toml")
    lint_p.add_argument("path", nargs="?", type=Path, default=Path(".siglum/policy.toml"))
    lint_p.add_argument("--json", action="store_true")
    lint_p.set_defaults(func=_policy_lint)

    gate_p = sub.add_parser("gate", help="sealed gate commands")
    gate_sub = gate_p.add_subparsers(dest="gate_command", required=True)
    run_p = gate_sub.add_parser("run", help="run the gate in CI")
    run_p.add_argument("gate_args", nargs=argparse.REMAINDER)
    run_p.set_defaults(func=_gate_run)

    release_p = sub.add_parser("release-check", help="require Siglum proof before publish")
    release_p.add_argument("--commit", required=True)
    release_p.add_argument("--attestation", type=Path, help="Siglum statement JSON")
    release_p.add_argument("--bundle", type=Path, help="Sigstore bundle JSON")
    release_p.add_argument("--identity-policy", type=Path, help="identity policy TOML")
    release_p.add_argument(
        "--gate-identity",
        type=Path,
        help="require the recorded gate authority to match this gate-identity TOML",
    )
    release_p.add_argument("--trust", default="staging")
    release_p.add_argument(
        "--allow-unsigned-predicate",
        action="store_true",
        help="dry-run/test mode only; production release checks should verify a signed bundle",
    )
    release_p.set_defaults(func=_release_check)

    demo_p = sub.add_parser("demo", help="demo fixture tools")
    demo_sub = demo_p.add_subparsers(dest="demo_command", required=True)
    scaffold_p = demo_sub.add_parser(
        "scaffold", help="create the Miasma-prevention fixture repo"
    )
    scaffold_p.add_argument("--out", type=Path, required=True)
    scaffold_p.add_argument("--repo", default="siglum/miasma-prevention-demo")
    scaffold_p.add_argument("--force", action="store_true")
    scaffold_p.set_defaults(func=_demo_scaffold)

    setup_p = sub.add_parser("setup", help="live install readiness checks")
    setup_sub = setup_p.add_subparsers(dest="setup_command", required=True)
    check_p = setup_sub.add_parser("check", help="verify a Sealed GitHub install")
    check_p.add_argument("--repo", help="GitHub repo, e.g. owner/name")
    check_p.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    check_p.add_argument("--local", type=Path, help="local repo fixture/check-out")
    check_p.add_argument(
        "--app-id",
        type=int,
        default=None,
        help="Siglum GitHub App id; verifies the required check is restricted to it (mirrors the runtime enforcement self-audit)."
        " Defaults to SIGLUM_GITHUB_APP_ID.",
    )
    check_p.add_argument("--json", action="store_true")
    check_p.set_defaults(func=_setup_check)

    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except PolicyError as exc:
        print(f"siglum: {exc}", file=sys.stderr)
        return 2
    except ReleaseCheckRejected as exc:
        print(f"siglum: release rejected: {exc}", file=sys.stderr)
        return 1
    except DemoScaffoldError as exc:
        print(f"siglum: {exc}", file=sys.stderr)
        return 2
    except GitHubFetchError as exc:
        print(f"siglum: {exc}", file=sys.stderr)
        return 2


def _audit(args: argparse.Namespace) -> int:
    if args.config:
        payload = json.loads(args.config.read_text(encoding="utf-8"))
        config = parse_repo_config(payload)
    else:
        if not args.repo:
            raise SystemExit("siglum audit requires --repo or --config")
        config = fetch_repo_config(args.repo, args.token)

    report = audit(config)
    if args.json:
        print(json.dumps(_report_json(report), indent=2, sort_keys=True))
    else:
        print(render_markdown(report), end="")
    if args.sample_attestation:
        print(json.dumps(sample_attestation(config.repo, "0" * 40), indent=2, sort_keys=True))
    return 1 if report.findings else 0


def _policy_lint(args: argparse.Namespace) -> int:
    policy = load_policy(args.path) if args.path.exists() else default_policy()
    payload = {
        "policy_id": policy.policy_id,
        "policy_hash": policy.policy_ref().policy_hash,
        "independence_required": policy.independence_required,
        "required_validators": list(policy.required_validator_ids()),
        "anchored_paths": list(anchored_paths(policy)),
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"policy ok: {policy.policy_id}")
        print(f"policy hash: {policy.policy_ref().policy_hash}")
        print(f"required validators: {', '.join(policy.required_validator_ids())}")
        print(f"anchored paths: {', '.join(anchored_paths(policy))}")
    return 0


def _gate_run(args: argparse.Namespace) -> int:
    return gate_run_main(args.gate_args)


def _release_check(args: argparse.Namespace) -> int:
    gate_identity = load_gate_identity(args.gate_identity) if args.gate_identity else None
    if args.bundle:
        if not args.identity_policy:
            raise ReleaseCheckRejected("--bundle requires --identity-policy")
        result = check_signed_bundle(
            args.bundle.read_text(encoding="utf-8"),
            commit=args.commit,
            identity_policy=load_identity_policy(args.identity_policy),
            trust=args.trust,
            gate_identity=gate_identity,
        )
    else:
        if not args.attestation:
            raise ReleaseCheckRejected("provide --bundle or --attestation")
        if not args.allow_unsigned_predicate:
            raise ReleaseCheckRejected(
                "unsigned predicate requires --allow-unsigned-predicate"
            )
        result = check_statement(
            load_statement(args.attestation), commit=args.commit, gate_identity=gate_identity
        )
    print(f"release ok: {result.commit}")
    print(f"decision hash: {result.decision_hash}")
    print(f"policy hash: {result.policy_hash}")
    return 0


def _demo_scaffold(args: argparse.Namespace) -> int:
    result = scaffold_demo(args.out, repo=args.repo, force=args.force)
    print(f"demo scaffolded: {result.root}")
    print(f"files written: {len(result.files)}")
    print(f"next: cd {result.root} && siglum audit --config siglum-audit-config.json")
    return 0


def _app_id_from_env() -> int | None:
    """Resolve the Siglum App id from the environment for the preflight. Unset/empty -> None (run
    the weaker no-app-id check). Set but not numeric -> fail closed, mirroring the runtime, which
    rejects a non-numeric App id (isdigit) rather than degrading to a weaker check."""
    value = os.environ.get("SIGLUM_GITHUB_APP_ID", "")
    if not value:
        return None
    if not value.isdigit():
        raise SystemExit(
            "SIGLUM_GITHUB_APP_ID must be the numeric Siglum GitHub App id (digits only); got "
            f"{value!r}. Unset it to run the weaker check, or pass a valid --app-id."
        )
    return int(value)


def _setup_check(args: argparse.Namespace) -> int:
    app_id = args.app_id if args.app_id is not None else _app_id_from_env()
    if args.local:
        snapshot = load_local_snapshot(args.local)
    else:
        if not args.repo:
            raise SystemExit("siglum setup check requires --repo or --local")
        snapshot = fetch_github_snapshot(args.repo, args.token)
    report = check_setup(snapshot, expected_app_id=app_id)
    if args.json:
        print(json.dumps(setup_report_json(report), indent=2, sort_keys=True))
    else:
        print(render_setup_markdown(report), end="")
    return 0 if report.is_ready() else 1


def _report_json(report: Any) -> dict[str, Any]:
    return {
        "repo": report.repo,
        "findings": [
            {
                "code": f.code,
                "target": f.target,
                "severity": f.severity.value,
                "detail": f.detail,
            }
            for f in report.findings
        ],
    }


if __name__ == "__main__":
    raise SystemExit(main())

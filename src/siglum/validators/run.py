"""Gather-side validator runner.

This job may run in the PR/head context. For v1 it only runs concrete built-in
read-only validators; arbitrary commands are deliberately not exposed as gate-critical
evidence.
"""
from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any

from siglum.models import Change, ValidatorResult
from siglum.validators.base import ValidationContext
from siglum.validators.secrets import SecretScanValidator


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    workspace = args.workspace.resolve()
    changed = _changed_files(args, workspace)
    change = Change(
        repo=os.environ.get("GITHUB_REPOSITORY", ""),
        base_sha=os.environ.get("GITHUB_BASE_SHA", ""),
        head_sha=os.environ.get("GITHUB_SHA", ""),
        merge_base=os.environ.get("GITHUB_BASE_SHA", ""),
    )
    ctx = ValidationContext(change=change, workspace=workspace, changed_files=changed)
    results = (SecretScanValidator().run(ctx),)
    # The gather is untrusted: it reports only validator observations. Head digests for the
    # base-anchored inputs are derived by the trusted gate itself at the head sha,
    # so this job no longer reports them.
    payload = {"validators": [_result_json(r) for r in results]}
    if args.out:
        args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    else:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if all(r.status.value == "PASSED" for r in results) else 1


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="siglum validators run")
    parser.add_argument("--out", type=Path, help="write validator results JSON")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--changed-file", action="append", default=[])
    parser.add_argument("--changed-files", type=Path, help="newline-delimited changed file list")
    return parser.parse_args(argv)


def _changed_files(args: argparse.Namespace, workspace: Path) -> tuple[str, ...]:
    paths: list[str] = list(args.changed_file)
    if args.changed_files:
        paths.extend(
            p.strip()
            for p in args.changed_files.read_text(encoding="utf-8").splitlines()
            if p.strip()
        )
    if paths:
        return tuple(paths)
    return _all_files(workspace)


def _all_files(workspace: Path) -> tuple[str, ...]:
    out: list[str] = []
    for path in workspace.rglob("*"):
        if path.is_file() and ".git" not in path.relative_to(workspace).parts:
            out.append(str(path.relative_to(workspace)))
    return tuple(out)


def _result_json(result: ValidatorResult) -> dict[str, Any]:
    payload = asdict(result)
    payload["status"] = result.status.value
    return payload


if __name__ == "__main__":
    raise SystemExit(main())

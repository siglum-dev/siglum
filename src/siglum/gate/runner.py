"""Hosted-runner requirement: at Sealed, fail closed on self-hosted or
unknown runner class: an attacker-controlled runner could fabricate evidence."""
from __future__ import annotations

from siglum.forge.base import RunContext
from siglum.gate.errors import GateRefused


def require_hosted_runner(run: RunContext) -> None:
    if run.runner_environment != "github-hosted":
        raise GateRefused(
            f"runner_environment {run.runner_environment!r} is not github-hosted (fail closed)"
        )

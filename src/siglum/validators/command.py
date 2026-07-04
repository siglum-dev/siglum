"""Run a pinned argv as a validator. Fail-closed: anything that isn't a clean exit
code is ERRORED, never a silent pass."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass

from siglum.models import ValidatorResult
from siglum.validators.base import ValidationContext, sha256_hex
from siglum.verdict import ValidatorStatus


@dataclass(frozen=True, slots=True)
class CommandValidator:
    id: str
    version: str
    required: bool
    argv: list[str]
    timeout_s: int = 600

    def run(self, ctx: ValidationContext) -> ValidatorResult:
        try:
            proc = subprocess.run(
                self.argv,
                cwd=ctx.workspace,
                capture_output=True,
                timeout=self.timeout_s,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            status = ValidatorStatus.ERRORED
            artifact = sha256_hex(f"{type(exc).__name__}:{exc}".encode())
            return ValidatorResult(self.id, self.version, status, self.required, artifact)

        status = ValidatorStatus.PASSED if proc.returncode == 0 else ValidatorStatus.FAILED
        artifact = sha256_hex(proc.stdout + b"\x00" + proc.stderr)
        return ValidatorResult(self.id, self.version, status, self.required, artifact)

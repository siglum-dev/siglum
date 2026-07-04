"""Built-in secret scanner over changed files. Concrete + pinned, so it is safe to be
gate-critical at the Sealed tier (unlike an arbitrary head-controlled command)."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

from siglum.models import ValidatorResult
from siglum.validators.base import ValidationContext, sha256_hex
from siglum.verdict import ValidatorStatus

# Conservative, low-false-positive patterns for v0. Extend deliberately.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
)


@dataclass(frozen=True, slots=True)
class SecretScanValidator:
    id: str = "secret-scan"
    version: str = "0"
    required: bool = True

    def run(self, ctx: ValidationContext) -> ValidatorResult:
        findings: list[dict[str, object]] = []
        for rel in ctx.changed_files:
            path = ctx.workspace / rel
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
                # A deleted file or a non-file entry (a submodule) has no content to scan.
                continue
            except OSError:
                # A present file the scanner cannot read is missing evidence, not a pass:
                # ERRORED fails closed, so a required secret-scan blocks the merge instead
                # of silently skipping the unreadable file.
                return ValidatorResult(
                    self.id, self.version, ValidatorStatus.ERRORED, self.required, ""
                )
            for name, pat in _PATTERNS:
                for m in pat.finditer(text):
                    findings.append({"file": rel, "rule": name, "line": text[: m.start()].count("\n") + 1})
        status = ValidatorStatus.FAILED if findings else ValidatorStatus.PASSED
        artifact = sha256_hex(json.dumps(findings, sort_keys=True).encode())
        return ValidatorResult(self.id, self.version, status, self.required, artifact)

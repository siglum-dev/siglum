"""Validator contract. A validator observes a change and returns a ValidatorResult."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from siglum.models import Change, ValidatorResult


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass(frozen=True, slots=True)
class ValidationContext:
    change: Change
    workspace: Path           # a checked-out copy of the change head
    changed_files: tuple[str, ...]


class Validator(Protocol):
    # Read-only members: our validators are frozen dataclasses, so the Protocol must
    # declare these as read-only (properties) rather than settable variables.
    @property
    def id(self) -> str: ...
    @property
    def version(self) -> str: ...
    @property
    def required(self) -> bool: ...

    def run(self, ctx: ValidationContext) -> ValidatorResult: ...

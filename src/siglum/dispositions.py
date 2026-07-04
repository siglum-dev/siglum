"""Dispositions: mark a finding accepted (with optional expiry), and apply them.

STAGED CAPABILITY: fully tested, but no runtime consumer yet; the gate does not read a
dispositions file today. A disposition suppresses a finding by fingerprint while it is
ACTIVE (not expired). Fail-closed: an unparseable expiry is treated as expired so a
malformed waiver cannot indefinitely protect a finding."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from siglum.findings import Finding


@dataclass(frozen=True, slots=True)
class Disposition:
    issue_fingerprint: str
    reason: str
    actor: str
    expires: str | None = None     # ISO-8601; None = never expires

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "issue_fingerprint": self.issue_fingerprint,
            "reason": self.reason,
            "actor": self.actor,
        }
        if self.expires is not None:
            d["expires"] = self.expires
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Disposition:
        return cls(
            issue_fingerprint=str(data["issue_fingerprint"]),
            reason=str(data["reason"]),
            actor=str(data["actor"]),
            expires=data.get("expires"),
        )


def load_dispositions(path: Path) -> tuple[Disposition, ...]:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ()
    data = json.loads(raw)
    if not isinstance(data, list):
        raise ValueError("dispositions file must contain a JSON array")
    return tuple(Disposition.from_dict(item) for item in data)


def save_dispositions(path: Path, dispositions: tuple[Disposition, ...]) -> None:
    payload = [
        d.to_dict() for d in sorted(dispositions, key=lambda d: d.issue_fingerprint)
    ]
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def add_disposition(
    existing: tuple[Disposition, ...], new: Disposition
) -> tuple[Disposition, ...]:
    filtered = tuple(d for d in existing if d.issue_fingerprint != new.issue_fingerprint)
    return (*filtered, new)


def revoke_disposition(
    existing: tuple[Disposition, ...], issue_fingerprint: str
) -> tuple[Disposition, ...]:
    return tuple(d for d in existing if d.issue_fingerprint != issue_fingerprint)


def expired_dispositions(
    dispositions: tuple[Disposition, ...], now: datetime | None = None
) -> tuple[Disposition, ...]:
    if now is None:
        now = datetime.now(UTC)
    out: list[Disposition] = []
    for d in dispositions:
        if d.expires is None:
            continue
        try:
            expiry = datetime.fromisoformat(d.expires)
        except ValueError:
            out.append(d)  # fail-closed: malformed expiry => expired
            continue
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)
        if expiry <= now:
            out.append(d)
    return tuple(out)


def active_dispositions(
    dispositions: tuple[Disposition, ...], now: datetime | None = None
) -> tuple[Disposition, ...]:
    expired_fps = {d.issue_fingerprint for d in expired_dispositions(dispositions, now)}
    return tuple(d for d in dispositions if d.issue_fingerprint not in expired_fps)


def apply_dispositions(
    findings: tuple[Finding, ...],
    dispositions: tuple[Disposition, ...],
    now: datetime | None = None,
) -> tuple[tuple[Finding, ...], tuple[Finding, ...]]:
    """Return (kept, suppressed). A finding is suppressed iff an ACTIVE disposition
    carries its fingerprint."""
    disposed = {d.issue_fingerprint for d in active_dispositions(dispositions, now)}
    kept = tuple(f for f in findings if f.fingerprint not in disposed)
    suppressed = tuple(f for f in findings if f.fingerprint in disposed)
    return kept, suppressed

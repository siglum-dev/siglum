"""Anchor every policy-relevant input to the protected base. The verdict uses the BASE
version of each anchored path regardless of what head contains; a head that modifies an
anchored path is recorded as an override *attempt* and otherwise ignored.

The head version of each anchored path is read from the trusted forge at the head sha, not
taken from the untrusted gather artifact. The override detection
is a property of base-vs-head content the trusted job reads itself, so a gather that lies
about (or omits) head digests cannot suppress an override."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from siglum.forge.base import ForgeProvider


@dataclass(frozen=True, slots=True)
class AnchoredInputs:
    # sha256 over the sorted (path, base-digest) pairs. This is NOT the policy hash (the
    # canonical parsed-policy hash lives in PolicyRef.policy_hash); it commits to the content
    # of every anchored file as read from the protected base.
    anchored_inputs_hash: str
    anchored_file_digests: tuple[tuple[str, str], ...]  # (path, sha256), sorted, base versions
    head_overrides_detected: tuple[str, ...]          # anchored paths head tried to change


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def anchor_inputs(
    provider: ForgeProvider,
    base_sha: str,
    head_sha: str,
    paths: tuple[str, ...],
) -> AnchoredInputs:
    digests: dict[str, str] = {}
    overrides: list[str] = []
    for path in paths:
        base_content = provider.read_base_file(path, at_sha=base_sha)
        base_digest = _sha256(base_content if base_content is not None else b"")
        digests[path] = base_digest
        # The head version is read from the trusted forge, never trusted from the gather.
        # A non-404 read failure raises ForgeReadError (fail closed). A 404 means the path
        # is absent at head, so a base-present path the head removed is an override.
        head_content = provider.read_head_file(path, at_sha=head_sha)
        head_digest = _sha256(head_content if head_content is not None else b"")
        if head_digest != base_digest:
            overrides.append(path)
    pairs = tuple(sorted(digests.items()))
    anchored_inputs_hash = _sha256(json.dumps(pairs, separators=(",", ":")).encode("utf-8"))
    return AnchoredInputs(
        anchored_inputs_hash=anchored_inputs_hash,
        anchored_file_digests=pairs,
        head_overrides_detected=tuple(sorted(overrides)),
    )

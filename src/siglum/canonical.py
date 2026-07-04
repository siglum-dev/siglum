"""Deterministic canonical JSON and the decision hash.

Canonical form: UTF-8, sorted keys, no insignificant whitespace, no NaN/Infinity.
This is the byte string the hash and (later) the signature cover.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def decision_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()

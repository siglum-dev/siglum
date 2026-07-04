"""DSSE statement bytes, pre-auth encoding, and envelope. Pure.

statement_bytes ties the signed payload to the canonical predicate, so signing can
never change the verdict. dsse_pae is the exact byte string a DSSE signature covers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from siglum.canonical import canonical_json
from siglum.models import Assessment
from siglum.predicate import build_predicate

DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"


def statement_bytes(assessment: Assessment) -> bytes:
    """Canonical bytes of the in-toto Statement, equal to canonical_json(build_predicate)."""
    return canonical_json(build_predicate(assessment))


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding:
    b"DSSEv1 " + len(type) + " " + type + " " + len(payload) + " " + payload."""
    t = payload_type.encode("utf-8")
    return b" ".join(
        [b"DSSEv1", str(len(t)).encode(), t, str(len(payload)).encode(), payload]
    )


@dataclass(frozen=True, slots=True)
class DsseEnvelope:
    payload_type: str
    payload_b64: str
    signatures: tuple[dict[str, str], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "payloadType": self.payload_type,
            "payload": self.payload_b64,
            "signatures": [dict(s) for s in self.signatures],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DsseEnvelope:
        return cls(
            payload_type=str(data["payloadType"]),
            payload_b64=str(data["payload"]),
            signatures=tuple(dict(s) for s in data["signatures"]),
        )

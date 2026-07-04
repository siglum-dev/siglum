"""seal(): recompute the verdict, then keyless-sign the canonical predicate via Sigstore.

The recompute-before-sign guard is real and unit-tested: a forged
Assessment raises before any signing call. The Fulcio/Rekor signing itself is the one
build-time binding to the optional `sigstore` dependency (lazy import). It cannot be
exercised without an OIDC identity provider, so it is marked and integration-gated, never
faked into a passing unit test."""
from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from siglum.canonical import canonical_json
from siglum.models import Assessment
from siglum.predicate import build_predicate
from siglum.sealing.identity import SignerIdentity
from siglum.verify import verify


class SigningUnavailableError(ImportError):
    """The optional `sigstore` extra is not installed."""


class SigningError(RuntimeError):
    """A signing attempt failed."""


@dataclass(frozen=True, slots=True)
class SignedAttestation:
    statement: dict[str, Any]          # the signed in-toto statement (see _signing_statement)
    sigstore_bundle: str               # serialized Sigstore bundle (cert + sig + Rekor proof)
    signer_identity: SignerIdentity    # extracted from the issued cert
    rekor_log_url: str | None          # transparency entry, when logged
    decision_hash: str                 # echo of assessment.decision_hash

    def to_dict(self) -> dict[str, Any]:
        return {
            "statement": self.statement,
            "sigstore_bundle": self.sigstore_bundle,
            "signer_identity": dataclasses.asdict(self.signer_identity),
            "rekor_log_url": self.rekor_log_url,
            "decision_hash": self.decision_hash,
        }


def seal(
    assessment: Assessment,
    *,
    trust: str = "staging",
    run_binding: Mapping[str, Any] | None = None,
) -> SignedAttestation:
    """Recompute (raise on a forged/tampered Assessment) -> build the signing statement
    -> keyless-sign via Fulcio -> log to Rekor -> return a SignedAttestation.

    `run_binding` is the gate's run provenance (gate/binding.binding_payload). It is recorded
    inside the signed predicate so the attestation names the exact run that produced it; it is
    covered by the signature but deliberately not by the decision_hash.

    `trust` is **staging-only**: production signing is deliberately not wired (it publishes
    to a permanent public log), so it must be added by an explicit, reviewed change."""
    verify(assessment)  # recompute-before-sign: AssessmentTampered if the verdict was asserted
    statement = _signing_statement(assessment, run_binding)
    bundle_json, signer_identity, rekor_url = _fulcio_sign_dsse(statement, trust)
    return SignedAttestation(
        statement=statement,
        sigstore_bundle=bundle_json,
        signer_identity=signer_identity,
        rekor_log_url=rekor_url,
        decision_hash=assessment.decision_hash,
    )


def _signing_statement(
    assessment: Assessment, run_binding: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """The in-toto statement we actually sign. Sigstore accepts only SHA-2 subject digests,
    so the subject is bound by the decision_hash (a sha256 that commits to the exact change
    + verdict); the commit identity is preserved in the subject name and the predicate body."""
    pred = build_predicate(assessment)
    body = dict(pred["predicate"])
    if run_binding is not None:
        body["run_binding"] = dict(run_binding)
    change = assessment.bundle.change
    commit = change.merge_candidate_sha or change.head_sha
    return {
        "_type": pred["_type"],
        "subject": [
            {
                "name": f"git+https://github.com/{change.repo}@{commit}",
                "digest": {"sha256": assessment.decision_hash},
            }
        ],
        "predicateType": pred["predicateType"],
        "predicate": body,
    }


def _fulcio_sign_dsse(
    statement: dict[str, Any], trust: str
) -> tuple[str, SignerIdentity, str | None]:  # pragma: no cover
    if trust != "staging":
        raise SigningError("only Sigstore staging is wired; production requires explicit review")
    try:
        from sigstore.dsse import Statement
        from sigstore.models import ClientTrustConfig
        from sigstore.oidc import IdentityToken, detect_credential
        from sigstore.sign import SigningContext
    except ImportError as exc:
        raise SigningUnavailableError(
            "signing requires the optional dependency: pip install siglum[sigstore]"
        ) from exc

    token = detect_credential()
    if token is None:
        raise SigningError("no ambient OIDC credential (run in CI with id-token: write)")
    identity = IdentityToken(token)
    stmt = Statement(canonical_json(statement))
    ctx = SigningContext.from_trust_config(ClientTrustConfig.staging())
    with ctx.signer(identity) as signer:
        bundle = signer.sign_dsse(stmt)
    signer_identity = SignerIdentity(issuer=identity.issuer, subject=identity.identity)
    return bundle.to_json(), signer_identity, _rekor_url(bundle)


def _rekor_url(bundle: Any) -> str | None:  # pragma: no cover
    # The bundle carries a transparency-log entry (Sigstore's verify requires its inclusion
    # proof). This version's entry object is opaque, so we report presence + the staging log
    # rather than fabricating an index we can't reliably read.
    try:
        return "https://search.sigstage.dev (staging Rekor)" if bundle.log_entry else None
    except Exception:
        return None

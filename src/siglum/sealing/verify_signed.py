"""verify_signed(): offline verification, fail-closed.

Two of the checks are pure and fully unit-tested here. They are the security substance that
makes an attestation more than "a signature exists":
  (1) a missing/empty identity policy is REJECTED (Sigstore signs anything);
  (5) the predicate is RECONSTRUCTED into an evidence bundle and the verdict is REDERIVED from
      it (not merely re-hashed). The attestation cannot lie about its own verdict: every
      decision field (verdict, coverage, independence, merge_eligible) and the decision_hash
      must follow from the recorded evidence, exactly as the gate's own verify() requires.
The Sigstore signature/cert/SCT verification (step 2) is the one build-time binding."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import json

from siglum.authority import authority_floor_mismatch, ref_of
from siglum.derive import SCHEMA_VERSION, assess
from siglum.models import (
    Assessment,
    Change,
    EvidenceBundle,
    GateIdentityPolicy,
    PolicyRef,
    ValidatorAuthority,
    ValidatorResult,
)
from siglum.predicate import PREDICATE_TYPE
from siglum.sealing.identity import IdentityMatch, IdentityPolicy, SignerIdentity
from siglum.sealing.seal import SignedAttestation
from siglum.verdict import ValidatorStatus

SUPPORTED_SCHEMA_VERSIONS = frozenset({SCHEMA_VERSION})


class AttestationRejected(Exception):
    """Any fail-closed reason an attestation is not accepted."""


@dataclass(frozen=True, slots=True)
class VerifiedAttestation:
    statement: dict[str, Any]
    signer_identity: SignerIdentity
    identity_match: IdentityMatch
    decision_hash: str


def _obj(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AttestationRejected(f"{what} must be a JSON object")
    return value


def _str(d: dict[str, Any], key: str, what: str) -> str:
    if key not in d:
        raise AttestationRejected(f"{what} is missing {key!r}")
    v = d[key]
    if not isinstance(v, str):
        raise AttestationRejected(f"{what}.{key} must be a string")
    return v


_HEX64 = frozenset("0123456789abcdef")


def _hex64(d: dict[str, Any], key: str, what: str) -> str:
    """A required sha256 hex field. An empty or malformed hash would make the field
    unverifiable while looking present, so it is rejected, not carried through."""
    v = _str(d, key, what)
    if len(v) != 64 or not set(v) <= _HEX64:
        raise AttestationRejected(f"{what}.{key} must be a 64-character sha256 hex digest")
    return v


def _bool(d: dict[str, Any], key: str, what: str) -> bool:
    if key not in d:
        raise AttestationRejected(f"{what} is missing {key!r}")
    v = d[key]
    # isinstance(True, int) is True, but isinstance(0, bool) is False, so this rejects 0/1 ints.
    if not isinstance(v, bool):
        raise AttestationRejected(f"{what}.{key} must be a boolean")
    return v


def _bundle_from_predicate(predicate: dict[str, Any]) -> EvidenceBundle:
    """Reconstruct the evidence bundle from a predicate body so the verdict can be rederived.
    Types are validated strictly (no coercion), so a schema-invalid attestation is rejected
    rather than silently reinterpreted. Only INPUT evidence is read; derived fields are
    recomputed, and the ref is recomputed from workflow_ref so a stated ref is never trusted."""
    change = _obj(predicate.get("change"), "change")
    policy = _obj(predicate.get("policy"), "policy")
    auth = _obj(predicate.get("validator_authority"), "validator_authority")
    raw_validators = predicate.get("validators")
    if not isinstance(raw_validators, list):
        raise AttestationRejected("validators must be a list")
    validators = tuple(
        ValidatorResult(
            id=_str(v, "id", "validator"),
            version=_str(v, "version", "validator"),
            status=ValidatorStatus(_str(v, "status", "validator")),
            required=_bool(v, "required", "validator"),
            artifact_digest=_str(v, "artifact_digest", "validator"),
        )
        for v in (_obj(x, "validator") for x in raw_validators)
    )
    workflow_ref = _str(auth, "workflow_ref", "validator_authority")
    gate = predicate.get("gate_identity")
    if gate is not None:
        gate = _obj(gate, "gate_identity")
        raw_refs = gate.get("protected_refs")
        if not isinstance(raw_refs, list) or not all(isinstance(r, str) for r in raw_refs):
            raise AttestationRejected("gate_identity.protected_refs must be a list of strings")
    mcs = change.get("merge_candidate_sha")
    if mcs is not None and not isinstance(mcs, str):
        raise AttestationRejected("change.merge_candidate_sha must be a string or null")
    return EvidenceBundle(
        change=Change(
            repo=_str(change, "repo", "change"),
            base_sha=_str(change, "base_sha", "change"),
            head_sha=_str(change, "head_sha", "change"),
            merge_base=_str(change, "merge_base", "change"),
            merge_candidate_sha=mcs,
        ),
        policy=PolicyRef(
            policy_id=_str(policy, "policy_id", "policy"),
            policy_hash=_hex64(policy, "policy_hash", "policy"),
            independence_required=_bool(policy, "independence_required", "policy"),
            anchored_inputs_hash=_hex64(policy, "anchored_inputs_hash", "policy"),
        ),
        validators=validators,
        validator_authority=ValidatorAuthority(
            repository=_str(auth, "repository", "validator_authority"),
            repository_id=_str(auth, "repository_id", "validator_authority"),
            workflow_ref=workflow_ref,
            ref=ref_of(workflow_ref),  # derived, never trusted from the predicate
            runner_class=_str(auth, "runner_class", "validator_authority"),
        ),
        change_author=_str(predicate, "change_author", "predicate"),
        gate_identity=(
            GateIdentityPolicy(
                repository=_str(gate, "repository", "gate_identity"),
                workflow_path=_str(gate, "workflow_path", "gate_identity"),
                protected_refs=tuple(gate["protected_refs"]),
                repository_id=_str(gate, "repository_id", "gate_identity"),
            )
            if gate is not None
            else None
        ),
    )


def rederive(predicate: dict[str, Any]) -> Assessment:
    schema_version = predicate.get("schema_version")
    if not isinstance(schema_version, str) or schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise AttestationRejected(f"unsupported schema_version {schema_version!r}")
    try:
        bundle = _bundle_from_predicate(predicate)
    except (KeyError, TypeError, ValueError) as exc:
        raise AttestationRejected(f"predicate is not a reconstructable bundle: {exc}") from exc
    # Replay the gate's unconditional authority floor, bound to the ATTESTED repo, so offline
    # verification refuses any authority state the runtime gate would have refused (e.g. a
    # self-hosted runner, or an authority for a different repository than the change).
    floor = authority_floor_mismatch(bundle.validator_authority, bundle.change.repo)
    if floor is not None:
        raise AttestationRejected(f"attestation authority is not a legitimate gate run: {floor}")
    return assess(bundle, schema_version=schema_version)


def recompute_decision_hash(predicate: dict[str, Any]) -> str:
    """The decision hash rederived from the predicate's recorded evidence."""
    return rederive(predicate).decision_hash


def check_decision_integrity(predicate: dict[str, Any]) -> None:
    fresh = rederive(predicate)
    # Type the stated decision fields strictly before comparing, so a JSON int 1 cannot pass as
    # boolean True (and similar coercion equivalences) for the merge-unblocking fields.
    for name in ("decision_hash", "verdict", "coverage", "independence"):
        if not isinstance(predicate.get(name), str):
            raise AttestationRejected(f"predicate {name} must be a string")
    if not isinstance(predicate.get("merge_eligible"), bool):
        raise AttestationRejected("predicate merge_eligible must be a boolean")
    for name, stated, got in (
        ("decision_hash", predicate.get("decision_hash"), fresh.decision_hash),
        ("verdict", predicate.get("verdict"), fresh.verdict.value),
        ("coverage", predicate.get("coverage"), fresh.coverage.value),
        ("independence", predicate.get("independence"), fresh.independence.value),
        ("merge_eligible", predicate.get("merge_eligible"), fresh.merge_eligible),
    ):
        if stated != got:
            raise AttestationRejected(
                f"predicate {name} does not rederive (stated={stated!r}, rederived={got!r})"
            )
    _check_run_binding(predicate)


def _check_run_binding(predicate: dict[str, Any]) -> None:
    """A recorded run binding is provenance (not part of the decision hash), but it must not
    contradict the attested evidence: its SHAs, anchored hash, and validator pins must equal
    the fields the decision hash commits to, so the two views of one attestation cannot
    diverge."""
    raw = predicate.get("run_binding")
    if raw is None:
        return
    binding = _obj(raw, "run_binding")
    # A present binding must actually carry the run provenance it exists to record; a
    # binding with hollow provenance fields would look like accountability without being any.
    for key in ("run_id", "run_attempt", "workflow_path", "workflow_ref_sha", "event_name"):
        if not _str(binding, key, "run_binding"):
            raise AttestationRejected(f"run_binding.{key} must be a non-empty string")
    change = _obj(predicate.get("change"), "change")
    policy = _obj(predicate.get("policy"), "policy")
    for key in ("head_sha", "base_sha", "merge_base", "merge_candidate_sha"):
        if binding.get(key) != change.get(key):
            raise AttestationRejected(
                f"run_binding.{key} does not match the attested change "
                f"({binding.get(key)!r} != {change.get(key)!r})"
            )
    if binding.get("anchored_inputs_hash") != policy.get("anchored_inputs_hash"):
        raise AttestationRejected(
            "run_binding.anchored_inputs_hash does not match the attested policy"
        )
    validators = predicate.get("validators")
    rows = [v for v in validators if isinstance(v, dict)] if isinstance(validators, list) else []

    def _pairs(value: Any, what: str) -> list[list[str]]:
        if not isinstance(value, list) or not all(
            isinstance(p, list) and len(p) == 2 and all(isinstance(s, str) for s in p)
            for p in value
        ):
            raise AttestationRejected(f"run_binding.{what} must be a list of [id, value] pairs")
        return sorted(value)

    expected_versions = sorted([str(v.get("id")), str(v.get("version"))] for v in rows)
    expected_digests = sorted([str(v.get("id")), str(v.get("artifact_digest"))] for v in rows)
    if _pairs(binding.get("validator_versions"), "validator_versions") != expected_versions:
        raise AttestationRejected(
            "run_binding.validator_versions does not match the attested validators"
        )
    if _pairs(binding.get("artifact_digests"), "artifact_digests") != expected_digests:
        raise AttestationRejected(
            "run_binding.artifact_digests does not match the attested validators"
        )


def _require_siglum_statement(statement: dict[str, Any]) -> None:
    if statement.get("predicateType") != PREDICATE_TYPE:
        raise AttestationRejected("not a Siglum validation attestation")
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict) or "decision_hash" not in predicate:
        raise AttestationRejected("malformed predicate")


def _require_subject_binds_decision(statement: dict[str, Any]) -> None:
    """The signed subject digest and the predicate's decision hash are two views of one
    decision (cosign consumers verify by subject; Siglum verifies by predicate). They must
    be provably the same value, or the two audiences would be looking at different facts."""
    subject = statement.get("subject")
    if not isinstance(subject, list) or len(subject) != 1 or not isinstance(subject[0], dict):
        raise AttestationRejected("statement subject must be a single entry")
    digest = subject[0].get("digest")
    sha = digest.get("sha256") if isinstance(digest, dict) else None
    predicate = statement.get("predicate")
    stated = predicate.get("decision_hash") if isinstance(predicate, dict) else None
    if not isinstance(sha, str) or sha != stated:
        raise AttestationRejected(
            "statement subject digest does not bind the predicate's decision hash"
        )


def verify_signed(
    att: SignedAttestation | dict[str, Any],
    *,
    identity_policy: IdentityPolicy | None,
    trust: str = "staging",
) -> VerifiedAttestation:
    """Verify a SignedAttestation (or its dict form): extract the bundle and verify it."""
    bundle_json = (
        att.sigstore_bundle if isinstance(att, SignedAttestation) else att["sigstore_bundle"]
    )
    return verify_signed_bundle(bundle_json, identity_policy=identity_policy, trust=trust)


def verify_signed_bundle(
    bundle_json: str,
    *,
    identity_policy: IdentityPolicy | None,
    trust: str = "staging",
) -> VerifiedAttestation:
    """Offline-ish verification against Sigstore staging + our own invariants.

    (1) missing/empty identity policy -> reject (a valid signature is NOT sufficient).
    (2) Sigstore verifies the signature, cert chain, transparency-log entry, AND the
        identity policy in one call (verify_dsse raises on any failure).
    (5) we reconstruct the verified payload into an evidence bundle and rederive the verdict;
        every decision field must follow from the evidence, so the attestation cannot lie."""
    # (1) is pure and unit-tested, as is the policy-translatability validation.
    if identity_policy is None or not identity_policy.issuers:
        raise AttestationRejected("no identity policy provided (fail closed)")
    _validate_identity_policy(identity_policy)
    if trust != "staging":
        raise AttestationRejected("only Sigstore staging is wired")

    try:
        from sigstore.models import Bundle
        from sigstore.verify import Verifier
    except ImportError as exc:
        raise AttestationRejected("verification requires: pip install siglum[sigstore]") from exc

    # (2) signature + cert + Rekor + identity policy
    bundle = Bundle.from_json(bundle_json)
    _, payload = Verifier.staging().verify_dsse(bundle, _sigstore_policy(identity_policy))
    statement = json.loads(payload)

    # (5) our invariants on the *verified* payload
    _require_siglum_statement(statement)
    _require_subject_binds_decision(statement)
    check_decision_integrity(statement["predicate"])

    signer = _bundle_signer_identity(bundle, identity_policy)
    match = IdentityMatch(True, identity_policy.policy_id, signer, "verified by sigstore verify_dsse")
    return VerifiedAttestation(
        statement=statement,
        signer_identity=signer,
        identity_match=match,
        decision_hash=statement["predicate"]["decision_hash"],
    )


def _validate_identity_policy(identity_policy: IdentityPolicy) -> None:
    """Sigstore's policy classes are EXACT matchers composed with AllOf. Anything this
    translation cannot express is rejected loudly, never silently narrowed or dropped: a
    policy that looks stricter than what is actually enforced is a fail-open in disguise."""
    if len(identity_policy.issuers) != 1:
        raise AttestationRejected(
            "signed-bundle verification supports exactly one issuer; split the policy if "
            "you need to accept more than one"
        )
    values = [("repository", p) for p in identity_policy.repository_patterns]
    values += [("subject", p) for p in identity_policy.subject_patterns]
    for what, value in values:
        if any(ch in value for ch in "*?["):
            raise AttestationRejected(
                f"identity policy {what} {value!r} contains pattern characters, but "
                "signed-bundle verification matches exactly; use the exact value"
            )
    if len(identity_policy.repository_patterns) > 1:
        raise AttestationRejected(
            "signed-bundle verification supports at most one repository pin"
        )


def _sigstore_policy(identity_policy: IdentityPolicy) -> Any:
    from sigstore.verify.policy import (
        AllOf,
        AnyOf,
        GitHubWorkflowRepository,
        Identity,
        OIDCIssuer,
        OIDCRunnerEnvironment,
    )

    _validate_identity_policy(identity_policy)
    issuer = identity_policy.issuers[0]
    clauses: list[Any] = [OIDCIssuer(issuer)]
    if identity_policy.repository_patterns:
        clauses.append(GitHubWorkflowRepository(identity_policy.repository_patterns[0]))
    # subject_patterns pin the exact signer SAN(s) (the org-pinned workflow identity). All
    # clauses apply, so the signer must be the pinned workflow AND in the repository. Multiple
    # protected refs become AnyOf so any one pinned ref matches.
    if identity_policy.subject_patterns:
        idents: list[Any] = [Identity(identity=s, issuer=issuer) for s in identity_policy.subject_patterns]
        clauses.append(idents[0] if len(idents) == 1 else AnyOf(idents))
    # Every field the policy carries is enforced; require_runner_environment maps to the
    # Fulcio runner-environment extension.
    if identity_policy.require_runner_environment is not None:
        clauses.append(OIDCRunnerEnvironment(identity_policy.require_runner_environment))
    return AllOf(clauses)


def _bundle_signer_identity(bundle: Any, identity_policy: IdentityPolicy) -> SignerIdentity:
    """The signer identity as recorded in the bundle's Fulcio certificate, for the audit
    trail. Extraction only; verify_dsse already enforced the policy. If the certificate
    cannot be read, say so instead of fabricating an identity."""
    try:
        return signer_identity_from_cert(bundle.signing_certificate)
    except Exception:
        return SignerIdentity(
            issuer=identity_policy.issuers[0], subject="(certificate identity unavailable)"
        )


def signer_identity_from_cert(cert: Any) -> SignerIdentity:
    """SAN URI + Fulcio issuer extension from a signing certificate."""
    from cryptography import x509

    subject = ""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
        if uris:
            subject = uris[0]
    except x509.ExtensionNotFound:
        pass
    return SignerIdentity(issuer=_fulcio_issuer(cert), subject=subject)


def _fulcio_issuer(cert: Any) -> str:
    """The OIDC issuer from the Fulcio cert: the v2 extension (1.3.6.1.4.1.57264.1.8, a DER
    UTF8String) with fallback to the deprecated v1 raw-bytes extension (…1.1)."""
    from cryptography import x509

    for oid, der in (("1.3.6.1.4.1.57264.1.8", True), ("1.3.6.1.4.1.57264.1.1", False)):
        try:
            ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(oid))
        except x509.ExtensionNotFound:
            continue
        raw = ext.value.value if isinstance(ext.value, x509.UnrecognizedExtension) else b""
        return _der_utf8(raw) if der else raw.decode("utf-8", "replace")
    return ""


def _der_utf8(data: bytes) -> str:
    """Decode a DER-encoded UTF8String (short form only; Fulcio issuer values are short)."""
    if len(data) >= 2 and data[0] == 0x0C and data[1] < 0x80 and len(data) == 2 + data[1]:
        return data[2:].decode("utf-8", "replace")
    return data.decode("utf-8", "replace")

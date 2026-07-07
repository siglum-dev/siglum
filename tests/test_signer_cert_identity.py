"""The signer identity recorded in VerifiedAttestation comes from the Fulcio certificate,
not from the policy that happened to match. Certs here are synthetic, built in memory."""
from __future__ import annotations

import datetime
import importlib.util

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from siglum.sealing.verify_signed import _der_utf8, signer_identity_from_cert

_SAN = "https://github.com/o/r/.github/workflows/siglum-seal-enforce.yml@refs/heads/main"
_ISSUER = "https://token.actions.githubusercontent.com"
_V2 = "1.3.6.1.4.1.57264.1.8"
_V1 = "1.3.6.1.4.1.57264.1.1"


def _der_utf8_bytes(value: str) -> bytes:
    raw = value.encode("utf-8")
    assert len(raw) < 128
    return b"\x0c" + bytes([len(raw)]) + raw


def _cert(extensions: list[tuple[str, bytes]], san: str | None = _SAN) -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sigstore-intermediate")])
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(minutes=10))
    )
    if san is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san)]), critical=False
        )
    for oid, value in extensions:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), value), critical=False
        )
    return builder.sign(key, hashes.SHA256())


def test_san_and_v2_issuer_are_extracted():
    cert = _cert([(_V2, _der_utf8_bytes(_ISSUER))])
    identity = signer_identity_from_cert(cert)
    assert identity.subject == _SAN
    assert identity.issuer == _ISSUER


def test_v1_issuer_fallback_is_raw_bytes():
    cert = _cert([(_V1, _ISSUER.encode("utf-8"))])
    assert signer_identity_from_cert(cert).issuer == _ISSUER


def test_missing_extensions_yield_empty_fields_not_errors():
    identity = signer_identity_from_cert(_cert([], san=None))
    assert identity.subject == "" and identity.issuer == ""


def test_der_utf8_short_form_and_fallback():
    assert _der_utf8(_der_utf8_bytes("hello")) == "hello"
    assert _der_utf8(b"raw-bytes") == "raw-bytes"


@pytest.mark.skipif(importlib.util.find_spec("sigstore") is None, reason="needs sigstore")
def test_runner_environment_policy_clause_is_built():
    # require_runner_environment used to be silently dropped by the sigstore translation;
    # it must now become a real OIDCRunnerEnvironment clause inside the AllOf.
    from sigstore.verify.policy import OIDCRunnerEnvironment

    from siglum.sealing.identity import IdentityPolicy
    from siglum.sealing.verify_signed import _sigstore_policy

    policy = _sigstore_policy(IdentityPolicy(
        policy_id="p", issuers=(_ISSUER,), require_runner_environment="github-hosted",
    ))
    clauses = policy._children if hasattr(policy, "_children") else policy._policies
    assert any(isinstance(c, OIDCRunnerEnvironment) for c in clauses)

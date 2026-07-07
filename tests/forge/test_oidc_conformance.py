"""Adversarial conformance for OIDC token verification.

verify_token does ALL cryptographic verification so a provider can never weaken a check.
These tests mint fixture JWTs with a throwaway RSA key and assert the fail-closed
invariants: a valid token is accepted, and alg:none, RS/HS confusion, wrong issuer,
wrong audience, expiry, a signature from a different key, an unknown kid, and a malformed
token are all rejected.
"""
import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from siglum.forge.oidc import TokenSpec, TokenVerifyError, fetch_jwks, verify_token

SPEC = TokenSpec(
    issuer="https://token.actions.githubusercontent.com",
    audience="siglum",
    jwks_uri="https://token.actions.githubusercontent.com/.well-known/jwks",
)


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _int_bytes(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


class _Signer:
    """A throwaway RSA signer for minting fixture JWTs."""

    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def jwk(self, kid: str = "k1") -> dict[str, str]:
        nums = self.key.public_key().public_numbers()
        return {"kty": "RSA", "kid": kid, "alg": "RS256",
                "n": _b64u(_int_bytes(nums.n)), "e": _b64u(_int_bytes(nums.e))}

    def mint(self, payload: dict[str, object], *, alg: str = "RS256", kid: str = "k1") -> str:
        header = _b64u(json.dumps({"alg": alg, "kid": kid, "typ": "JWT"}).encode())
        body = _b64u(json.dumps(payload).encode())
        signing_input = f"{header}.{body}".encode("ascii")
        if alg == "none":
            sig = b"unused"   # non-empty: forces verify_token to reach the alg pin, not _split
        elif alg == "HS256":
            # RS/HS confusion: attacker HMACs using the public modulus as the shared secret.
            secret = _int_bytes(self.key.public_key().public_numbers().n)
            sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
        else:
            sig = self.key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return f"{header}.{body}.{_b64u(sig)}"


def _payload(*, moment=None, exp_delta=3600, iss=SPEC.issuer, aud=SPEC.audience) -> dict[str, object]:
    t = int((moment or datetime.now(UTC)).timestamp())
    return {
        "iss": iss, "aud": aud, "sub": "repo:o/r:ref:refs/heads/main",
        "repository": "o/r", "job_workflow_ref": "o/r/.github/workflows/seal.yml@refs/heads/main",
        "actor": "alice", "runner_environment": "github-hosted", "iat": t, "exp": t + exp_delta,
    }


def test_a_valid_token_is_accepted_and_claims_returned():
    s = _Signer()
    claims = verify_token(s.mint(_payload()), SPEC, jwks=[s.jwk()])
    assert claims["repository"] == "o/r"
    assert claims["actor"] == "alice"
    assert str(claims["job_workflow_ref"]).endswith("seal.yml@refs/heads/main")


def test_alg_none_is_rejected():
    s = _Signer()
    with pytest.raises(TokenVerifyError):
        verify_token(s.mint(_payload(), alg="none"), SPEC, jwks=[s.jwk()])


def test_rs_hs_confusion_is_rejected():
    s = _Signer()
    with pytest.raises(TokenVerifyError):
        verify_token(s.mint(_payload(), alg="HS256"), SPEC, jwks=[s.jwk()])


def test_wrong_issuer_is_rejected():
    s = _Signer()
    with pytest.raises(TokenVerifyError):
        verify_token(s.mint(_payload(iss="https://attacker.example")), SPEC, jwks=[s.jwk()])


def test_wrong_audience_is_rejected():
    s = _Signer()
    with pytest.raises(TokenVerifyError):
        verify_token(s.mint(_payload(aud="not-siglum")), SPEC, jwks=[s.jwk()])


def test_expired_token_is_rejected():
    s = _Signer()
    old = datetime.now(UTC) - timedelta(hours=2)
    with pytest.raises(TokenVerifyError):
        verify_token(s.mint(_payload(moment=old, exp_delta=60)), SPEC, jwks=[s.jwk()])


def test_a_signature_from_a_different_key_is_rejected():
    signer, attacker = _Signer(), _Signer()
    with pytest.raises(TokenVerifyError):
        verify_token(signer.mint(_payload()), SPEC, jwks=[attacker.jwk()])


def test_an_unknown_kid_is_rejected():
    s = _Signer()
    with pytest.raises(TokenVerifyError):
        verify_token(s.mint(_payload(), kid="other"), SPEC, jwks=[s.jwk()])


def test_a_malformed_token_is_rejected():
    s = _Signer()
    with pytest.raises(TokenVerifyError):
        verify_token("not.a.jwt.x", SPEC, jwks=[s.jwk()])


def test_a_non_base64_header_is_rejected_as_a_verify_error():
    s = _Signer()
    with pytest.raises(TokenVerifyError):
        verify_token("!!!.eyJhIjoxfQ.sig", SPEC, jwks=[s.jwk()])


def test_a_payload_that_is_not_a_json_object_is_rejected():
    # A validly-signed token whose payload is a JSON array, not an object.
    s = _Signer()
    token = s.mint([1, 2, 3])  # type: ignore[arg-type]
    with pytest.raises(TokenVerifyError):
        verify_token(token, SPEC, jwks=[s.jwk()])


def test_jwks_ssrf_guard_rejects_non_https():
    with pytest.raises(TokenVerifyError):
        fetch_jwks("http://token.actions.githubusercontent.com/jwks", issuer=SPEC.issuer)


def test_jwks_ssrf_guard_rejects_a_host_that_is_not_the_issuer():
    with pytest.raises(TokenVerifyError):
        fetch_jwks("https://attacker.example/jwks", issuer=SPEC.issuer)

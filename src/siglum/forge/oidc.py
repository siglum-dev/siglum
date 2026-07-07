"""Forge-neutral OIDC token verification. The core owns ALL cryptographic verification and
claim extraction so a provider can never weaken a check. Built for GitHub Actions first; a
second forge is a different TokenSpec, not a different verifier.

Rules enforced, in order, before any claim is trusted:
  1. Algorithm pinning: `alg` must be in `spec.algorithms` and never `none`. The key type is
     fixed to RSA in code (never chosen from the token header), so RS/HS confusion is
     impossible.
  2. Signature: RS256 over the signing input, against a JWKS key selected by `kid`.
  3. Issuer and audience are pinned exactly.
  4. exp/nbf/iat are checked with bounded skew.

`cryptography` is imported lazily inside the verify helpers, so this module imports without
the optional extra; verification then requires it.
"""
from __future__ import annotations

import base64
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

_SKEW = timedelta(minutes=5)


class TokenVerifyError(Exception):
    """An OIDC token failed verification. The gate fails closed on this."""


@dataclass(frozen=True, slots=True)
class TokenSpec:
    issuer: str
    audience: str
    jwks_uri: str
    algorithms: tuple[str, ...] = ("RS256",)

    def __post_init__(self) -> None:
        for name in ("issuer", "audience", "jwks_uri"):
            if not getattr(self, name):
                raise ValueError(f"TokenSpec.{name} must be non-empty")
        if not self.jwks_uri.startswith("https://"):
            raise ValueError("TokenSpec.jwks_uri must be https")
        if not self.algorithms or any(a.lower() == "none" for a in self.algorithms):
            raise ValueError("TokenSpec.algorithms must be non-empty and never 'none'")


def github_actions_spec(audience: str) -> TokenSpec:
    issuer = "https://token.actions.githubusercontent.com"
    return TokenSpec(issuer=issuer, audience=audience,
                     jwks_uri=f"{issuer}/.well-known/jwks", algorithms=("RS256",))


def verify_token(
    token: str,
    spec: TokenSpec,
    *,
    jwks: Sequence[Mapping[str, Any]],
    now: datetime | None = None,
) -> dict[str, object]:
    moment = now or datetime.now(UTC)
    header_b64, payload_b64, sig_b64 = _split(token)

    header = _segment(header_b64, "header")
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in spec.algorithms:
        raise TokenVerifyError(f"token alg {alg!r} is not in the pinned algorithms")
    if alg != "RS256":
        raise TokenVerifyError(f"alg {alg!r} is pinned but not implemented")

    key = _rsa_public_key(_select_jwk(jwks, header.get("kid")))
    _verify_rs256(f"{header_b64}.{payload_b64}".encode("ascii"), _b64d(sig_b64), key)

    payload = _segment(payload_b64, "payload")
    if payload.get("iss") != spec.issuer:
        raise TokenVerifyError("token issuer does not match the pinned issuer")
    _check_audience(payload, spec.audience)
    _check_temporal(payload, moment)
    return dict(payload)


def fetch_jwks(jwks_uri: str, *, issuer: str, http_get: Any | None = None) -> list[dict[str, Any]]:
    """Fetch a forge JWKS, enforcing the SSRF guard. The network call is the seam."""
    _assert_jwks_allowed(jwks_uri, issuer)
    body = (http_get or _https_get_no_redirect)(jwks_uri)
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise TokenVerifyError("JWKS response is not JSON") from exc
    keys = data.get("keys") if isinstance(data, dict) else None
    if not isinstance(keys, list) or not keys:
        raise TokenVerifyError("JWKS response has no keys")
    return [k for k in keys if isinstance(k, dict)]


# --- internals ---------------------------------------------------------------


def _split(token: str) -> tuple[str, str, str]:
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise TokenVerifyError("token is not a well-formed JWT")
    return parts[0], parts[1], parts[2]


def _b64d(segment: str) -> bytes:
    try:
        # binascii.Error (raised on bad base64) is a ValueError subclass.
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except ValueError as exc:
        raise TokenVerifyError("token segment is not valid base64url") from exc


def _segment(segment: str, name: str) -> dict[str, Any]:
    try:
        # ValueError covers both JSONDecodeError and a non-UTF-8 segment (UnicodeDecodeError).
        decoded = json.loads(_b64d(segment))
    except ValueError as exc:
        raise TokenVerifyError(f"token {name} is not valid JSON") from exc
    if not isinstance(decoded, dict):
        raise TokenVerifyError(f"token {name} must be a JSON object")
    return decoded


def _select_jwk(jwks: Sequence[Mapping[str, Any]], kid: Any) -> Mapping[str, Any]:
    candidates = [k for k in jwks if kid is None or k.get("kid") == kid]
    if len(candidates) != 1:
        raise TokenVerifyError(f"expected exactly one JWKS key for kid={kid!r}, found {len(candidates)}")
    return candidates[0]


def _rsa_public_key(jwk: Mapping[str, Any]) -> Any:
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError as exc:  # pragma: no cover
        raise TokenVerifyError("OIDC verification requires the 'cryptography' extra") from exc
    if jwk.get("kty") != "RSA":
        raise TokenVerifyError(f"unsupported JWK kty {jwk.get('kty')!r}")
    try:
        modulus = int.from_bytes(_b64d(jwk["n"]), "big")
        exponent = int.from_bytes(_b64d(jwk["e"]), "big")
        return rsa.RSAPublicNumbers(exponent, modulus).public_key()
    except (KeyError, TypeError, ValueError) as exc:
        raise TokenVerifyError("malformed RSA JWK") from exc


def _verify_rs256(signing_input: bytes, signature: bytes, key: Any) -> None:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError as exc:  # pragma: no cover
        raise TokenVerifyError("OIDC verification requires the 'cryptography' extra") from exc
    try:
        key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise TokenVerifyError("token signature is invalid") from exc


def _check_audience(payload: Mapping[str, Any], audience: str) -> None:
    aud = payload.get("aud")
    if isinstance(aud, list):
        if len(aud) != 1 or aud[0] != audience:
            raise TokenVerifyError("token audience does not match the pinned audience")
        return
    if aud != audience:
        raise TokenVerifyError(f"token audience {aud!r} does not match the pinned audience")


def _check_temporal(payload: Mapping[str, Any], now: datetime) -> None:
    exp = _int_claim(payload, "exp", required=True)
    assert exp is not None
    if datetime.fromtimestamp(exp, UTC) + _SKEW < now:
        raise TokenVerifyError("token is expired")
    nbf = _int_claim(payload, "nbf", required=False)
    if nbf is not None and datetime.fromtimestamp(nbf, UTC) - _SKEW > now:
        raise TokenVerifyError("token is not yet valid (nbf)")
    iat = _int_claim(payload, "iat", required=False)
    if iat is not None and datetime.fromtimestamp(iat, UTC) - _SKEW > now:
        raise TokenVerifyError("token was issued in the future (iat)")


def _int_claim(payload: Mapping[str, Any], key: str, *, required: bool) -> int | None:
    value = payload.get(key)
    if value is None:
        if required:
            raise TokenVerifyError(f"token is missing required claim {key!r}")
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise TokenVerifyError(f"token claim {key!r} must be an integer")
    return value


def _assert_jwks_allowed(jwks_uri: str, issuer: str) -> None:
    parsed = urlparse(jwks_uri)
    if parsed.scheme != "https":
        raise TokenVerifyError("JWKS URI must be https")
    if not parsed.hostname or parsed.hostname != urlparse(issuer).hostname:
        raise TokenVerifyError("JWKS host must match the issuer host")


def _https_get_no_redirect(url: str) -> str:  # pragma: no cover
    import ipaddress
    import socket
    import urllib.error
    import urllib.request

    host = urlparse(url).hostname or ""
    for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP):
        addr = ipaddress.ip_address(str(info[4][0]))
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            raise TokenVerifyError(f"JWKS host {host!r} resolves to a non-public address")

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a: Any, **k: Any) -> Any:
            raise TokenVerifyError("JWKS request was unexpectedly redirected")

    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(url, timeout=30) as resp:
            raw: bytes = resp.read()
            return raw.decode("utf-8")
    except urllib.error.URLError as exc:
        raise TokenVerifyError(f"JWKS request failed: {exc}") from exc

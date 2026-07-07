"""GitHub App authentication helpers.

Sealed enforcement should post the authoritative `siglum` check as a GitHub App that a
ruleset can source-restrict. This module is deliberately small: pure JWT construction plus
the one network call that exchanges the JWT for an installation token.
"""
from __future__ import annotations

import base64
import json
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_API = "https://api.github.com"


class GitHubAppAuthError(RuntimeError):
    """GitHub App credentials are missing, malformed, or rejected."""


@dataclass(frozen=True, slots=True)
class GitHubAppCredentials:
    app_id: str
    installation_id: str
    private_key_pem: str


def credentials_from_env(env: dict[str, str]) -> GitHubAppCredentials | None:
    """The Sealed App credentials, or None for the Standard tier (no App env at all). PARTIAL
    App credentials fail closed: the operator intended Sealed but misconfigured, and silently
    degrading to GITHUB_TOKEN would post a check that cannot be source-restricted to the App."""
    app_id = env.get("SIGLUM_GITHUB_APP_ID") or env.get("GITHUB_APP_ID")
    installation_id = (
        env.get("SIGLUM_GITHUB_APP_INSTALLATION_ID") or env.get("GITHUB_APP_INSTALLATION_ID")
    )
    private_key = env.get("SIGLUM_GITHUB_APP_PRIVATE_KEY") or env.get("GITHUB_APP_PRIVATE_KEY")
    key_path = env.get("SIGLUM_GITHUB_APP_PRIVATE_KEY_PATH") or env.get(
        "GITHUB_APP_PRIVATE_KEY_PATH"
    )
    have = {"app id": bool(app_id), "installation id": bool(installation_id),
            "private key": bool(private_key or key_path)}
    if not any(have.values()):
        return None
    if not all(have.values()):
        missing = ", ".join(name for name, ok in have.items() if not ok)
        raise GitHubAppAuthError(
            f"partial GitHub App credentials; missing: {missing} (set all of them, or none)"
        )
    if key_path:
        private_key = Path(key_path).read_text(encoding="utf-8")
    assert app_id is not None and installation_id is not None and private_key is not None
    return GitHubAppCredentials(
        app_id=app_id,
        installation_id=installation_id,
        private_key_pem=private_key.replace("\\n", "\n"),
    )


def create_app_jwt(creds: GitHubAppCredentials, *, now: int | None = None) -> str:
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError as exc:  # pragma: no cover
        raise GitHubAppAuthError(
            "GitHub App auth requires the optional dependency: pip install siglum[github-app]"
        ) from exc

    issued_at = int(time.time() if now is None else now) - 60
    expires_at = issued_at + 9 * 60
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"iat": issued_at, "exp": expires_at, "iss": creds.app_id}
    signing_input = (
        _base64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        + "."
        + _base64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    )
    key = serialization.load_pem_private_key(creds.private_key_pem.encode("utf-8"), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise GitHubAppAuthError("GitHub App private key must be an RSA key")
    signature = key.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return signing_input + "." + _base64url(signature)


def create_installation_token(creds: GitHubAppCredentials) -> str:  # pragma: no cover
    jwt = create_app_jwt(creds)
    req = urllib.request.Request(
        f"{_API}/app/installations/{creds.installation_id}/access_tokens",
        data=b"{}",
        method="POST",
        headers={
            "Authorization": f"Bearer {jwt}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "siglum-github-app",
        },
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        payload: Any = json.loads(resp.read().decode("utf-8"))
    token = payload.get("token") if isinstance(payload, dict) else None
    if not isinstance(token, str) or not token:
        raise GitHubAppAuthError("GitHub App installation token response did not include token")
    return token


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

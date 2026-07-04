import base64
import json
from typing import cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import pytest

from siglum.forge.github_app import (
    GitHubAppAuthError,
    GitHubAppCredentials,
    create_app_jwt,
    credentials_from_env,
)


def _pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def _decode_segment(segment: str) -> dict[str, object]:
    padding = "=" * (-len(segment) % 4)
    payload = json.loads(base64.urlsafe_b64decode(segment + padding))
    assert isinstance(payload, dict)
    return cast(dict[str, object], payload)


def test_credentials_from_env_accepts_escaped_pem():
    pem = _pem()
    creds = credentials_from_env(
        {
            "SIGLUM_GITHUB_APP_ID": "123",
            "SIGLUM_GITHUB_APP_INSTALLATION_ID": "456",
            "SIGLUM_GITHUB_APP_PRIVATE_KEY": pem.replace("\n", "\\n"),
        }
    )
    assert creds is not None
    assert creds.app_id == "123"
    assert "BEGIN PRIVATE KEY" in creds.private_key_pem


def test_no_app_env_is_standard_tier_not_an_error():
    assert credentials_from_env({}) is None


def test_partial_app_credentials_fail_closed():
    # The operator intended Sealed but misconfigured. Fail closed instead of silently degrading
    # to GITHUB_TOKEN, which cannot post the source-restricted check.
    with pytest.raises(GitHubAppAuthError, match="partial"):
        credentials_from_env({"SIGLUM_GITHUB_APP_ID": "123"})


def test_create_app_jwt_sets_expected_claims():
    token = create_app_jwt(
        GitHubAppCredentials(app_id="123", installation_id="456", private_key_pem=_pem()),
        now=1_700_000_000,
    )
    header, payload, signature = token.split(".")
    assert _decode_segment(header)["alg"] == "RS256"
    claims = _decode_segment(payload)
    assert claims["iss"] == "123"
    assert claims["iat"] == 1_699_999_940
    assert claims["exp"] == 1_700_000_480
    assert signature

"""Phase B proof: exercise the real seal() + verify_signed_bundle() against Sigstore
**STAGING**, end to end. STAGING ONLY: seal() refuses production. Runs in GitHub Actions,
where the ambient OIDC identity lives (`id-token: write`)."""
from __future__ import annotations

import os

from siglum.derive import assess
from siglum.models import (
    Assessment,
    Change,
    EvidenceBundle,
    PolicyRef,
    ValidatorAuthority,
    ValidatorResult,
)
from siglum.sealing.identity import IdentityPolicy
from siglum.sealing.seal import seal
from siglum.sealing.verify_signed import verify_signed_bundle
from siglum.verdict import ValidatorStatus

_GH_OIDC_ISSUER = "https://token.actions.githubusercontent.com"


def _sample_assessment() -> Assessment:
    bundle = EvidenceBundle(
        change=Change(
            repo=os.environ.get("GITHUB_REPOSITORY", "ostinato-forge/siglum-fixture"),
            base_sha="0" * 40, head_sha=os.environ.get("GITHUB_SHA", "a" * 40), merge_base="0" * 40,
        ),
        policy=PolicyRef("default", "0" * 64, independence_required=False),
        validators=(
            ValidatorResult("secret-scan", "0", ValidatorStatus.PASSED, True, "sha256:" + "0" * 64),
        ),
        validator_authority=ValidatorAuthority(
            repository=os.environ.get("GITHUB_REPOSITORY", "ostinato-forge/siglum-fixture"),
            repository_id="0",
            workflow_ref=os.environ.get("GITHUB_REPOSITORY", "ostinato-forge/siglum-fixture")
            + "/.github/workflows/siglum-seal-enforce.yml@refs/heads/main",
            ref="refs/heads/main", runner_class="github-hosted",
        ),
        change_author="tempo-64",
    )
    return assess(bundle)


def main() -> int:
    repo = os.environ.get("GITHUB_REPOSITORY", "ostinato-forge/siglum-fixture")
    assessment = _sample_assessment()

    # --- sign (real seal(), STAGING) ---
    att = seal(assessment)  # trust defaults to "staging"
    print("=== SIGNED (staging) ===")
    print(f"verdict:        {assessment.verdict.value}")
    print(f"decision_hash:  {att.decision_hash}")
    print(f"signer:         {att.signer_identity.subject}")
    print(f"issuer:         {att.signer_identity.issuer}")
    print(f"rekor:          {att.rekor_log_url}")

    # --- verify (real verify_signed_bundle(), STAGING) against an identity policy ---
    policy = IdentityPolicy(
        policy_id="fixture",
        issuers=(_GH_OIDC_ISSUER,),
        repository_patterns=(repo,),
    )
    verified = verify_signed_bundle(att.sigstore_bundle, identity_policy=policy)
    print("=== VERIFIED (staging) ===")
    print(f"verified verdict:        {verified.statement['predicate']['verdict']}")
    print(f"identity policy:         satisfied ({verified.identity_match.reason})")
    print("decision_hash recompute: passed (would have raised otherwise)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

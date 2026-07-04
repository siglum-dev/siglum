# Publishing is a separate gate from merging

Siglum is a **merge** gate. It blocks a non-merge-eligible change from merging. It does
**not**, by itself, stop a **publish/release**. A release workflow that runs off a tag or
a branch can ship an artifact whose source never passed the gate.

To deliver the "author + independently-validated + published" story end to end, the
**release/publish workflow must require the Siglum attestation as a predicate**:

- The release job verifies the Siglum validation attestation for the exact commit being
  released, using `cosign verify-attestation` / a policy-controller admission policy with
  the same identity policy the gate uses (issuer + subject/repo pinning).
- If no merge-eligible Siglum attestation exists for that commit, the release fails closed.

This is **opt-in**. Two honest scopes:

1. **Merge-eligibility only (default).** The claim is "this change is merge-eligible." We do
   not assert anything about what gets published. Simple; correct; the common case.
2. **Author + validate + publish.** Wire the release-side requirement above. Now the claim
   extends to "what shipped was independently validated." Requires the release workflow to
   be org-controlled too (same authority-isolation discipline as the seal-enforce job).

Do not imply scope (2) while only deploying scope (1). The attestation's subject is the
merge candidate; a release of a different artifact is outside the claim unless the release
workflow checks the attestation.

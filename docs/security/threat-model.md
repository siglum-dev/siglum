# Siglum threat model

Siglum turns "CI passed" from a claim into evidence you can verify. This document states what that protection assumes and what it does not. It describes the trust boundary, the attacker Siglum defends against, each attack and the specific mechanism that stops it, the cases Siglum deliberately does not cover, and the assumptions the guarantee rests on.

The honesty discipline here matches the README's Build status. Each defense below is marked as wired and unit-tested, or wired but exercised only in a live run, so a reader can tell proven logic from a live integration. Signing runs against Sigstore staging today, so every attestation should be treated as non-production until production Sigstore is wired.

## Attacker model

Siglum defends against a contributor who has push access to the repository and can edit CI in their own pull request, and who does not have organization-admin or bypass rights. This is the common and dangerous case: the person asking to merge also controls the workflow that produces the merge check, and with AI agents authoring a large share of pull requests, that trust is extended at scale.

Siglum does not defend against a compromised organization administrator. An admin who can disable branch protection, remove the required check, or replace the organization-pinned workflow is outside the model, and we state that boundary on purpose. A gate that claims to stop an attacker it cannot stop is just another green badge.

What Siglum attests is execution fidelity and evidence completeness, bound to the exact change: that a defined set of validators ran to completion over this commit, under a policy that was fixed and independent of the author for the duration of the assessment, and that the recorded verdict is a pure function of that evidence. It does not claim that the code is safe, the tests are meaningful, or the dependencies are sound.

## The trust boundary

The work is split across two jobs, and the boundary between them is the center of the design.

```
  ┌─ gather (UNTRUSTED) ─────────┐         ┌─ seal + enforce (TRUSTED) ──────────┐
  │ runs over the PR             │ digest- │ org-controlled, pinned to the base  │
  │ read-only, no secrets        │ pinned  │ never checks out the PR's code      │
  │ produces evidence only       │ ──────► │ anchors all policy inputs to base   │
  │ (cannot assert a verdict)    │ evidence│ recomputes, seals, posts the check  │
  └──────────────────────────────┘         └─────────────────────────────────────┘
```

Anything the author can edit runs in the gather job, whose output is consumed downstream only as untrusted, digest-pinned evidence. The trusted job recomputes the verdict, signs it, and posts the check. It never runs the author's code and never holds a token the pull request can reach. Every security-relevant fact about the verdict, which validators are required and at which pinned version, is taken authoritatively from the base policy and never from the gather artifact. The artifact supplies observations only: a status and an artifact digest for each validator.

## Attacks defended

These are listed in the order the trusted gate enforces them, because the order is part of the design: each stop fails closed and posts a failing check before the next one runs.

### Editing the gate in your own pull request

An author can edit the workflow, policy, or scanner config in their own pull request so the check passes without the validation, or replay an Actions token from a fork or another repository so that a run which is not the organization-pinned gate appears to be it. Siglum stops this by minting its own Actions OIDC token at the Sealed tier and verifying it (signature, issuer, audience, expiry), then enforcing the token claims against an organization-pinned gate-identity policy: the repository, the workflow reference, a protected ref the author cannot edit, and a hosted runner. The trigger actor string is never treated as the authority, and any mismatch fails closed with a specific reason, enforced in `gate/orchestrate.py` before the verdict is assessed and through the shared `gate_identity_mismatch` predicate. The verification and enforcement logic is wired and unit-tested, including an adversarial conformance suite that rejects `alg:none`, key-type confusion, a wrong issuer or audience, expiry, a bad signature, a self-hosted runner, and an absent run. Minting the live token runs only in a real CI workflow.

### Loosening the gate-identity policy

Even with the identity check in place, an author could try to make it vacuous by configuring the gate-identity policy with a wildcard workflow path or pointing it at a ref they can edit. Siglum mitigates this by requiring the gate-identity policy whenever independence is required, anchoring it to the base so a head commit cannot loosen it, and parsing it tight by construction: a wildcard workflow path is rejected, and a concrete workflow path and a non-empty list of branch or tag refs are required at load time. Load-time parsing checks the shape of those refs, not that they are actually protected. The `siglum setup check` preflight verifies that the declared ref is the actually-protected default branch, where proving protection for any other ref is a documented limitation, and at runtime the gate requires the verified token's own ref to be one of the declared refs. So a base policy that named an editable ref is caught by the preflight rather than by policy parsing. The parsing and the preflight are wired and unit-tested.

### Installing the gate without actually enforcing it

An operator can install the App and the workflow but forget to make the `siglum` check required, or leave it satisfiable by any source, so the gate runs but nothing depends on its result. At the Sealed tier the gate closes this by self-auditing its own enforcement configuration through the App API and failing closed unless the `siglum` check is required on a protected branch and source-restricted to the Siglum App by its id. A policy that requires independence but has no App credentials also fails closed, rather than degrading silently to a weaker posture. The `siglum setup check` preflight runs the same predicate before go-live, so the misconfiguration is caught before the gate is relied on. This is enforced in `gate/orchestrate.py` through `_self_audit_enforcement` over the `enforcement_mismatch` predicate. The audit logic and the preflight are wired and unit-tested, and the live configuration read is exercised only in a real run and is normalized to fail closed on any read error.

### Poisoning the evidence

The gather job runs over the author's code, so an author can influence it to report a base-required validator as not required, pin it to a different version, or omit it, turning a failing or missing validator into a pass or an absence. Siglum defends against this by taking the required flag and the pinned version for every validator authoritatively from the base policy and treating the gather artifact as observations only, namely a status and an artifact digest. A head-controlled results.json therefore cannot launder a base-required validator's required flag or its version, though the gate records the base-pinned version rather than independently proving the gather executed that exact version. A base-required validator that the gather job did not produce is filled with UNKNOWN, which fails closed, so a head that deletes a gate-critical validator cannot make it disappear. Duplicate validator ids are rejected, and any id not declared by the base policy is ignored, so only base-policy validators contribute to the verdict. This is enforced in `gate/evidence.py` through `normalize_evidence`, which the trusted job in `gate/orchestrate.py` calls, and is wired and unit-tested.

### Changing a base-anchored input at the head

An author can edit a gate-critical input at the head, such as the policy, a scanner config, or the workflow, so that the validation effectively runs under the head's rules instead of the base's. The trusted job reads the head version of each anchored path itself, at the head SHA, through the App contents API, rather than trusting any digest reported by the gather artifact, and it fails closed when the head overrides a base-anchored input. This is enforced in `gate/orchestrate.py` through `anchor_inputs`. The override-detection logic is wired and unit-tested, and the live file reads are exercised only in a real run.

### Approve one version, merge another

An author can obtain an approval on one commit and then force-push a different one, or route the change through a merge queue that does not actually require a review. When the policy requires approval, Siglum requires the mergeable subject to carry a current approval bound to the subject SHA: the approved SHA is computed per reviewer from the reviews the gate reads with its own token, is cleared by a later request for changes, and must equal the head being gated. Approve-A-then-force-push-B and an approval left behind by a new push both fail closed, because the approval is then for the old SHA, and the failing check says exactly that and asks for a re-approval of the current head, since an innocent fixup push produces the same state. Approval proof is opt-in through `approval_required` in the base policy; a policy that does not require it never consults review state, so a leftover approval for an older commit cannot refuse a gate that was never asked to prove one. The gate also confirms the event head against the pull request fetched with its own token, so a head that moved during the run fails closed. In a merge queue, where per-pull-request approval is not visible, the gate instead proves the prerequisite that the protected target branch requires an approving review, read from branch protection; it proves this only for the audited default branch and fails closed for any other target or on a read error. The proof logic (`prove_approval` and the head binding) is wired and unit-tested; fetching the reviews and the pull-request head runs only in a real CI workflow.

### A green check with nothing behind it

An attacker could try to present a green check that is not backed by the recomputed, signed verdict. Siglum recomputes the verdict and the decision hash on deserialization and rejects anything that does not recompute, so a stored or hand-edited result is never trusted, and at the Sealed tier it signs the attestation and self-verifies the signed bundle before it posts a success, failing closed if signing or self-verification fails. There is never a green check without a verified attestation behind it. The ordering and the recompute guard are wired and unit-tested, and the offline verification path is unit-tested, while the Sigstore signing itself runs only in a real CI workflow and against staging. A self-hosted runner and a read failure fail closed as well, since the gate requires a hosted runner from the verified token and a non-404 read failure raises rather than falling back to a weaker policy. This is enforced in `gate/orchestrate.py` in the success path and in `verify`.

## What Siglum does not defend against

A compromised organization administrator. An admin who disables branch protection or a ruleset, removes the required check, or changes the organization-pinned workflow defeats the gate. The runtime self-verification checks on every run that the gate is the expected authority and is actually enforced, but it cannot defend against an administrator who turns enforcement off. This is the documented org-admin and bypass boundary.

Validators that execute head-authored code. The model is sound for read-only validators, which apply base logic over head data, and that is why this version ships only the read-only secret-scan validator. A validator that runs head-authored code would need a stronger evidence-integrity mechanism than digest-pinned observations, and that is out of scope for now.

The adequacy of the validation. Siglum attests that the validators ran and that the verdict follows from their evidence. It does not judge whether those validators were the right ones or whether they were strict enough.

Production-grade signing. Signing is pinned to Sigstore staging and refuses to run against production, because production signing is deliberately gated behind explicit review. Until production Sigstore is wired, every attestation should be treated as non-production.

## Residual assumptions

The guarantee rests on a few assumptions that are worth stating plainly.

GitHub's OIDC issuer, branch protection, and rulesets behave as documented. The gate reads them as ground truth for the run's identity and for whether the check is enforced.

The organization deploys the pinned seal-and-enforce workflow correctly and restricts the `siglum` check to the Siglum App. The runtime self-audit and the setup-check preflight detect a missing or loose deployment and fail closed, but they cannot detect an administrator who removes protection after the fact.

The Siglum App's credentials are held as organization or repository secrets and are not reachable from the pull request. The gather job runs with read-only permissions and holds no secrets, no write access, and no id-token, so it cannot post a verdict or sign.

Pinning the immutable repository id is optional. When a policy pins it, the runtime enforces it, and the preflight verifies a numeric pin against the repository's actual id whenever the snapshot carries one. A snapshot without a trustworthy id (a local fixture) reports the pin as enforced at runtime rather than verified, and a non-numeric pin fails the preflight outright.

Sigstore staging is the current trust root. Staging attestations are not production evidence.

## Status discipline

Every defense above is marked as wired and unit-tested, or wired but exercised only in a live run. The split is simple: the decision logic is unit-tested through in-memory fakes, and every live call the gate makes at runtime is exercised only in a real CI workflow, never in unit tests. Those live calls include the Sigstore signing; minting and verifying the Actions OIDC token, with its JWKS fetch; the GitHub App installation-token exchange; reading the enforcement configuration and branch protection, the pull-request head, its reviews, and its changed files, and the base and head versions of each anchored file; and posting the check-run and the pull-request comment. Production Sigstore and an end-to-end run against a real repository are the remaining roadmap items, as listed in the README Build status.

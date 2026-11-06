# Siglum

**A merge gate you can prove.**

[![CI](https://github.com/siglum-dev/siglum/actions/workflows/ci.yml/badge.svg)](https://github.com/siglum-dev/siglum/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)

Siglum turns "CI passed" from a claim into evidence you can verify. A green check tells you that a check with the right name reported success. It does not tell you the check ran on the exact code being merged, that it was not silently skipped, or that the pull request did not edit the check on its way in. Siglum recomputes the verdict from the actual evidence, binds it to the exact commit, runs the gate outside the pull request's control, and seals the result into a signed [in-toto](https://in-toto.io) attestation that anyone can verify offline with [Sigstore](https://www.sigstore.dev) tooling.

> **Status: early-stage (v0.1).** The decision logic is implemented and unit-tested. Signing runs against Sigstore staging today. The [Status](#status) section says exactly what is wired.

## Why

AI agents now open pull requests faster than a human can read them line by line. At that volume the reviewer stops re-reading every diff and leans on the checks: if the required checks pass, the change can merge. That reliance is only sound if a green check is trustworthy.

Today it is not. A contributor, human or agent, who can push a branch and edit CI can make a required check pass without doing the validation it stands for. Nothing needs to be exploited or forged; the check goes green for real and looks identical to a genuine pass, because the command, config, or workflow behind it arrived in the same pull request that is asking to merge.

Siglum makes the green check mean what the reviewer assumes it means. It proves the required checks actually ran, on this exact commit, under a policy the pull request could not edit, and it leaves a signed record. The reviewer can trust the gate instead of re-deriving it by hand, so a team can take agent-authored pull requests at the speed agents produce them.

Siglum also ships an audit that reads a repository's actual branch-protection, ruleset, and workflow configuration and reports where the gate can be bypassed today, so you can see the gap in your own repositories before deciding whether to close it.

## Try it

```bash
git clone https://github.com/siglum-dev/siglum && cd siglum
python -m pip install -e ".[dev]"
```

Audit a repository you can read. Public repos may work without a token; private repos and full branch-protection details need `GITHUB_TOKEN`:

```bash
siglum audit --repo owner/name
```

It reports each place the gate is hollow: a required check any token can post, a workflow the pull request can edit, a job that can skip without failing. It only reads; it changes nothing. Exit code `0` means no findings, `1` means findings were found, and `2` means Siglum could not complete the audit.

To walk the whole flow locally with no GitHub access, use the generated demo repository:

```bash
siglum demo scaffold --out /tmp/gate-proof-demo --repo owner/gate-proof-demo --force
cd /tmp/gate-proof-demo
siglum audit --config siglum-audit-config.json || true
siglum setup check --local .
```

The fixture audit should find `PR_EDITABLE_WORKFLOW`, so it exits `1` by design. The `|| true` keeps the walkthrough moving to the setup check, which shows what a ready Sealed install looks like.

If `siglum` is not found after an editable install, make sure your Python user-script directory, often `.local/bin` in your home directory, is on `PATH`.

## How it works

**1. Siglum computes the verdict from the evidence.** It takes the evidence about a change (which validators ran, their status, the artifacts they produced) and computes one verdict: `PASS`, `FAIL`, or `ERROR`, with explicit coverage (`FULL` or `INCOMPLETE`). A change is mergeable only when the verdict is `PASS`, coverage is `FULL`, and independence is satisfied. Anything missing fails closed. The core is pure and replayable, so the same evidence always produces the same verdict and you can re-run the decision offline.

**2. The author is kept away from the gate.** At the Sealed tier the work is split across two jobs:

```
  gather (untrusted)                    seal + enforce (trusted)
  runs over the pull request            org-controlled, pinned to the base
  read-only, holds no secrets     -->   never checks out the PR's code
  produces evidence only          -->   anchors every policy input to the base
  cannot assert a verdict               recomputes, signs, posts the check
```

Anything the author edits lands in the gather job, whose output is consumed only as untrusted, digest-pinned evidence. The job that recomputes the verdict and signs it never runs the author's code and never holds a token the pull request can reach.

**3. The result is a signed proof anyone can verify.** The verdict is sealed into an in-toto validation predicate, the validation-side sibling to SLSA build provenance. It is keyless-signed through Sigstore, recorded in a transparency log, and verifiable offline with `cosign` and a strict identity policy, with no Siglum service in the loop:

```bash
cosign verify-attestation \
  --type https://siglum.dev/ValidationAttestation/v0.3 \
  --certificate-identity-regexp '^https://github.com/your-org/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  your-artifact
```

## Two tiers

**Dry-run** runs in your normal CI and previews the verdict. Use it to author policy and to see where a gate silently skips. It has no verified identity and does not sign.

**Sealed** is the security guarantee. It runs in an org-controlled workflow outside the pull request's pipeline, verifies its own GitHub Actions OIDC identity, and signs the attestation. It defends against a contributor who can push and edit CI but does not have organization-admin rights.

## What it proves, and what it doesn't

Siglum attests that a defined set of validators ran to completion over a specific change, under a policy that was fixed and independent of the author for the duration of the assessment, and that the recorded verdict is a pure function of that evidence.

It does not claim your code is safe, your tests are meaningful, or your dependencies are sound. It attests to execution fidelity and evidence completeness, bound to the exact change. A pull request from an AI agent is treated exactly like one from any other contributor: the guarantee never depends on trusting the author, so it holds whether the author is a person or an agent. It defends against a malicious contributor without admin or bypass rights, and it does not defend against a compromised organization administrator. The full boundary, attack by attack, is in [the threat model](docs/security/threat-model.md).

## Install

Python 3.12 or newer.

- `pip install -e .` installs the core and the `siglum` CLI.
- `pip install -e ".[sigstore]"` adds signing and offline bundle verification.
- `pip install -e ".[github-app]"` adds the Sealed tier's GitHub App authentication.
- `pip install -e ".[dev]"` adds the test and lint tooling.

The reference workflows install Siglum from the `SIGLUM_PACKAGE_SPEC` repository variable, which can point at this repository (`git+https://...`) or a package index. Point it at an immutable ref (a commit SHA or a pinned release) so the code your trusted job runs cannot drift underneath you.

## Deploying the Sealed gate

Register a GitHub App in your own organization. There is no hosted Siglum service and no marketplace App; the App and its key are yours. Deploy the org-controlled `seal + enforce` reusable workflow, pinned to a ref your contributors cannot edit, and make the `siglum` check required in your ruleset with its source restricted to that App. The workflow needs the App id, installation id, and private key as secrets so it can post the check-run and the explanation comment. Gating releases is a separate step from gating merges; see [`docs/publish-gate.md`](docs/publish-gate.md).

## Status

Early-stage. The GitHub and Sigstore integrations are at different stages of maturity, so this section is the honest ledger of what is true today.

**Working today, covered by the unit suite.**

- **The verdict core.** The verdict is recomputed from the evidence rather than accepted from the pull request, and anything missing or malformed fails closed: a skipped validator, an unreadable policy, or an evidence gap is never a pass. The decision is a pure function of the evidence, pinned by a decision hash, so a verifier can re-derive it offline later.
- **Policy anchoring.** Every input that affects the verdict (the policy file, the gate workflows, anything else the policy names) is read from the protected base branch, and digests for the head are derived at the head commit itself instead of being trusted from the untrusted gather output. A pull request that edits an anchored file is refused before the verdict is derived.
- **Verified identity.** The Sealed gate verifies its own GitHub Actions OIDC token and enforces its claims (issuer, repository, workflow ref, protected ref, hosted runner) against an org-pinned policy. The conformance suite covers the adversarial cases: `alg:none`, key-type confusion, wrong issuer or audience, expired tokens, bad signatures, self-hosted runners, and absent runs.
- **Enforcement self-audit.** The gate fails closed unless its own check is actually required and source-restricted to the App, so a half-installed gate refuses rather than quietly running with no authority.
- **The rest of the surface.** The source-restricted check-run and explanation comment, the opt-in approval proof, the evidence-gap audit, the setup preflight, offline verification, the secret-scan validator in the gather job, and the CLI.

**Working, exercised only in a live run.** Signing and self-verifying the attestation before the check goes green, and minting the Actions OIDC token that verification consumes. The logic is covered by unit tests; the live signing and network paths run only in a real CI workflow.

**Roadmap.** Production Sigstore (signing is pinned to staging and refuses production until that path has been reviewed) and an end-to-end run on a real repository.

Siglum grew out of an earlier in-CI evidence check for agent-assisted pull requests. That check ran inside the pull request's own workflow, which is the hole Siglum closes.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, the pull-request gates, and the invariants the code holds. To report a vulnerability, see [SECURITY.md](SECURITY.md).

Siglum sits on top of the validators you already run and decides whether their evidence is trustworthy enough to merge, then leaves a signed record of that decision. It runs in your organization's CI; there is no hosted service.

## License

[Apache-2.0](LICENSE).

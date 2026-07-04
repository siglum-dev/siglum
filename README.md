# Siglum

**A merge gate you can prove.**

[![CI](https://github.com/siglum-dev/siglum/actions/workflows/ci.yml/badge.svg)](https://github.com/siglum-dev/siglum/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)

Siglum turns "CI passed" from a claim into evidence you can verify. When a required check goes green, all you really know is that a check with the right name ran. You do not know it ran on the exact code being merged, that it was not silently skipped, or that the author did not edit the check in the same pull request that is asking to merge. Siglum recomputes the verdict from the actual evidence, binds it to the exact commit, runs the gate outside the pull request's control, and seals the result into a signed [in-toto](https://in-toto.io) attestation that anyone can verify offline with [Sigstore](https://www.sigstore.dev) tooling.

This is what lets a team accept pull requests from AI agents at the speed the agents produce them. The reviewer cannot read every diff at that volume, so they rely on the checks. Siglum makes that reliance sound: it proves the required checks actually ran on this exact code, under rules the pull request could not touch, so a human can trust a green gate instead of re-deriving it by hand.

> **Status: early-stage (v0.1).** The decision logic is implemented and unit-tested. Signing runs against Sigstore staging today. The [Status](#status) section says exactly what is wired.

## Why

AI agents now open pull requests faster than a human can read them line by line. At that volume the reviewer stops re-reading every diff and leans on the checks: if the required checks pass, the change can merge. That only holds if a green check is trustworthy, and today it is not.

A green check tells you a check with the right name ran. It does not tell you the check ran on the exact code being merged, that it was not silently skipped, or that its command, config, or workflow was not edited by the same pull request that is asking to merge. A contributor, human or agent, who can push a branch and edit CI can make the checks pass without doing the validation. Nothing is exploited; the check goes green for real and looks identical to a genuine one.

Siglum makes the green check mean what the reviewer assumes it means. It proves the required checks actually ran, on this exact commit, under a policy the pull request could not edit, and it leaves a signed record of it. The reviewer trusts the gate instead of re-deriving it by hand, so you can take agent-authored pull requests at agent speed without the gate quietly turning into theater.

Siglum also ships an audit that reads a repository's actual branch-protection, ruleset, and workflow configuration and reports where the gate can be bypassed today, so you can see the gap in your own repositories before deciding whether to close it.

## Try it

```bash
git clone https://github.com/siglum-dev/siglum && cd siglum
python -m pip install -e .
```

Audit a repository you can read (set a GitHub token in `GITHUB_TOKEN`):

```bash
siglum audit --repo owner/name
```

It reports each place the gate is hollow: a required check any token can post, a workflow the pull request can edit, a job that can skip without failing. It only reads; it changes nothing.

To walk the whole flow locally with no GitHub access, use the generated demo repository:

```bash
siglum demo scaffold --out /tmp/siglum-demo --repo owner/demo
cd /tmp/siglum-demo
siglum audit --config siglum-audit-config.json
siglum setup check --local .
```

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

The reference workflows install Siglum from the `SIGLUM_PACKAGE_SPEC` repository variable, which can point at this repository (`git+https://...`) or a package index.

## Deploying the Sealed gate

Register a GitHub App in your own organization. There is no hosted Siglum service and no marketplace App; the App and its key are yours. Deploy the org-controlled `seal + enforce` reusable workflow, pinned to a ref your contributors cannot edit, and make the `siglum` check required in your ruleset with its source restricted to that App. The workflow needs the App id, installation id, and private key as secrets so it can post the check-run and the explanation comment. Gating releases is a separate step from gating merges; see [`docs/publish-gate.md`](docs/publish-gate.md).

## Status

Early-stage. The decision logic is implemented and unit-tested; the GitHub and Sigstore integrations are at different stages, so here is what is true today.

**Wired and unit-tested.** The verdict core (derivation, coverage, independence, the decision hash, recompute-before-trust), base-anchoring of policy inputs, the drop-a-validator defense, and binary enforcement. The Sealed-tier identity logic: the gate verifies a GitHub Actions OIDC token and enforces its claims (issuer, repository, workflow ref, protected ref, hosted runner) against an org-pinned, base-anchored policy, with an adversarial conformance suite (`alg:none`, key-type confusion, wrong issuer or audience, expiry, bad signature, self-hosted runner, absent run). The runtime enforcement self-audit (the gate fails closed unless its own check is required and source-restricted to the App by id). Fail-closed reads, with no fallback to a weaker policy. The opt-in approval proof. Head-digest integrity (head digests are derived at the head SHA, never trusted from the gather artifact). The source-restricted check-run and comment, the evidence-gap audit, the setup preflight, offline verification, and the CLI. The `secret-scan` validator runs in the gather job.

**Wired, exercised only in a live run.** Signing and self-verifying the attestation before a green check, and minting the Actions OIDC token the verification consumes. The logic is covered by unit tests; the live signing and network paths run only in a real CI workflow.

**Roadmap.** Production Sigstore (signing is pinned to staging and refuses to run otherwise, because production signing is gated behind explicit review) and an end-to-end run on a real repository.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and the invariants the code holds: fail-closed reads, strict typing on untrusted input, and the schema lockstep rule. To report a vulnerability, see [SECURITY.md](SECURITY.md).

Siglum is not a scanner, linter, or AI reviewer, and it is not a SaaS or a dashboard. It sits on top of the tools you already run and decides whether their evidence is trustworthy enough to merge, then leaves a signed record that it was.

## License

[Apache-2.0](LICENSE).

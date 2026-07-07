# Security policy

Siglum is a security tool, so we treat reports about it with priority.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository ("Security" tab,
"Report a vulnerability"). Do not open a public issue for anything you believe is
exploitable.

Include what you can: the attack you see, the code path, and ideally a failing test or
reproduction. You can expect an acknowledgment within a few days.

## Scope

The interesting reports are the ones that break a stated guarantee. In particular:

- a way to make the gate post a green `siglum` check without the validation happening
  (fail-open paths, evidence laundering, identity confusion),
- a way to make offline verification accept an attestation whose verdict does not
  rederive from its recorded evidence,
- a way for a pull request author to influence the trusted seal-enforce job.

Out of scope by design (documented in `docs/security/threat-model.md`): a compromised
organization administrator, validators that execute head-authored code, and the adequacy
of any particular validator.

## Signing status

Signing currently runs against Sigstore **staging** and refuses production. Attestations
produced today are not production evidence, and the project treats them that way.

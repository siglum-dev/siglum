# Fixture credential audit

Siglum's own feature is detecting planted secrets, so its test corpus and the gate-proof demo fixtures necessarily contain deliberately-fake credentials. This note is the pre-public-launch audit of every secret-shaped value in the repository. It certifies that each is an obviously-fake placeholder, is documented as a fixture, and either never appears as a literal a scanner can match or is allowlisted with a stated reason. It was first run on 2026-07-04 on the launch-hardening tree; both gitleaks scans (working tree and full history) were clean. Both scans were re-run on 2026-07-07 over this tree with gitleaks 8.30.0 and were clean again.

## Inventory

`AKIA0123456789ABCDEF` is an AWS-access-key-shaped placeholder built from the sequential hex digits, used to exercise the `secret-scan` validator and the demo's injected leak. It is not a real credential. It appears as a literal in `src/siglum/demo_scaffold.py` (the generated gate-proof demo's planted key) and in `tests/test_validators_run.py`, and it is allowlisted in `.gitleaks.toml` with a comment explaining why.

`AKIA` followed by sixteen `A` characters is a second fake AWS-key shape used in `tests/test_validator_secrets.py`. It is constructed at runtime by string concatenation (`'AKIA' + "A"*16`), so the complete key literal never appears in the source and no scanner can match it. It needs no allowlist entry for that reason.

RSA private keys used by the GitHub App credential tests in `tests/gate/test_github_app.py` are generated in memory at test runtime with the `cryptography` library (`rsa.generate_private_key`). No private-key material is committed to the repository or its history. The only `PRIVATE KEY` strings in the tree are that library call, a `"BEGIN PRIVATE KEY"` assertion, and the detector's own regex.

The detector patterns in `src/siglum/validators/secrets.py` (the AWS, private-key, and GitHub-token regexes) are patterns, not literal secrets, so a scanner does not match them.

## Scanner coverage

`.gitleaks.toml` extends the gitleaks default rules (`useDefault = true`) and adds one allowlist entry for `AKIA0123456789ABCDEF`, with a comment recording that it is a known-fake demo and test credential.

Run with gitleaks 8.30.0:

- Working tree (`gitleaks detect --no-git`): no leaks found.
- Full git history (`gitleaks detect`): no leaks found.

A search for other live-token shapes (GitHub personal access tokens, OpenAI keys, Slack tokens) found none anywhere in the tree.

## Maintenance

Keep this property when adding fixtures. A new fake credential should either be constructed at runtime so its literal never lands in the source, or be an obviously-fake canonical value allowlisted in `.gitleaks.toml` with a one-line reason. Re-run the two gitleaks scans above before any public launch.

# Contributing

## Setup

```bash
git clone https://github.com/siglum-dev/siglum && cd siglum
python -m pip install -e ".[dev,sigstore,github-app]"
python -m pytest -q        # the whole suite runs in a couple of seconds
python -m ruff check .
python -m mypy src tests
```

## Opening a pull request

All three gates above must be clean before a pull request; CI runs the same test, lint, and type checks. Every pull request also gets a preview `siglum` check posted by this repository's own dry-run gate (`.github/workflows/siglum-self-gate.yml`). The project gates itself with the tool it ships, and the check's comment explains its verdict. The preview check is informational; the checks that block a merge are the tests, lint, and types.

Bug reports and proposals are welcome as issues. If you believe you have found something exploitable, do not open a public issue; see [SECURITY.md](SECURITY.md) instead.

## How the code is organized

The pure verdict core (`models`, `verdict`, `derive`, `canonical`, `predicate`) has no
I/O. Sealing (`sealing/`) signs and verifies it. The gate (`gate/`) composes the trusted
side. The only network code lives in `forge/` and the fetch halves of `audit/` and
`setup_check`, and network functions are marked `# pragma: no cover`: decision logic is
unit-tested through in-memory fakes, live calls are exercised only in a real CI run.

## The lockstep rule (read this before touching the schema)

The decision fields are hand-mirrored in four places, and they must change together:

1. `derive._decision_payload` (what the decision hash covers)
2. `predicate.build_predicate` (what the attestation records)
3. `sealing/verify_signed._bundle_from_predicate` (what offline verification reconstructs)
4. `policy._canonical_policy` (what the policy hash covers), when the field is policy-side

If you add, rename, or remove a field in one and not the others, the failure mode is not
a test error somewhere obvious; it is an attestation that silently stops rederiving, which
is exactly the class of bug this project exists to prevent.
`tests/test_schema_conformance.py` round-trips bundles through the predicate and back and
fails on any drift; keep it passing and extend it when you add fields. A change to the
decision payload is a schema change: bump `SCHEMA_VERSION` and `PREDICATE_TYPE` together
and update `SUPPORTED_SCHEMA_VERSIONS`.

## Fail-closed is the house style

A read failure is never an absence (404 is the only absence). Untrusted input is typed
strictly, never coerced. A refusal posts a legible failing check that says what happened
and how to fix it; see `docs/security/threat-model.md` for the enforcement order. If a
change can fail open under any misconfiguration, it needs a test showing it does not.

## Writing style

Repository prose (docs, comments, messages surfaced to users) is plain human English.
No em dashes. Refusal and error text must state the situation and the fix, not just name
the rule that fired. When a documented walkthrough intentionally exits nonzero (for
example, an audit that is supposed to find a finding), say so next to the command, so
readers do not think the demo broke.

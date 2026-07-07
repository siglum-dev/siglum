"""Generate the gate-proof demo fixture repository."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


class DemoScaffoldError(RuntimeError):
    """The demo fixture cannot be written safely."""


@dataclass(frozen=True, slots=True)
class DemoScaffoldResult:
    root: Path
    files: tuple[Path, ...]


def scaffold_demo(
    root: Path, *, repo: str = "siglum/gate-proof-demo", force: bool = False
) -> DemoScaffoldResult:
    root = root.resolve()
    if root.exists() and any(root.iterdir()) and not force:
        raise DemoScaffoldError(f"{root} is not empty; pass --force to overwrite demo files")
    files: list[Path] = []
    for rel, body in _files(repo).items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        files.append(path)
    script = root / "demo" / "local-rehearsal.sh"
    script.chmod(0o755)
    return DemoScaffoldResult(root=root, files=tuple(sorted(files)))


def _files(repo: str) -> dict[str, str]:
    return {
        "README.md": _readme(repo),
        "service/__init__.py": "",
        "service/auth.py": _auth_py(),
        "tests/test_auth.py": _test_auth_py(),
        ".github/workflows/ci.yml": _ci_yml(),
        ".github/workflows/siglum-gather.yml": _gather_yml(),
        ".github/workflows/siglum-seal-enforce.yml": _seal_yml(),
        ".siglum/policy.toml": _policy_toml(repo),
        "identity-policy.toml": _identity_policy(repo),
        "siglum-audit-config.json": _audit_config(repo),
        "siglum-setup-config.json": _setup_config(repo),
        "demo/prevention.patch": _prevention_patch(),
        "demo/prevention-pr.md": _prevention_pr(repo),
        "demo/local-rehearsal.sh": _local_rehearsal_sh(),
        "demo/README.md": _demo_readme(repo),
    }


def _readme(repo: str) -> str:
    return f"""# Siglum Gate-Proof Fixture

This repo is intentionally shaped as a gate-proof demo: Siglum blocks a
poisoned-evidence PR before it can become mergeable.

Repo name used by the generated audit fixture: `{repo}`.

The story:

1. The repo has a required `tests` check.
2. That check is produced by a pull-request workflow.
3. A contributor can edit that workflow in the same PR as their code change.
4. The old required check can go green even though validation was poisoned.
5. Siglum Sealed blocks the prevention PR because the gate-critical workflow and policy are
   anchored to the protected base.

Start with `demo/README.md`.
"""


def _auth_py() -> str:
    return '''"""Tiny service code for the Siglum gate-proof demo."""


def issue_session_token(user_id: str) -> str:
    if not user_id:
        raise ValueError("user_id is required")
    return f"session:{user_id}"
'''


def _test_auth_py() -> str:
    return """from service.auth import issue_session_token


def test_issue_session_token():
    assert issue_session_token("alex") == "session:alex"
"""


def _ci_yml() -> str:
    return """name: ci
on:
  pull_request:

permissions:
  contents: read

jobs:
  tests:
    name: tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install pytest
      - run: python -m pytest
"""


def _gather_yml() -> str:
    return """name: siglum-gather
on:
  workflow_call:
    outputs:
      results_digest:
        description: sha256 of the uploaded validator results
        value: ${{ jobs.gather.outputs.results_digest }}

permissions:
  contents: read

jobs:
  gather:
    runs-on: ubuntu-latest
    env:
      SIGLUM_PACKAGE_SPEC: ${{ vars.SIGLUM_PACKAGE_SPEC }}
      # Event values are passed through env and treated as data, so no run script
      # interpolates ${{ github.event.* }} directly.
      BASE_SHA: ${{ github.event.pull_request.base.sha }}
      HEAD_SHA: ${{ github.event.pull_request.head.sha }}
      # siglum.validators.run reads GITHUB_BASE_SHA for the Change record it emits.
      GITHUB_BASE_SHA: ${{ github.event.pull_request.base.sha }}
    outputs:
      results_digest: ${{ steps.run.outputs.results_digest }}
    steps:
      # Pinned by commit digest rather than a movable tag: these workflows are the
      # gate's own supply chain. The comment records the release the digest came from.
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0   # v7.0.0
        with:
          fetch-depth: 0
      - id: run
        run: |
          python -m pip install "${SIGLUM_PACKAGE_SPEC:?Set SIGLUM_PACKAGE_SPEC to the Siglum package source}"
          git diff --name-only "$BASE_SHA" "$HEAD_SHA" > changed-files.txt
          python -m siglum.validators.run --changed-files changed-files.txt --out results.json
          echo "results_digest=$(sha256sum results.json | cut -d' ' -f1)" >> "$GITHUB_OUTPUT"
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a   # v7.0.1
        with:
          name: siglum-results
          path: results.json
"""


def _seal_yml() -> str:
    return """name: siglum-seal-enforce
on:
  workflow_call:
    inputs:
      results_artifact:
        type: string
        required: true
    secrets:
      SIGLUM_GITHUB_APP_ID:
        required: true
      SIGLUM_GITHUB_APP_INSTALLATION_ID:
        required: true
      SIGLUM_GITHUB_APP_PRIVATE_KEY:
        required: true

permissions:
  id-token: write
  checks: write
  issues: write
  contents: read

jobs:
  seal-enforce:
    runs-on: ubuntu-latest
    env:
      SIGLUM_GITHUB_APP_ID: ${{ secrets.SIGLUM_GITHUB_APP_ID }}
      SIGLUM_GITHUB_APP_INSTALLATION_ID: ${{ secrets.SIGLUM_GITHUB_APP_INSTALLATION_ID }}
      SIGLUM_GITHUB_APP_PRIVATE_KEY: ${{ secrets.SIGLUM_GITHUB_APP_PRIVATE_KEY }}
      SIGLUM_PACKAGE_SPEC: ${{ vars.SIGLUM_PACKAGE_SPEC }}
    steps:
      # Pinned by commit digest rather than a movable tag. The comment records the
      # release the digest came from. The trusted job never checks out or runs the
      # PR's code.
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c   # v8.0.1
        with:
          name: ${{ inputs.results_artifact }}
      - run: |
          python -m pip install "${SIGLUM_PACKAGE_SPEC:?Set SIGLUM_PACKAGE_SPEC to the Siglum package source}"
          python -m siglum.gate.run --results results.json
"""


def _policy_toml(repo: str) -> str:
    return f"""version = 1
policy_id = "gate-proof-demo"
independence_required = true
anchor_paths = [".github/workflows/siglum-seal-enforce.yml"]

[[validators]]
id = "secret-scan"
version = "0"
required = true
kind = "builtin"
anchor_paths = [".github/workflows/siglum-gather.yml"]

[gate_identity]
repository = "{repo}"
workflow_path = ".github/workflows/siglum-seal-enforce.yml"
protected_refs = ["refs/heads/main"]
"""


def _identity_policy(repo: str) -> str:
    return f"""policy_id = "gate-proof-demo-release"
issuers = ["https://token.actions.githubusercontent.com"]
repository_patterns = ["{repo}"]
require_runner_environment = "github-hosted"
"""


def _audit_config(repo: str) -> str:
    return f"""{{
  "repo": "{repo}",
  "default_branch": "main",
  "protected": true,
  "required_checks": [
    {{
      "context": "tests",
      "enforcement": "app_check_run",
      "source_restricted": true
    }}
  ],
  "workflows": [
    {{
      "path": ".github/workflows/ci.yml",
      "pr_editable": true,
      "continue_on_error": false,
      "path_filters": [],
      "produces_checks": ["tests"]
    }}
  ],
  "admin_bypass_allowed": false
}}
"""


def _setup_config(repo: str) -> str:
    return f"""{{
  "repo": "{repo}",
  "default_branch": "main",
  "protected": true,
  "required_checks": [
    {{
      "context": "siglum",
      "enforcement": "app_check_run",
      "source_restricted": true
    }}
  ],
  "workflows": [],
  "admin_bypass_allowed": false
}}
"""


def _prevention_patch() -> str:
    return """diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -14,5 +14,4 @@ jobs:
       - uses: actions/setup-python@v5
         with:
           python-version: "3.12"
-      - run: python -m pip install pytest
-      - run: python -m pytest
+      - run: echo "All tests passed"
diff --git a/service/auth.py b/service/auth.py
--- a/service/auth.py
+++ b/service/auth.py
@@ -1,7 +1,10 @@
 \"""Tiny service code for the Siglum gate-proof demo.\"""
 
+AWS_ACCESS_KEY_ID = "AKIA0123456789ABCDEF"
+
 
 def issue_session_token(user_id: str) -> str:
     if not user_id:
         raise ValueError("user_id is required")
+    _ = AWS_ACCESS_KEY_ID
     return f"session:{user_id}"
"""


def _local_rehearsal_sh() -> str:
    return """#!/usr/bin/env bash
set -euo pipefail

echo "1. Audit the intentionally vulnerable pre-Siglum gate"
siglum audit --config siglum-audit-config.json || true

echo
echo "2. Lint the Sealed policy that will be installed"
siglum policy lint .siglum/policy.toml

echo
echo "2b. Check the post-install Sealed readiness fixture"
siglum setup check --local .

echo
echo "3. Apply the prevention patch in a throwaway branch/worktree before running this step"
echo "   git apply demo/prevention.patch"
echo "   The old required tests check can be changed to echo success."
echo "   Siglum's secret-scan evidence will fail on the injected key."
"""


def _demo_readme(repo: str) -> str:
    return f"""# Siglum Gate-Proof Walkthrough

This directory is generated by `siglum demo scaffold`.

## 1. Show the problem

Run:

```bash
siglum audit --config siglum-audit-config.json || true
```

Expected finding:

```text
PR_EDITABLE_WORKFLOW .github/workflows/ci.yml
```

Meaning: the required `tests` check is produced by a workflow the PR author can edit. The
command exits `1` because it found the expected gap; `|| true` keeps scripted
walkthroughs moving.

## 2. Open the prevention PR

Create a branch and apply the prevention patch:

```bash
git checkout -b demo/siglum-prevents-poisoned-evidence
git apply demo/prevention.patch
```

The patch does two things in one PR:

- adds a hardcoded AWS-looking credential to `service/auth.py`
- changes `.github/workflows/ci.yml` from `python -m pytest` to `echo "All tests passed"`

This is a controlled prevention drill: the PR represents the class of poisoned-evidence
change Siglum is designed to prevent.

Use `demo/prevention-pr.md` as the PR body.

## 3. Install Sealed

Install the Siglum GitHub App on `{repo}` and store these secrets:

```text
SIGLUM_GITHUB_APP_ID
SIGLUM_GITHUB_APP_INSTALLATION_ID
SIGLUM_GITHUB_APP_PRIVATE_KEY
```

Set this repository or organization variable:

```text
SIGLUM_PACKAGE_SPEC
```

For the prevention drill, `SIGLUM_PACKAGE_SPEC` must point to an installable Siglum
package source that the untrusted gather job can read without secrets.

Then require the `siglum` check in branch protection or a ruleset, and source-restrict it
to the Siglum App.

The files already generated for the install are:

```text
.siglum/policy.toml
.github/workflows/siglum-gather.yml
.github/workflows/siglum-seal-enforce.yml
identity-policy.toml
siglum-setup-config.json
```

## 4. Rerun the same prevention PR

The old `tests` workflow may still echo success, but Siglum blocks the PR because
`secret-scan` produces failing evidence for the injected key. If the attacker edits
Siglum's policy or gate workflows in the PR, the Sealed gate blocks earlier with:

```text
Siglum: base-anchored inputs changed
```

## 5. Show publish protection

For a valid clean commit, release workflows should require:

```bash
siglum release-check \\
  --commit "$GITHUB_SHA" \\
  --bundle siglum-attestation.bundle.json \\
  --identity-policy identity-policy.toml
```

For the pre-Siglum bad commit, release-check fails closed because there is no valid
Siglum validation attestation for the subject.
"""


def _prevention_pr(repo: str) -> str:
    return f"""# Demo: Siglum prevents poisoned CI evidence

This is a controlled Siglum validation drill for `{repo}`.

This PR intentionally changes both application code and the workflow that produces the
old `tests` check. It demonstrates the poisoned-evidence pattern Siglum is designed to
prevent.

Expected result:

- legacy `tests` may appear green
- Siglum detects the invalid or failing evidence path
- the required `siglum` check blocks merge
- the Siglum PR comment explains the decision
- this PR remains unmerged and will be closed after validation

This is a gate-proof demo PR, not a request to merge the injected code.
"""

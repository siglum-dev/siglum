"""In-memory ForgeProvider + builders. The seam that makes the whole gate testable
without GitHub."""
from __future__ import annotations

from siglum.forge.base import CheckRun, ForgeReadError, MergeContext, RunContext
from siglum.gate.anchor import AnchoredInputs
from siglum.gate.binding import RunBinding, bind_run
from siglum.models import (
    Assessment,
    Change,
    EvidenceBundle,
    GateIdentityPolicy,
    PolicyRef,
    ValidatorAuthority,
    ValidatorResult,
)
from siglum.verdict import ValidatorStatus

H = "h" * 40
B = "b" * 40
M = "m" * 40

_DEFAULT_OIDC = {
    "iss": "https://token.actions.githubusercontent.com",
    "sub": "repo:o/r:ref:refs/heads/main",
    "actor": "org-runner",
    "repository": "o/r",
    "job_workflow_ref": "o/r/.github/workflows/siglum-seal-enforce.yml@refs/heads/main",
    "runner_environment": "github-hosted",
}


class FakeProvider:
    def __init__(self, *, run, merge, base_files=None, head_files=None, oidc=None,
                 base_readable=True, read_error=False, head_read_error=False,
                 expected_app_id=None, enforcement=None, enforcement_error=False,
                 verified_pr=None, approval_error=False):
        self._run = run
        self._merge = merge
        self._base_files = base_files or {}
        self._head_files = head_files or {}
        self._verified_pr = verified_pr
        self._oidc = oidc if oidc is not None else dict(_DEFAULT_OIDC)
        self._base_readable = base_readable
        self._read_error = read_error
        self._head_read_error = head_read_error
        self._expected_app_id = expected_app_id
        self._enforcement = enforcement
        self._enforcement_error = enforcement_error
        self._approval_error = approval_error
        self.approval_fetches = 0
        self.posted: list[CheckRun] = []
        self.comments: list[tuple[str, str]] = []

    def expected_app_id(self):
        return self._expected_app_id

    def approved_head_sha(self):
        self.approval_fetches += 1
        if self._approval_error:
            raise ForgeReadError("simulated reviews read failure")
        return self._merge.approved_sha

    def enforcement_config(self):
        if self._enforcement_error:
            raise ForgeReadError("simulated enforcement read failure")
        return self._enforcement

    def run_context(self):
        return self._run

    def merge_context(self):
        return self._merge

    def verified_pr(self):
        return self._verified_pr

    def read_base_file(self, path, *, at_sha):
        if self._read_error:
            raise ForgeReadError("simulated base read failure")
        return self._base_files.get(path)

    def read_head_file(self, path, *, at_sha):
        if self._head_read_error:
            raise ForgeReadError("simulated head read failure")
        return self._head_files.get(path)

    def base_readable(self, at_sha):
        if self._read_error:
            raise ForgeReadError("simulated base read failure")
        return self._base_readable

    def oidc_claims(self):
        return self._oidc

    def post_check_run(self, run):
        self.posted.append(run)

    def upsert_pr_comment(self, *, marker, body):
        self.comments.append((marker, body))


def run_ctx(env="github-hosted"):
    return RunContext(
        run_id="r1", run_attempt="1",
        workflow_path=".github/workflows/siglum-seal-enforce.yml",
        workflow_ref_sha="w" * 40, event_name="pull_request", runner_environment=env,
    )


def merge_ctx(head=H, candidate=None, approved=None, base_ref="refs/heads/main"):
    return MergeContext(head_sha=head, base_sha=B, merge_base=M,
                        merge_candidate_sha=candidate, approved_sha=approved, base_ref=base_ref)


def vr(vid, version="1", status=ValidatorStatus.PASSED, required=True):
    return ValidatorResult(id=vid, version=version, status=status, required=required,
                           artifact_digest="sha256:" + "a" * 64)


def authority(repo="o/r", repo_id="",
              wref="o/r/.github/workflows/siglum-seal-enforce.yml@refs/heads/main",
              runner="github-hosted"):
    """A verified run identity matching _DEFAULT_OIDC (the org-pinned gate)."""
    return ValidatorAuthority(repository=repo, repository_id=repo_id, workflow_ref=wref,
                              ref=wref.partition("@")[2], runner_class=runner)


def pinned(repo="o/r", repo_id="", path=".github/workflows/siglum-seal-enforce.yml",
           refs=("refs/heads/main",)):
    """The expected gate identity that `authority()` satisfies."""
    return GateIdentityPolicy(repository=repo, workflow_path=path, protected_refs=refs,
                              repository_id=repo_id)


def bundle(results, independence_required=False, change_author="alice", candidate=None,
           authority_=None, gate_identity=None):
    return EvidenceBundle(
        change=Change(repo="o/r", base_sha=B, head_sha=H, merge_base=M,
                      merge_candidate_sha=candidate),
        policy=PolicyRef(policy_id="default", policy_hash="p" * 64,
                         independence_required=independence_required),
        validators=tuple(results),
        validator_authority=authority_ if authority_ is not None else authority(),
        change_author=change_author,
        gate_identity=gate_identity,
    )


def anchored():
    return AnchoredInputs(
        anchored_inputs_hash="ah", anchored_file_digests=(), head_overrides_detected=()
    )


def binding_for(a: Assessment) -> RunBinding:
    ch = a.bundle.change
    return bind_run(run_ctx(), merge_ctx(head=ch.head_sha, candidate=ch.merge_candidate_sha),
                    anchored(), a.bundle)

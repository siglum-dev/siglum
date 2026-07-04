"""The gate entry point must fail closed WITH A POSTED CHECK on malformed trusted inputs.

The results artifact crosses the trust boundary (a hostile head can shape it), and the base
policy can be malformed by mistake. Neither may crash the trusted job with a bare traceback:
the PR gets a legible failing `siglum` check, exactly like a failed base read (threat model:
"each stop fails closed and posts a failing check")."""
import json

import pytest

from siglum.gate.evidence import EvidenceError
from siglum.gate.run import _load_results, main
from tests.gate.fakes import FakeProvider, H, merge_ctx, run_ctx

POLICY = b"""policy_id = "demo"
version = 1
[[validators]]
id = "secret-scan"
version = "0"
required = true
"""


# --- _load_results: malformed artifact -> EvidenceError, never a raw traceback ----


def _write(tmp_path, text: str):
    p = tmp_path / "results.json"
    p.write_text(text, encoding="utf-8")
    return p


def test_invalid_json_is_an_evidence_error(tmp_path):
    with pytest.raises(EvidenceError):
        _load_results(_write(tmp_path, "{not json"))


def test_non_list_payload_is_an_evidence_error(tmp_path):
    with pytest.raises(EvidenceError):
        _load_results(_write(tmp_path, json.dumps({"validators": "nope"})))


def test_row_missing_id_is_an_evidence_error(tmp_path):
    with pytest.raises(EvidenceError):
        _load_results(_write(tmp_path, json.dumps([{"status": "PASSED"}])))


def test_unknown_status_string_is_an_evidence_error(tmp_path):
    with pytest.raises(EvidenceError):
        _load_results(_write(tmp_path, json.dumps([{"id": "tests", "status": "GREENISH"}])))


def test_missing_results_file_is_an_evidence_error(tmp_path):
    with pytest.raises(EvidenceError):
        _load_results(tmp_path / "absent.json")


def test_a_wellformed_artifact_still_loads(tmp_path):
    p = _write(tmp_path, json.dumps([{"id": "tests", "status": "PASSED", "version": "1"}]))
    loaded = _load_results(p)
    assert loaded is not None and loaded.validators[0].id == "tests"


# --- main(): the shell posts one failing check instead of crashing ---------------


class _RunFake(FakeProvider):
    """FakeProvider plus the two reads only the run.py shell makes."""

    def changed_files(self):
        return ("x.txt",)


def _wire(monkeypatch, tmp_path, provider):
    class _Stub:
        @classmethod
        def from_env(cls, env, event, token):
            return provider

    monkeypatch.setattr("siglum.gate.run.GitHubProvider", _Stub)
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    monkeypatch.setenv("SIGLUM_WORKSPACE", str(tmp_path))


def test_main_posts_a_failure_check_on_a_malformed_results_artifact(monkeypatch, tmp_path):
    fp = _RunFake(run=run_ctx(), merge=merge_ctx(approved=H),
                  base_files={".siglum/policy.toml": POLICY})
    _wire(monkeypatch, tmp_path, fp)
    bad = _write(tmp_path, "{not json")
    assert main(["--results", str(bad)]) == 1
    assert len(fp.posted) == 1
    assert fp.posted[0].conclusion.conclusion == "failure"
    assert "trusted inputs" in fp.posted[0].conclusion.title
    assert fp.posted[0].head_sha == H


def test_main_posts_a_failure_check_on_a_malformed_base_policy(monkeypatch, tmp_path):
    fp = _RunFake(run=run_ctx(), merge=merge_ctx(approved=H),
                  base_files={".siglum/policy.toml": b"not = ["})
    _wire(monkeypatch, tmp_path, fp)
    good = _write(tmp_path, json.dumps([{"id": "secret-scan", "status": "PASSED"}]))
    assert main(["--results", str(good)]) == 1
    assert len(fp.posted) == 1
    assert fp.posted[0].conclusion.conclusion == "failure"
    assert "trusted inputs" in fp.posted[0].conclusion.title

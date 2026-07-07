import json

import pytest

from siglum import __version__
from siglum.derive import assess
from siglum.cli import main
from siglum.predicate import build_predicate
from siglum.verdict import ValidatorStatus
from tests.test_derive import _b, _v


def test_version_flag_prints_version_and_exits_zero(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert capsys.readouterr().out.strip() == f"siglum {__version__}"


def test_policy_lint_outputs_json(tmp_path, capsys):
    policy = tmp_path / "policy.toml"
    policy.write_text(
        """
[[validators]]
id = "secret-scan"
version = "0"
""",
        encoding="utf-8",
    )
    assert main(["policy", "lint", str(policy), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["required_validators"] == ["secret-scan"]
    assert ".siglum/policy.toml" in payload["anchored_paths"]


def test_audit_from_local_config_returns_findings(tmp_path, capsys):
    config = tmp_path / "repo.json"
    config.write_text(
        json.dumps(
            {
                "repo": "o/r",
                "required_checks": [
                    {"context": "tests", "enforcement": "commit_status", "source_restricted": False}
                ],
                "workflows": [],
                "admin_bypass_allowed": False,
            }
        ),
        encoding="utf-8",
    )
    assert main(["audit", "--config", str(config), "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"][0]["code"] == "SPOOFABLE_CHECK"


def test_release_check_requires_explicit_unsigned_mode(tmp_path, capsys):
    att = tmp_path / "attestation.json"
    att.write_text(
        json.dumps(build_predicate(assess(_b([_v(ValidatorStatus.PASSED)])))),
        encoding="utf-8",
    )
    assert main(["release-check", "--commit", "h" * 40, "--attestation", str(att)]) == 1
    assert (
        main(
            [
                "release-check",
                "--commit",
                "h" * 40,
                "--attestation",
                str(att),
                "--allow-unsigned-predicate",
            ]
        )
        == 0
    )
    assert "release ok" in capsys.readouterr().out


def test_demo_scaffold_cli_writes_fixture(tmp_path, capsys):
    out = tmp_path / "demo"
    assert main(["demo", "scaffold", "--out", str(out), "--repo", "acme/payments"]) == 0
    assert (out / "demo" / "README.md").exists()
    assert (out / "siglum-audit-config.json").exists()
    assert "demo scaffolded" in capsys.readouterr().out


def test_setup_check_local_cli(tmp_path, capsys):
    out = tmp_path / "demo"
    assert main(["demo", "scaffold", "--out", str(out)]) == 0
    capsys.readouterr()
    assert main(["setup", "check", "--local", str(out), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ready"] is True


def test_setup_check_malformed_app_id_env_fails_closed(tmp_path, monkeypatch):
    # The runtime rejects a non-numeric Siglum App id; the preflight must not be more lenient by
    # silently treating a malformed env var as "no app id" and running the weaker check.
    out = tmp_path / "demo"
    assert main(["demo", "scaffold", "--out", str(out)]) == 0
    monkeypatch.setenv("SIGLUM_GITHUB_APP_ID", "not-a-number")
    with pytest.raises(SystemExit):
        main(["setup", "check", "--local", str(out)])


def test_setup_check_app_id_env_is_consumed(tmp_path, monkeypatch):
    # The scaffold's required check is source-restricted but carries no app id, so a supplied app
    # id must make the mirror fail; with the env unset the weaker check passes. This proves the
    # env value is actually used, not ignored.
    out = tmp_path / "demo"
    assert main(["demo", "scaffold", "--out", str(out)]) == 0
    monkeypatch.setenv("SIGLUM_GITHUB_APP_ID", "42")
    assert main(["setup", "check", "--local", str(out)]) == 1
    monkeypatch.delenv("SIGLUM_GITHUB_APP_ID", raising=False)
    assert main(["setup", "check", "--local", str(out)]) == 0


def test_release_check_missing_bundle_reports_cli_error(tmp_path, capsys):
    result = main([
        "release-check",
        "--commit",
        "h" * 40,
        "--bundle",
        str(tmp_path / "missing.bundle.json"),
        "--identity-policy",
        str(tmp_path / "identity-policy.toml"),
    ])

    assert result == 1
    assert "cannot read" in capsys.readouterr().err


def test_gate_run_forwards_results_to_gate_runner(monkeypatch, tmp_path):
    seen = []

    def fake_gate_run(argv):
        seen.extend(argv)
        return 7

    monkeypatch.setattr("siglum.cli.gate_run_main", fake_gate_run)
    results = tmp_path / "results.json"

    assert main(["gate", "run", "--results", str(results)]) == 7
    assert seen == ["--results", str(results)]

import json

from siglum.validators.run import main


def test_validator_runner_writes_results(tmp_path):
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    out = tmp_path / "results.json"
    assert main(["--workspace", str(tmp_path), "--out", str(out)]) == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["validators"][0]["id"] == "secret-scan"
    assert payload["validators"][0]["status"] == "PASSED"
    # The untrusted gather no longer reports head digests; the trusted gate derives
    # them itself at the head sha. A security-relevant field never crosses the trust boundary.
    assert "head_digests" not in payload


def test_validator_runner_fails_on_secret(tmp_path):
    (tmp_path / "app.py").write_text("key = 'AKIA0123456789ABCDEF'\n", encoding="utf-8")
    out = tmp_path / "results.json"
    assert main(["--workspace", str(tmp_path), "--out", str(out)]) == 1
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["validators"][0]["status"] == "FAILED"

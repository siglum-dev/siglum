import pytest

from siglum.audit import github


def test_fetch_payload_rejects_missing_repo(monkeypatch):
    monkeypatch.setattr(github, "_api_get", lambda _url, _token: None)
    with pytest.raises(github.GitHubFetchError, match="cannot read GitHub repo"):
        github._fetch_payload("o/missing", "token")


def test_forbidden_protection_read_is_flagged_not_treated_as_absent(monkeypatch):
    # A 403 on the branch-protection endpoint (non-admin token) must surface as
    # "protection unreadable", never as "no protection configured".
    def fake_get(url, _token):
        if url.endswith("/repos/o/r"):
            return {"id": 7, "default_branch": "main"}
        if "/protection" in url:
            raise github.GitHubForbiddenError(f"GET {url} returned 403")
        return None

    monkeypatch.setattr(github, "_api_get", fake_get)
    payload = github._fetch_payload("o/r", "token")
    assert payload["protection_readable"] is False
    assert payload["protected"] is False


def test_forbidden_rulesets_read_also_marks_protection_unreadable(monkeypatch):
    # Rulesets are the other source of protection facts; if they cannot be read either,
    # the audit must not claim the branch is unprotected.
    def fake_get(url, _token):
        if url.endswith("/repos/o/r"):
            return {"id": 7, "default_branch": "main"}
        if "/protection" in url:
            return None  # genuinely no classic protection (404)
        if url.endswith("/rulesets"):
            raise github.GitHubForbiddenError(f"GET {url} returned 403")
        return None

    monkeypatch.setattr(github, "_api_get", fake_get)
    payload = github._fetch_payload("o/r", "token")
    assert payload["protection_readable"] is False


def test_readable_absent_protection_stays_a_genuine_absence(monkeypatch):
    def fake_get(url, _token):
        if url.endswith("/repos/o/r"):
            return {"id": 7, "default_branch": "main"}
        return None  # 404 everywhere: no protection, no rulesets

    monkeypatch.setattr(github, "_api_get", fake_get)
    payload = github._fetch_payload("o/r", "token")
    assert payload["protection_readable"] is True
    assert payload["protected"] is False

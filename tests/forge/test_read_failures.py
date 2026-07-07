"""A base read must fail closed on permission/rate-limit/server errors. Only a genuine
404 (file not found) is 'absent'. The disposition of an HTTP status and the decoding of a
contents response are pure and tested here; the network call itself is the seam."""
import base64

import pytest

from siglum.forge.base import ForgeReadError
from siglum.forge.github import _file_bytes_from_contents, _read_disposition


def test_404_is_absent():
    assert _read_disposition(404) == "absent"


def test_permission_ratelimit_and_server_errors_fail_closed():
    for code in (401, 403, 429, 500, 502, 503):
        assert _read_disposition(code) == "error"


def test_absent_contents_is_none():
    # _get surfaces a 404 as None; that is the only genuine absence.
    assert _file_bytes_from_contents(None) is None


def test_a_directory_listing_fails_closed():
    # GitHub returns a JSON list (not a file object) when the path is a directory.
    with pytest.raises(ForgeReadError):
        _file_bytes_from_contents([{"name": "policy.toml"}])


def test_a_non_file_object_fails_closed():
    # A submodule or symlink is a 200 dict without "content": an anomaly, not an absence.
    with pytest.raises(ForgeReadError):
        _file_bytes_from_contents({"type": "submodule", "sha": "abc"})


def test_a_real_file_decodes():
    payload = {"encoding": "base64", "content": base64.b64encode(b"version = 1\n").decode()}
    assert _file_bytes_from_contents(payload) == b"version = 1\n"


def test_a_large_file_with_encoding_none_fails_closed():
    # The contents API returns encoding "none" + empty content for files >1MB. Decoding that as
    # b"" would make a changed large anchored file hash equal to base and hide a head override
    # so a non-base64 encoding fails closed rather than reading as empty.
    with pytest.raises(ForgeReadError):
        _file_bytes_from_contents({"size": 3991446, "encoding": "none", "content": ""})

"""The gate must not silently fall back to a weaker default policy when the base is
unreadable. A genuine 404 (policy absent) is only trusted after confirming the base is
readable; a read failure fails closed."""
import pytest

from siglum.forge.base import ForgeReadError
from siglum.gate.run import _load_base_policy
from siglum.policy import default_policy
from tests.gate.fakes import FakeProvider, run_ctx, merge_ctx, B

POLICY = b"""policy_id = "demo"
version = 1
[[validators]]
id = "secret-scan"
version = "0"
required = true
"""


def _fp(**kw):
    return FakeProvider(run=run_ctx(), merge=merge_ctx(), **kw)


def test_loads_the_base_policy_when_present():
    p = _load_base_policy(_fp(base_files={".siglum/policy.toml": POLICY}), B, None)
    assert p.policy_id == "demo"


def test_uses_secure_default_when_policy_absent_but_base_is_readable():
    p = _load_base_policy(_fp(base_files={}, base_readable=True), B, None)
    assert p.policy_id == default_policy().policy_id


def test_fails_closed_when_policy_absent_and_base_is_unreadable():
    with pytest.raises(ForgeReadError):
        _load_base_policy(_fp(base_files={}, base_readable=False), B, None)


def test_fails_closed_when_the_base_read_errors():
    with pytest.raises(ForgeReadError):
        _load_base_policy(_fp(read_error=True), B, None)

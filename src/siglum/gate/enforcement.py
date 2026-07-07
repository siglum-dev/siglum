"""The gate's runtime enforcement self-audit: pure logic over a fetched RepoConfig.

Runtime identity checks prove the verdict was produced by the org-pinned gate. They
cannot see whether the operator actually wired the gate into branch protection. This closes
that gap: the gate fails closed unless its own `siglum` check is a required status check on a
protected branch AND source-restricted to the Siglum App specifically, so a green check or a
signed attestation can never outrun proof that the gate is really enforced.
"""
from __future__ import annotations

from siglum.audit.model import RepoConfig


def enforcement_mismatch(
    config: RepoConfig, *, check_name: str, expected_app_id: int
) -> str | None:
    """None iff the named check is required on a protected branch and restricted to our App;
    else a human reason the enforcement is not real."""
    if not config.protected:
        if not config.protection_readable:
            return (
                "the branch-protection configuration could not be read (HTTP 403), so the "
                "gate cannot verify its own enforcement. Grant the Siglum App the repository "
                "Administration read permission, or configure the required check through a "
                "ruleset, which is readable without it."
            )
        return "the default branch is not protected by branch protection or a ruleset"
    matching = [c for c in config.required_checks if c.context == check_name]
    if not matching:
        return f"the {check_name!r} check is not a required status check on the protected branch"
    if not any(c.source_restricted and c.app_id == expected_app_id for c in matching):
        return (
            f"the {check_name!r} check is not source-restricted to the Siglum App "
            f"(expected app id {expected_app_id})"
        )
    return None

from siglum.forge.base import CheckConclusion
from siglum.gate.comment import SIGLUM_COMMENT_MARKER, format_authority, render_pr_comment
from siglum.models import ValidatorAuthority
from siglum.verdict import Independence


def _authority():
    return ValidatorAuthority(
        repository="o/r", repository_id="123",
        workflow_ref="o/r/.github/workflows/siglum-seal-enforce.yml@refs/heads/main",
        ref="refs/heads/main", runner_class="github-hosted",
    )


def test_format_authority_shows_the_verified_run_and_independence():
    section = format_authority(_authority(), independence=Independence.SATISFIED)
    assert "o/r" in section
    assert ".github/workflows/siglum-seal-enforce.yml" in section
    assert "refs/heads/main" in section
    assert "satisfied" in section.lower()


def test_format_authority_flags_unmet_independence():
    section = format_authority(_authority(), independence=Independence.UNMET)
    assert "UNMET" in section


def test_comment_includes_the_authority_section_when_provided():
    body = render_pr_comment(
        CheckConclusion("success", "Siglum: merge eligible", "all required evidence passed"),
        authority_section=format_authority(_authority(), independence=Independence.SATISFIED),
    )
    assert "Verified gate run" in body
    assert ".github/workflows/siglum-seal-enforce.yml" in body


def test_comment_renders_blocked_outcome_and_next_step():
    body = render_pr_comment(
        CheckConclusion(
            "failure",
            "Siglum: base-anchored inputs changed",
            "head changed gate-critical input(s): .siglum/policy.toml",
        )
    )
    assert "Outcome:** blocked" in body
    assert ".siglum/policy.toml" in body
    assert "separate trusted update" in body


def test_marker_is_stable():
    assert SIGLUM_COMMENT_MARKER == "<!-- siglum:gate-comment:v1 -->"

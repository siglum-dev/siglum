"""Gate-level errors. A refusal is a fail-closed stop (the gate could not establish a
trustworthy verdict), distinct from a clean FAIL verdict."""
from __future__ import annotations


class GateRefused(Exception):
    """The gate refuses to produce a verdict (self-hosted runner, TOCTOU, etc.)."""

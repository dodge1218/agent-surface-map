"""Scanner compatibility facade."""

from __future__ import annotations

from surface_map import (  # noqa: F401
    REPORT_VERSION,
    agent_context,
    parse_gemma_content,
    review_report,
    safe_excerpt,
    safe_install_context,
    scan,
    validate_install_plan,
)

__all__ = [
    "REPORT_VERSION",
    "agent_context",
    "parse_gemma_content",
    "review_report",
    "safe_excerpt",
    "safe_install_context",
    "scan",
    "validate_install_plan",
]

"""win-cua-guard: DPI-aware Windows Computer Use CLI & MCP server with fail-closed safety rails."""

from .policy import (
    BASELINE_BLOCKED_PATTERNS,
    GuardPolicy,
    SafetyBlockedError,
    load_blocklist_config,
)

__all__ = [
    "BASELINE_BLOCKED_PATTERNS",
    "GuardPolicy",
    "SafetyBlockedError",
    "load_blocklist_config",
]
__version__ = "0.1.0"

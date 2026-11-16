#!/usr/bin/env python3
"""FastMCP server exposing guarded Windows desktop inspection and CUA tools."""

from __future__ import annotations

import argparse
import json
from types import SimpleNamespace

from . import cli
from .policy import SafetyBlockedError, load_blocklist_config

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover - allows stdlib-only unit testing when mcp is optional
    FastMCP = None  # type: ignore[assignment]


class _NoopMCP:
    def __init__(self, name: str) -> None:
        self.name = name

    def tool(self):
        def _dec(fn):
            return fn

        return _dec

    def run(self) -> None:
        raise RuntimeError(
            "The 'mcp' package is required to run the MCP server. Install with: pip install mcp"
        )


mcp = FastMCP("win-cua-guard") if FastMCP is not None else _NoopMCP("win-cua-guard")
_ACTIVE_BLOCKLIST: str | None = None


def _get_policy(blocklist: str | None = None):
    return load_blocklist_config(blocklist or _ACTIVE_BLOCKLIST)


def _run_guarded(fn, *args) -> str:
    try:
        return json.dumps(fn(*args), ensure_ascii=False, indent=2)
    except SafetyBlockedError as exc:
        return json.dumps({"ok": False, "blocked": True, "error": str(exc)}, ensure_ascii=False)
    except Exception as exc:
        return json.dumps({"ok": False, "blocked": False, "error": str(exc)}, ensure_ascii=False)


@mcp.tool()
def screen_info() -> str:
    """Return physical monitors, virtual desktop bounds, DPI awareness mode, and Win32 desktop env."""
    return _run_guarded(cli.cmd_screen_info, SimpleNamespace(), cli.DPI_MODE, _get_policy())


@mcp.tool()
def list_windows(filter_pattern: str | None = None, include_untitled: bool = False) -> str:
    """List visible top-level desktop windows (blocked inside isolated sandbox desktops)."""
    ns = SimpleNamespace(filter=filter_pattern, include_untitled=include_untitled)
    return _run_guarded(cli.cmd_windows, ns, cli.DPI_MODE, _get_policy())


@mcp.tool()
def screenshot_with_grid(
    out_path: str,
    title_pattern: str | None = None,
    hwnd: int | None = None,
    grid: bool = True,
    synthetic_selftest: bool = False,
) -> str:
    """Capture desktop/window screenshot with 50/100px global coordinate ruler grid."""
    ns = SimpleNamespace(
        out=out_path,
        title=title_pattern,
        hwnd=hwnd,
        grid=grid,
        synthetic_selftest=synthetic_selftest,
    )
    return _run_guarded(cli.cmd_screenshot, ns, cli.DPI_MODE, _get_policy())


@mcp.tool()
def uia_find(
    title_pattern: str | None = None,
    hwnd: int | None = None,
    name_pattern: str | None = None,
    automation_id: str | None = None,
    control_type: str | None = None,
    max_results: int = 50,
) -> str:
    """Query .NET UI Automation elements on a window or desktop."""
    ns = SimpleNamespace(
        title=title_pattern,
        hwnd=hwnd,
        name=name_pattern,
        automation_id=automation_id,
        control_type=control_type,
        max_results=max_results,
    )
    return _run_guarded(cli.cmd_uia_find, ns, cli.DPI_MODE, _get_policy())


@mcp.tool()
def focus_window(title_pattern: str | None = None, hwnd: int | None = None) -> str:
    """Bring a permitted window to the foreground after safety validation."""
    ns = SimpleNamespace(title=title_pattern, hwnd=hwnd)
    return _run_guarded(cli.cmd_focus, ns, cli.DPI_MODE, _get_policy())


@mcp.tool()
def guarded_click(
    x: int,
    y: int,
    button: str = "left",
    clicks: int = 1,
    dry_run: bool = False,
) -> str:
    """Click at virtual-screen coordinates after verifying target HWND and desktop safety."""
    ns = SimpleNamespace(
        x=x, y=y, button=button, clicks=clicks, move_duration=0.08, dry_run=dry_run
    )
    return _run_guarded(cli.cmd_click, ns, cli.DPI_MODE, _get_policy())


@mcp.tool()
def guarded_type_text(text: str, interval: float = 0.01) -> str:
    """Type Unicode text via Win32 SendInput after checking foreground window and text safety."""
    ns = SimpleNamespace(text=text, interval=interval)
    return _run_guarded(cli.cmd_type_text, ns, cli.DPI_MODE, _get_policy())


@mcp.tool()
def guarded_hotkey(keys: str) -> str:
    """Press a key combination (e.g. 'ctrl,s') after safety checks."""
    ns = SimpleNamespace(keys=keys)
    return _run_guarded(cli.cmd_hotkey, ns, cli.DPI_MODE, _get_policy())


def main(argv: list[str] | None = None) -> None:
    global _ACTIVE_BLOCKLIST
    parser = argparse.ArgumentParser(description="Run win-cua-guard FastMCP server")
    parser.add_argument("--blocklist", default=None, help="Path to YAML/JSON blocklist file")
    args = parser.parse_args(argv)
    _ACTIVE_BLOCKLIST = args.blocklist
    mcp.run()


if __name__ == "__main__":
    main()

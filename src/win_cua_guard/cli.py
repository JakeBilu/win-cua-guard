#!/usr/bin/env python3
"""Windows DPI-aware Computer Use (CUA) CLI with fail-closed safety guardrails."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .policy import GuardPolicy, SafetyBlockedError, load_blocklist_config


def init_dpi_awareness() -> str:
    """Enable Per-Monitor v2 DPI awareness before PyAutoGUI locks SYSTEM_AWARE."""
    if os.name != "nt":
        return "NON_WINDOWS"
    import ctypes.wintypes as wintypes

    try:
        # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 == -4
        user32 = ctypes.windll.user32
        user32.SetProcessDpiAwarenessContext.argtypes = [ctypes.c_void_p]
        user32.SetProcessDpiAwarenessContext.restype = wintypes.BOOL
        if user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4)):
            return "PER_MONITOR_AWARE_V2"
    except Exception:
        pass
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
        return "PER_MONITOR_AWARE"
    except Exception:
        pass
    try:
        ctypes.windll.user32.SetProcessDPIAware()
        return "SYSTEM_AWARE"
    except Exception:
        return "UNAWARE"


DPI_MODE = init_dpi_awareness()


def _win32():
    if os.name != "nt":
        raise RuntimeError("Win32 desktop automation requires Windows.")
    import pyautogui
    import win32api
    import win32con
    import win32gui
    import win32process
    import win32service

    pyautogui.FAILSAFE = True
    pyautogui.PAUSE = 0.05
    return pyautogui, win32api, win32con, win32gui, win32process, win32service


def _pil():
    from PIL import Image, ImageDraw, ImageFont, ImageGrab

    return Image, ImageDraw, ImageFont, ImageGrab


def get_desktop_environment() -> dict[str, Any]:
    """Inspect current Win32 WindowStation and Desktop names."""
    if os.name != "nt":
        return {
            "window_station": "non-windows",
            "desktop": "non-windows",
            "is_isolated_sandbox_desktop": True,
        }
    _, _, win32con, _, _, win32service = _win32()
    winsta_name = "unknown"
    desktop_name = "unknown"
    try:
        ws = win32service.GetProcessWindowStation()
        winsta_name = str(win32service.GetUserObjectInformation(ws, win32con.UOI_NAME))
    except Exception:
        pass
    try:
        tid = ctypes.windll.kernel32.GetCurrentThreadId()
        dt = ctypes.windll.user32.GetThreadDesktop(tid)
        desktop_name = str(win32service.GetUserObjectInformation(dt, win32con.UOI_NAME))
    except Exception:
        pass
    return {
        "window_station": winsta_name,
        "desktop": desktop_name,
        "is_isolated_sandbox_desktop": desktop_name.lower() != "default",
    }


def _assert_interactive_desktop(policy: GuardPolicy) -> dict[str, Any]:
    env = get_desktop_environment()
    policy.assert_desktop_safe(env)
    return env


def _get_process_name(pid: int) -> str:
    if not pid:
        return ""
    _, win32api, win32con, _, win32process, _ = _win32()
    handle = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    try:
        exe_path = win32process.GetModuleFileNameEx(handle, 0)
        return os.path.basename(exe_path)
    except Exception:
        return ""
    finally:
        win32api.CloseHandle(handle)


def _describe_hwnd(hwnd: int) -> dict[str, Any]:
    _, _, _, win32gui, win32process, _ = _win32()
    title = win32gui.GetWindowText(hwnd) or ""
    cls = win32gui.GetClassName(hwnd) or ""
    rect = list(win32gui.GetWindowRect(hwnd))
    _, pid = win32process.GetWindowThreadProcessId(hwnd)
    exe = _get_process_name(pid)
    return {
        "hwnd": hwnd,
        "hwnd_hex": hex(hwnd),
        "title": title,
        "class_name": cls,
        "pid": pid,
        "exe": exe,
        "rect": rect,
        "width": max(0, rect[2] - rect[0]),
        "height": max(0, rect[3] - rect[1]),
        "minimized": bool(win32gui.IsIconic(hwnd)),
        "active": hwnd == win32gui.GetForegroundWindow(),
    }


def _root_hwnd_at_point(x: int, y: int) -> int:
    _, _, win32con, win32gui, _, _ = _win32()
    hwnd = win32gui.WindowFromPoint((int(x), int(y)))
    if not hwnd:
        return 0
    root = win32gui.GetAncestor(hwnd, win32con.GA_ROOT)
    return int(root or hwnd)


def _assert_hwnd_safe(hwnd: int, context: str, policy: GuardPolicy) -> None:
    _, _, _, win32gui, _, _ = _win32()
    if not hwnd or not win32gui.IsWindow(hwnd):
        return
    info = _describe_hwnd(hwnd)
    policy.assert_window_info_safe(info, context)


def _assert_input_safe(
    policy: GuardPolicy,
    target_hwnd: int | None = None,
    points: list[tuple[int, int]] | None = None,
    text_args: list[tuple[str, str | None]] | None = None,
) -> None:
    for label, val in text_args or []:
        policy.assert_text_safe(label, val)
    _assert_interactive_desktop(policy)
    _, _, _, win32gui, _, _ = _win32()
    fg = win32gui.GetForegroundWindow()
    _assert_hwnd_safe(fg, "foreground_window", policy)
    if target_hwnd:
        _assert_hwnd_safe(target_hwnd, "target_window", policy)
    for idx, (px, py) in enumerate(points or []):
        pt_hwnd = _root_hwnd_at_point(px, py)
        _assert_hwnd_safe(pt_hwnd, f"point[{idx}]_window", policy)


def _resolve_hwnd(hwnd: int | None, title_pattern: str | None) -> int:
    _, _, _, win32gui, _, _ = _win32()
    if hwnd:
        if not win32gui.IsWindow(hwnd):
            raise ValueError(f"Invalid HWND: {hwnd}")
        return hwnd
    if not title_pattern:
        raise ValueError("Either --hwnd or --title is required.")
    rx = re.compile(title_pattern, re.IGNORECASE)
    matches: list[int] = []

    def _enum_cb(cand: int, _: Any) -> None:
        if win32gui.IsWindowVisible(cand):
            title = win32gui.GetWindowText(cand) or ""
            if rx.search(title):
                matches.append(cand)

    win32gui.EnumWindows(_enum_cb, None)
    if not matches:
        raise ValueError(f"No visible window matched title pattern: {title_pattern!r}")
    return matches[0]


def draw_coordinate_grid(img: Any, origin_x: int, origin_y: int) -> Any:
    """Overlay semi-transparent 50px/100px global-coordinate ruler grid."""
    Image, ImageDraw, ImageFont, _ = _pil()
    base = img.convert("RGBA")
    overlay = Image.new("RGBA", base.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    font = ImageFont.load_default()
    w, h = base.size

    minor_step = 50
    major_step = 100
    for x in range(0, w, minor_step):
        is_major = (x % major_step) == 0
        color = (255, 64, 64, 150) if is_major else (255, 180, 0, 70)
        draw.line([(x, 0), (x, h)], fill=color, width=1)
        if is_major and x > 0:
            label = f"x={origin_x + x}"
            draw.rectangle([x + 2, 2, x + 54, 15], fill=(0, 0, 0, 175))
            draw.text((x + 4, 3), label, fill=(255, 230, 120, 255), font=font)

    for y in range(0, h, minor_step):
        is_major = (y % major_step) == 0
        color = (255, 64, 64, 150) if is_major else (255, 180, 0, 70)
        draw.line([(0, y), (w, y)], fill=color, width=1)
        if is_major and y > 0:
            label = f"y={origin_y + y}"
            draw.rectangle([2, y + 2, 54, y + 15], fill=(0, 0, 0, 175))
            draw.text((4, y + 3), label, fill=(255, 230, 120, 255), font=font)

    hdr = f"Origin=({origin_x},{origin_y}) Size={w}x{h} Step=50/100px"
    draw.rectangle([4, h - 20, 290, h - 4], fill=(0, 0, 0, 190))
    draw.text((8, h - 17), hdr, fill=(140, 255, 170, 255), font=font)
    return Image.alpha_composite(base, overlay).convert("RGB")


def build_synthetic_selftest_canvas(desktop_env: dict[str, Any]) -> Any:
    """Create a 1280x720 calibration canvas for verifying grid overlays inside sandboxes."""
    Image, ImageDraw, ImageFont, _ = _pil()
    img = Image.new("RGB", (1280, 720), (28, 32, 38))
    draw = ImageDraw.Draw(img)
    font = ImageFont.load_default()
    draw.rectangle([120, 90, 620, 610], outline=(100, 185, 255), width=2, fill=(38, 46, 56))
    draw.rectangle([660, 90, 1160, 390], outline=(140, 230, 160), width=2, fill=(36, 48, 44))
    draw.rectangle([660, 420, 1160, 610], outline=(245, 195, 100), width=2, fill=(48, 44, 36))
    draw.text(
        (140, 110),
        f"win-cua-guard Synthetic Grid Self-Test | {desktop_env['window_station']}\\{desktop_env['desktop']}",
        fill=(230, 240, 250),
        font=font,
    )
    draw.text((680, 110), "Sample Panel Region A (660,90)-(1160,390)", fill=(200, 245, 210), font=font)
    draw.text((680, 440), "Sample Zone B (660,420)-(1160,610)", fill=(255, 225, 165), font=font)
    return img


def _send_unicode_text(text: str, interval: float = 0.01) -> None:
    """Send arbitrary Unicode text cleanly via Win32 SendInput KEYEVENTF_UNICODE."""
    import ctypes.wintypes as wintypes

    pyautogui, _, _, _, _, _ = _win32()
    KEYEVENTF_UNICODE = 0x0004
    KEYEVENTF_KEYUP = 0x0002
    INPUT_KEYBOARD = 1

    class KEYBDINPUT(ctypes.Structure):
        _fields_ = [
            ("wVk", wintypes.WORD),
            ("wScan", wintypes.WORD),
            ("dwFlags", wintypes.DWORD),
            ("time", wintypes.DWORD),
            ("dwExtraInfo", ctypes.c_size_t),
        ]

    class _INPUT_UNION(ctypes.Union):
        _fields_ = [("ki", KEYBDINPUT), ("pad", ctypes.c_byte * 28)]

    class INPUT(ctypes.Structure):
        _fields_ = [("type", wintypes.DWORD), ("union", _INPUT_UNION)]

    user32 = ctypes.windll.user32
    for ch in text:
        if ch == "\n":
            pyautogui.press("enter")
            continue
        if ch == "\t":
            pyautogui.press("tab")
            continue
        code = ord(ch)
        down = INPUT(
            type=INPUT_KEYBOARD,
            union=_INPUT_UNION(ki=KEYBDINPUT(0, code, KEYEVENTF_UNICODE, 0, 0)),
        )
        up = INPUT(
            type=INPUT_KEYBOARD,
            union=_INPUT_UNION(
                ki=KEYBDINPUT(0, code, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP, 0, 0)
            ),
        )
        arr = (INPUT * 2)(down, up)
        user32.SendInput(2, ctypes.byref(arr), ctypes.sizeof(INPUT))
        if interval > 0:
            time.sleep(interval)


def cmd_screen_info(_: argparse.Namespace, dpi_mode: str, _policy: GuardPolicy) -> dict[str, Any]:
    _, win32api, win32con, _, _, _ = _win32()
    monitors = []
    for idx, (hmon, _, rc) in enumerate(win32api.EnumDisplayMonitors()):
        info = win32api.GetMonitorInfo(hmon)
        monitors.append(
            {
                "index": idx,
                "device": info.get("Device", ""),
                "primary": bool(info.get("Flags", 0) & 1),
                "rect": list(rc),
                "work_rect": list(info.get("Work", rc)),
                "width": rc[2] - rc[0],
                "height": rc[3] - rc[1],
            }
        )
    vx = win32api.GetSystemMetrics(win32con.SM_XVIRTUALSCREEN)
    vy = win32api.GetSystemMetrics(win32con.SM_YVIRTUALSCREEN)
    vw = win32api.GetSystemMetrics(win32con.SM_CXVIRTUALSCREEN)
    vh = win32api.GetSystemMetrics(win32con.SM_CYVIRTUALSCREEN)
    try:
        cursor_pos: list[int] | None = list(win32api.GetCursorPos())
    except Exception:
        cursor_pos = None
    return {
        "ok": True,
        "dpi_awareness": dpi_mode,
        "desktop_env": get_desktop_environment(),
        "virtual_screen": {"left": vx, "top": vy, "width": vw, "height": vh},
        "monitors": monitors,
        "cursor_pos": cursor_pos,
    }


def cmd_windows(args: argparse.Namespace, _: str, policy: GuardPolicy) -> dict[str, Any]:
    _assert_interactive_desktop(policy)
    _, _, _, win32gui, _, _ = _win32()
    rx = re.compile(args.filter, re.IGNORECASE) if args.filter else None
    rows: list[dict[str, Any]] = []

    def _cb(hwnd: int, _: Any) -> None:
        if not win32gui.IsWindowVisible(hwnd):
            return
        info = _describe_hwnd(hwnd)
        if not info["title"].strip() and not args.include_untitled:
            return
        if rx and not (rx.search(info["title"]) or rx.search(info["exe"])):
            return
        rows.append(info)

    win32gui.EnumWindows(_cb, None)
    return {"ok": True, "count": len(rows), "windows": rows}


def cmd_focus(args: argparse.Namespace, _: str, policy: GuardPolicy) -> dict[str, Any]:
    policy.assert_text_safe("focus.title_pattern", args.title)
    _assert_interactive_desktop(policy)
    pyautogui, _, win32con, win32gui, _, _ = _win32()
    hwnd = _resolve_hwnd(args.hwnd, args.title)
    _assert_hwnd_safe(hwnd, "focus", policy)

    if win32gui.IsIconic(hwnd):
        win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
    else:
        win32gui.ShowWindow(hwnd, win32con.SW_SHOW)

    try:
        win32gui.SetForegroundWindow(hwnd)
    except Exception:
        pyautogui.press("alt")
        time.sleep(0.05)
        win32gui.SetForegroundWindow(hwnd)

    time.sleep(0.15)
    fg = win32gui.GetForegroundWindow()
    return {
        "ok": True,
        "focused": fg == hwnd,
        "target": _describe_hwnd(hwnd),
        "foreground_hwnd": fg,
    }


def cmd_screenshot(args: argparse.Namespace, _: str, policy: GuardPolicy) -> dict[str, Any]:
    policy.assert_text_safe("screenshot.title_pattern", args.title)
    out_path = Path(args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    desktop_env = get_desktop_environment()

    if args.synthetic_selftest:
        img = build_synthetic_selftest_canvas(desktop_env)
        origin_x, origin_y = 0, 0
        bbox = [0, 0, img.width, img.height]
    else:
        _assert_interactive_desktop(policy)
        _, win32api, win32con, win32gui, _, _ = _win32()
        _, _, _, ImageGrab = _pil()
        if args.hwnd or args.title:
            hwnd = _resolve_hwnd(args.hwnd, args.title)
            _assert_hwnd_safe(hwnd, "screenshot", policy)
            rect = win32gui.GetWindowRect(hwnd)
            if rect[2] <= rect[0] or rect[3] <= rect[1]:
                raise ValueError(f"Window {hwnd} has zero area rect={rect}")
            img = ImageGrab.grab(bbox=rect, all_screens=True)
            origin_x, origin_y = rect[0], rect[1]
            bbox = list(rect)
        else:
            img = ImageGrab.grab(all_screens=True)
            origin_x = win32api.GetSystemMetrics(win32con.SM_XVIRTUALSCREEN)
            origin_y = win32api.GetSystemMetrics(win32con.SM_YVIRTUALSCREEN)
            bbox = [origin_x, origin_y, origin_x + img.width, origin_y + img.height]

    if args.grid:
        img = draw_coordinate_grid(img, origin_x, origin_y)

    img.save(out_path, format="PNG")
    raw = out_path.read_bytes()
    return {
        "ok": True,
        "path": str(out_path),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "width": img.width,
        "height": img.height,
        "bbox": bbox,
        "grid": bool(args.grid),
        "synthetic_selftest": bool(args.synthetic_selftest),
        "desktop_env": desktop_env,
    }


def cmd_uia_find(args: argparse.Namespace, _: str, policy: GuardPolicy) -> dict[str, Any]:
    policy.assert_text_safe("uia.title_pattern", args.title)
    policy.assert_text_safe("uia.name_pattern", args.name)
    _assert_interactive_desktop(policy)
    target_hwnd = 0
    if args.hwnd or args.title:
        target_hwnd = _resolve_hwnd(args.hwnd, args.title)
        _assert_hwnd_safe(target_hwnd, "uia_find", policy)

    ps_script = r"""
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$hwnd = [int]$env:CUA_UIA_HWND
$nameRx = $env:CUA_UIA_NAME
$aidRx = $env:CUA_UIA_AID
$ctypeRx = $env:CUA_UIA_CTYPE
$maxRes = [int]$env:CUA_UIA_MAX

$root = if ($hwnd -gt 0) {
    [System.Windows.Automation.AutomationElement]::FromHandle([IntPtr]$hwnd)
} else {
    [System.Windows.Automation.AutomationElement]::RootElement
}
if ($null -eq $root) { throw "Root AutomationElement is null" }

$cond = [System.Windows.Automation.Condition]::TrueCondition
$els = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $cond)
$out = New-Object System.Collections.Generic.List[object]
foreach ($el in $els) {
    if ($out.Count -ge $maxRes) { break }
    $cur = $el.Current
    $nm = [string]$cur.Name
    $aid = [string]$cur.AutomationId
    $ct = [string]$cur.ControlType.ProgrammaticName
    if ($nameRx -and ($nm -notmatch $nameRx)) { continue }
    if ($aidRx -and ($aid -notmatch $aidRx)) { continue }
    if ($ctypeRx -and ($ct -notmatch $ctypeRx)) { continue }
    $r = $cur.BoundingRectangle
    if ([double]::IsInfinity($r.Width) -or [double]::IsNaN($r.Width)) { continue }
    $out.Add([pscustomobject]@{
        name = $nm
        automation_id = $aid
        control_type = $ct
        class_name = [string]$cur.ClassName
        rect = @([int]$r.Left, [int]$r.Top, [int]$r.Right, [int]$r.Bottom)
        center = @([int]($r.Left + $r.Width / 2), [int]($r.Top + $r.Height / 2))
        is_enabled = [bool]$cur.IsEnabled
        is_offscreen = [bool]$cur.IsOffscreen
    })
}
$out | ConvertTo-Json -Depth 4 -Compress
"""
    env = os.environ.copy()
    env["CUA_UIA_HWND"] = str(target_hwnd)
    env["CUA_UIA_NAME"] = args.name or ""
    env["CUA_UIA_AID"] = args.automation_id or ""
    env["CUA_UIA_CTYPE"] = args.control_type or ""
    env["CUA_UIA_MAX"] = str(args.max_results)

    res = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
        capture_output=True,
        text=True,
        env=env,
        timeout=25,
        check=False,
    )
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip() or "UIAutomation query failed")
    raw_out = res.stdout.strip()
    if not raw_out:
        items: list[dict[str, Any]] = []
    else:
        parsed = json.loads(raw_out)
        items = parsed if isinstance(parsed, list) else [parsed]
    return {"ok": True, "count": len(items), "elements": items}


def cmd_click(args: argparse.Namespace, _: str, policy: GuardPolicy) -> dict[str, Any]:
    _assert_input_safe(policy, points=[(args.x, args.y)])
    if args.dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "x": args.x,
            "y": args.y,
            "button": args.button,
            "clicks": args.clicks,
        }
    pyautogui, _, _, _, _, _ = _win32()
    pyautogui.moveTo(args.x, args.y, duration=args.move_duration)
    pyautogui.click(x=args.x, y=args.y, clicks=args.clicks, button=args.button)
    return {
        "ok": True,
        "x": args.x,
        "y": args.y,
        "button": args.button,
        "clicks": args.clicks,
    }


def cmd_drag(args: argparse.Namespace, _: str, policy: GuardPolicy) -> dict[str, Any]:
    _assert_input_safe(policy, points=[(args.x1, args.y1), (args.x2, args.y2)])
    pyautogui, _, _, _, _, _ = _win32()
    pyautogui.moveTo(args.x1, args.y1, duration=0.1)
    pyautogui.dragTo(args.x2, args.y2, duration=args.duration, button=args.button)
    return {
        "ok": True,
        "from": [args.x1, args.y1],
        "to": [args.x2, args.y2],
        "button": args.button,
    }


def cmd_scroll(args: argparse.Namespace, _: str, policy: GuardPolicy) -> dict[str, Any]:
    pts = [(args.x, args.y)] if (args.x is not None and args.y is not None) else []
    _assert_input_safe(policy, points=pts)
    pyautogui, _, _, _, _, _ = _win32()
    if pts:
        pyautogui.moveTo(args.x, args.y, duration=0.05)
        pyautogui.scroll(args.clicks, x=args.x, y=args.y)
    else:
        pyautogui.scroll(args.clicks)
    return {"ok": True, "clicks": args.clicks, "point": pts[0] if pts else None}


def cmd_hotkey(args: argparse.Namespace, _: str, policy: GuardPolicy) -> dict[str, Any]:
    keys = [k.strip().lower() for k in re.split(r"[,+\s]+", args.keys) if k.strip()]
    if not keys:
        raise ValueError("No keys specified for hotkey.")
    _assert_input_safe(policy, text_args=[("hotkey", " ".join(keys))])
    pyautogui, _, _, _, _, _ = _win32()
    pyautogui.hotkey(*keys)
    return {"ok": True, "keys": keys}


def cmd_type_text(args: argparse.Namespace, _: str, policy: GuardPolicy) -> dict[str, Any]:
    _assert_input_safe(policy, text_args=[("type_text", args.text)])
    _send_unicode_text(args.text, interval=args.interval)
    return {"ok": True, "chars": len(args.text)}


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser for win-cua-guard."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--blocklist",
        default=argparse.SUPPRESS,
        help="Path to YAML/JSON blocklist file (or set WIN_CUA_BLOCKLIST)",
    )

    p = argparse.ArgumentParser(
        description="Windows DPI-aware Computer Use CLI with fail-closed safety guards",
        parents=[common],
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("screen-info", parents=[common], help="Print DPI mode, desktop env, and monitors")

    pw = sub.add_parser("windows", parents=[common], help="List visible top-level windows")
    pw.add_argument("--filter", help="Regex matching title or executable")
    pw.add_argument("--include-untitled", action="store_true")

    pf = sub.add_parser("focus", parents=[common], help="Bring a window to foreground")
    pf.add_argument("--hwnd", type=int)
    pf.add_argument("--title", help="Regex matching window title")

    ps = sub.add_parser("screenshot", parents=[common], help="Capture screen, window, or synthetic grid")
    ps.add_argument("--out", required=True, help="Output PNG path")
    ps.add_argument("--hwnd", type=int)
    ps.add_argument("--title", help="Regex matching window title")
    ps.add_argument("--grid", action="store_true", help="Overlay 50/100px coordinate grid")
    ps.add_argument(
        "--synthetic-selftest",
        action="store_true",
        help="Render offline calibration canvas with grid (allowed inside sandbox desktop)",
    )

    pu = sub.add_parser("uia-find", parents=[common], help="Find UI Automation elements")
    pu.add_argument("--hwnd", type=int)
    pu.add_argument("--title")
    pu.add_argument("--name", help="Regex matching UIA Name")
    pu.add_argument("--automation-id", help="Regex matching UIA AutomationId")
    pu.add_argument("--control-type", help="Regex matching ControlType")
    pu.add_argument("--max-results", type=int, default=50)

    pc = sub.add_parser("click", parents=[common], help="Click at virtual screen (x, y)")
    pc.add_argument("--x", type=int, required=True)
    pc.add_argument("--y", type=int, required=True)
    pc.add_argument("--button", choices=["left", "right", "middle"], default="left")
    pc.add_argument("--clicks", type=int, default=1)
    pc.add_argument("--move-duration", type=float, default=0.08)
    pc.add_argument("--dry-run", action="store_true")

    pd = sub.add_parser("drag", parents=[common], help="Drag from (x1, y1) to (x2, y2)")
    pd.add_argument("--x1", type=int, required=True)
    pd.add_argument("--y1", type=int, required=True)
    pd.add_argument("--x2", type=int, required=True)
    pd.add_argument("--y2", type=int, required=True)
    pd.add_argument("--duration", type=float, default=0.35)
    pd.add_argument("--button", choices=["left", "right", "middle"], default="left")

    psc = sub.add_parser("scroll", parents=[common], help="Scroll mouse wheel")
    psc.add_argument("--clicks", type=int, required=True)
    psc.add_argument("--x", type=int)
    psc.add_argument("--y", type=int)

    ph = sub.add_parser("hotkey", parents=[common], help="Press hotkey combo (comma/plus separated)")
    ph.add_argument("--keys", required=True)

    pt = sub.add_parser("type-text", parents=[common], help="Type Unicode text via SendInput")
    pt.add_argument("--text", required=True)
    pt.add_argument("--interval", type=float, default=0.01)

    return p


def main(argv: list[str] | None = None) -> int:
    """Entrypoint: dispatch command using early-initialized DPI mode and print JSON."""
    args = build_parser().parse_args(argv)
    handlers = {
        "screen-info": cmd_screen_info,
        "windows": cmd_windows,
        "focus": cmd_focus,
        "screenshot": cmd_screenshot,
        "uia-find": cmd_uia_find,
        "click": cmd_click,
        "drag": cmd_drag,
        "scroll": cmd_scroll,
        "hotkey": cmd_hotkey,
        "type-text": cmd_type_text,
    }
    try:
        policy = load_blocklist_config(getattr(args, "blocklist", None))
        result = handlers[args.cmd](args, DPI_MODE, policy)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except SafetyBlockedError as exc:
        print(json.dumps({"ok": False, "blocked": True, "error": str(exc)}, ensure_ascii=False))
        return 2
    except Exception as exc:
        print(json.dumps({"ok": False, "blocked": False, "error": str(exc)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    sys.exit(main())

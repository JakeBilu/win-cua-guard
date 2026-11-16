"""Unit tests for win-cua-guard safety guardrails, blocklist loader, CLI, and MCP server."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from win_cua_guard import cli, mcp_server  # noqa: E402
from win_cua_guard.policy import GuardPolicy, SafetyBlockedError, load_blocklist_config  # noqa: E402


class TestGuardPolicy(unittest.TestCase):
    def test_baseline_blocks_chat_captcha_and_upload_dialog(self) -> None:
        gp = GuardPolicy()

        with self.assertRaises(SafetyBlockedError):
            gp.assert_window_info_safe(
                {"title": "WhatsApp Web", "exe": "msedge.exe", "class_name": "Chrome_WidgetWin_1"},
                "target_window",
            )
        with self.assertRaises(SafetyBlockedError):
            gp.assert_window_info_safe(
                {"title": "Chat", "exe": "WhatsApp.exe", "class_name": "ApplicationFrameWindow"},
                "target_window",
            )

        for title in ("Verify you are human", "Cloudflare Turnstile", "reCAPTCHA challenge"):
            with self.assertRaises(SafetyBlockedError):
                gp.assert_text_safe("target_window.title", title)

        with self.assertRaises(SafetyBlockedError):
            gp.assert_window_info_safe(
                {"title": "Choose File to Upload", "exe": "chrome.exe", "class_name": "#32770"},
                "foreground_window",
            )
        with self.assertRaises(SafetyBlockedError):
            gp.assert_window_info_safe(
                {"title": "Open", "exe": "acad.exe", "class_name": "#32770"},
                "foreground_window",
            )

        gp.assert_window_info_safe(
            {"title": "model.skp - SketchUp 2026", "exe": "SketchUp.exe", "class_name": "AfxFrameOrView140u"},
            "target_window",
        )

    def test_isolated_sandbox_desktop_blocked_and_default_allowed(self) -> None:
        gp = GuardPolicy()
        gp.assert_desktop_safe(
            {
                "window_station": "WinSta0",
                "desktop": "Default",
                "is_isolated_sandbox_desktop": False,
            }
        )
        with self.assertRaises(SafetyBlockedError):
            gp.assert_desktop_safe(
                {
                    "window_station": "WinSta0",
                    "desktop": "exebox-4821",
                    "is_isolated_sandbox_desktop": True,
                }
            )

    def test_load_example_yaml_blocklist_and_custom_rules(self) -> None:
        example_yaml = REPO_ROOT / "blocklist.example.yaml"
        self.assertTrue(example_yaml.is_file())
        gp = load_blocklist_config(example_yaml)

        with self.assertRaises(SafetyBlockedError):
            gp.assert_text_safe("focus.title", "Telegram Desktop")
        with self.assertRaises(SafetyBlockedError):
            gp.assert_text_safe("focus.title", "1Password Vault")
        with self.assertRaises(SafetyBlockedError):
            gp.assert_text_safe("focus.title", "WhatsApp")

    def test_cli_exit_code_2_on_safety_block_and_mcp_wrapper(self) -> None:
        example_yaml = REPO_ROOT / "blocklist.example.yaml"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["--blocklist", str(example_yaml), "focus", "--title", "Telegram"])
        self.assertEqual(rc, 2)
        payload = json.loads(buf.getvalue())
        self.assertTrue(payload["blocked"])

        with mock.patch.object(
            cli,
            "get_desktop_environment",
            return_value={
                "window_station": "WinSta0",
                "desktop": "exebox-99",
                "is_isolated_sandbox_desktop": True,
            },
        ):
            buf2 = io.StringIO()
            with contextlib.redirect_stdout(buf2):
                rc_sandbox = cli.main(["windows"])
            self.assertEqual(rc_sandbox, 2)
            self.assertTrue(json.loads(buf2.getvalue())["blocked"])

            out_json = json.loads(mcp_server.focus_window(title_pattern="WhatsApp"))
            self.assertFalse(out_json["ok"])
            self.assertTrue(out_json["blocked"])

    def test_synthetic_selftest_grid_and_parser(self) -> None:
        parsed = cli.build_parser().parse_args(["--blocklist", "custom.yaml", "click", "--x", "10", "--y", "20", "--dry-run"])
        self.assertEqual(parsed.cmd, "click")
        self.assertEqual(parsed.blocklist, "custom.yaml")
        self.assertTrue(parsed.dry_run)

        with tempfile.TemporaryDirectory() as tmp:
            out_png = Path(tmp) / "grid.png"
            try:
                import PIL  # noqa: F401
                has_pil = True
            except ImportError:
                has_pil = False

            if has_pil:
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = cli.main(["screenshot", "--synthetic-selftest", "--grid", "--out", str(out_png)])
                self.assertEqual(rc, 0)
                self.assertTrue(out_png.is_file())
                self.assertGreater(out_png.stat().st_size, 5000)
                data = json.loads(buf.getvalue())
                self.assertTrue(data["grid"])
                self.assertEqual(data["width"], 1280)
                self.assertEqual(data["height"], 720)
            else:
                class _FakeImg:
                    width = 1280
                    height = 720

                    def save(self, path, format=None):
                        Path(path).write_bytes(b"PNG_STUB_DATA")

                with (
                    mock.patch.object(cli, "get_desktop_environment", return_value={"window_station": "WinSta0", "desktop": "Default", "is_isolated_sandbox_desktop": False}),
                    mock.patch.object(cli, "build_synthetic_selftest_canvas", return_value=_FakeImg()),
                    mock.patch.object(cli, "draw_coordinate_grid", return_value=_FakeImg()) as mock_grid,
                ):
                    buf = io.StringIO()
                    with contextlib.redirect_stdout(buf):
                        rc = cli.main(["screenshot", "--synthetic-selftest", "--grid", "--out", str(out_png)])
                    self.assertEqual(rc, 0)
                    self.assertTrue(mock_grid.called)
                    self.assertTrue(out_png.is_file())
                    self.assertEqual(json.loads(buf.getvalue())["width"], 1280)


if __name__ == "__main__":
    unittest.main()

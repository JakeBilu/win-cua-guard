"""Fail-closed safety guardrails and YAML/JSON blocklist loader for win-cua-guard."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

BASELINE_BLOCKED_PATTERNS: tuple[str, ...] = (
    r"(?i)(whatsapp)",
    r"(?i)(recaptcha|turnstile|captcha|cf-turnstile|verify\s+you\s+are\s+human)",
    r"(?i)(antigravity.*automation|agent.*permission)",
)

BASELINE_UPLOAD_DIALOG_PATTERN = (
    r"(?i)^(open|file upload|choose file( to upload)?|select file|打开|选择要上[传载]的文件)$"
)


class SafetyBlockedError(RuntimeError):
    """Raised when an operation targets a guarded or sandbox-isolated surface."""


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    """Minimal YAML subset parser for blocklist files when PyYAML is not installed."""
    result: dict[str, Any] = {}
    current_key: str | None = None
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- ") and current_key is not None:
            val = stripped[2:].strip()
            if (val.startswith('"') and val.endswith('"')) or (
                val.startswith("'") and val.endswith("'")
            ):
                val = val[1:-1]
            if not isinstance(result.get(current_key), list):
                result[current_key] = []
            result[current_key].append(val)
            continue
        if ":" in stripped:
            key, val = stripped.split(":", 1)
            key = key.strip()
            val = val.strip()
            if "#" in val and not (val.startswith('"') or val.startswith("'")):
                val = val.split("#", 1)[0].strip()
            if not val:
                result[key] = []
                current_key = key
            else:
                current_key = None
                if val.lower() == "true":
                    result[key] = True
                elif val.lower() == "false":
                    result[key] = False
                elif (val.startswith('"') and val.endswith('"')) or (
                    val.startswith("'") and val.endswith("'")
                ):
                    result[key] = val[1:-1]
                else:
                    result[key] = val
    return result


def _load_structured_file(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        try:
            import yaml  # type: ignore

            data = yaml.safe_load(text) or {}
        except ImportError:
            data = _parse_simple_yaml(text)
    if not isinstance(data, dict):
        raise ValueError(f"Blocklist config must be a mapping/dict: {path}")
    return data


@dataclass(slots=True)
class GuardPolicy:
    """Fail-closed policy checking text targets, HWNDs, upload dialogs, and Win32 desktops."""

    extra_patterns: list[str] = field(default_factory=list)
    upload_dialog_pattern: str = BASELINE_UPLOAD_DIALOG_PATTERN
    require_default_desktop: bool = True
    _compiled_patterns: list[re.Pattern[str]] = field(init=False, repr=False)
    _upload_rx: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        all_patterns = list(BASELINE_BLOCKED_PATTERNS) + [
            p for p in self.extra_patterns if p and p not in BASELINE_BLOCKED_PATTERNS
        ]
        self._compiled_patterns = [re.compile(p) for p in all_patterns]
        self._upload_rx = re.compile(self.upload_dialog_pattern)

    def assert_text_safe(self, label: str, value: str | None) -> None:
        """Fail closed if string matches any baseline or user-configured block pattern."""
        if not value:
            return
        for rx in self._compiled_patterns:
            if rx.search(value):
                raise SafetyBlockedError(
                    f"Blocked by safety policy ({label} matched guard pattern): {value!r}"
                )

    def assert_desktop_safe(self, desktop_env: dict[str, Any]) -> None:
        """Fail closed when invoked inside an isolated non-Default Win32 desktop."""
        if not self.require_default_desktop:
            return
        desktop = str(desktop_env.get("desktop", "unknown"))
        winsta = str(desktop_env.get("window_station", "unknown"))
        isolated = bool(desktop_env.get("is_isolated_sandbox_desktop")) or (
            desktop.lower() != "default"
        )
        if isolated:
            raise SafetyBlockedError(
                "Blocked by Win32 desktop isolation: current process runs on "
                f"{winsta}\\{desktop} rather than WinSta0\\Default. "
                "Use headless automation or an interactive WinSta0\\Default terminal."
            )

    def assert_window_info_safe(self, info: dict[str, Any], context: str) -> None:
        """Fail closed if window title, executable, or #32770 upload dialog is guarded."""
        title = str(info.get("title") or "")
        exe = str(info.get("exe") or "")
        class_name = str(info.get("class_name") or "")
        self.assert_text_safe(f"{context}.title", title)
        self.assert_text_safe(f"{context}.exe", exe)
        if class_name == "#32770" and self._upload_rx.match(title.strip()):
            raise SafetyBlockedError(
                f"Blocked by safety policy ({context} is an OS file chooser dialog): {title!r}"
            )


def load_blocklist_config(path: str | Path | None = None) -> GuardPolicy:
    """Load GuardPolicy from --blocklist path, WIN_CUA_BLOCKLIST env var, or defaults."""
    resolved: Path | None = None
    if path is not None:
        resolved = Path(path)
        if not resolved.is_file():
            raise FileNotFoundError(f"Blocklist file not found: {resolved}")
    else:
        env_path = os.environ.get("WIN_CUA_BLOCKLIST", "").strip()
        if env_path:
            cand = Path(os.path.expanduser(env_path))
            if not cand.is_file():
                raise FileNotFoundError(f"WIN_CUA_BLOCKLIST file not found: {cand}")
            resolved = cand

    if resolved is None:
        return GuardPolicy()

    raw = _load_structured_file(resolved)
    extra = [str(p) for p in raw.get("blocked_patterns", []) if str(p).strip()]
    upload_pat = str(raw.get("upload_dialog_pattern") or BASELINE_UPLOAD_DIALOG_PATTERN)
    req_default = bool(raw.get("require_default_desktop", True))
    return GuardPolicy(
        extra_patterns=extra,
        upload_dialog_pattern=upload_pat,
        require_default_desktop=req_default,
    )

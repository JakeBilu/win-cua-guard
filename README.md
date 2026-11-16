# win-cua-guard

A Per-Monitor v2 DPI-aware Windows Computer Use (CUA) CLI and FastMCP server with **fail-closed safety guardrails**.

## Why?

Raw GUI automation scripts routinely misclick across scaled multi-monitor setups, break inside isolated Windows sandbox desktops (`WinSta0\exebox-*`), or accidentally interact with sensitive messaging apps, password managers, CAPTCHAs, and `#32770` OS file upload dialogs.

`win-cua-guard` solves both problems cleanly:
- **Per-Monitor v2 DPI Awareness** initialized *before* importing PyAutoGUI.
- **50px / 100px Coordinate-Grid Overlay Screenshots** (`--grid`) + offline `--synthetic-selftest` calibration canvas.
- **.NET UI Automation Lookup** (`uia-find`) returning exact element bounding rectangles and center coordinates.
- **Unicode-safe Win32 `SendInput`** (`KEYEVENTF_UNICODE`) without clipboard clobbering.
- **Fail-Closed Safety Guardrails** (`SafetyBlockedError`, exit code `2`) enforced across both CLI and MCP tools, with user-extensible `--blocklist` YAML/JSON policies.

## Baseline & Custom Guardrails

Baseline protections (always enforced):
- Messaging / chat surfaces (`WhatsApp`)
- Anti-bot / CAPTCHA gates (`reCAPTCHA`, `Turnstile`, `cf-turnstile`, `captcha`)
- `#32770` OS file chooser / upload dialogs (`Open`, `File Upload`, `Choose File to Upload`, `Select File`)
- Non-Default Win32 sandbox desktops (`WinSta0\exebox-*`)

Extend with `--blocklist blocklist.example.yaml` (or `WIN_CUA_BLOCKLIST` env var).

## Quickstart

```bash
pip install -e .

# Inspect monitors, DPI awareness mode, and Win32 desktop station
win-cua screen-info

# Capture a coordinate-grid screenshot of a target window
win-cua screenshot --title "SketchUp" --grid --out screen_grid.png

# Generate an offline synthetic calibration grid (works inside sandboxes)
win-cua screenshot --synthetic-selftest --grid --out selftest.png

# Apply custom blocklist rules
win-cua --blocklist blocklist.example.yaml click --x 400 --y 300 --dry-run
```

### MCP Server Configuration

```json
{
  "mcpServers": {
    "win-cua-guard": {
      "command": "win-cua-mcp",
      "args": ["--blocklist", "C:\\path\\to\\blocklist.example.yaml"]
    }
  }
}
```

## License

MIT — see [LICENSE](LICENSE).

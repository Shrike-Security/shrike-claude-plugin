# Changelog

All notable changes to the Shrike Security plugin for Claude Code.

This project follows [Semantic Versioning](https://semver.org/).

## [1.0.0]

First public release.

### Added

- **PreToolUse enforcement.** Shell commands and file writes are scanned before
  they execute, and the hook routes on the verdict: `allow` proceeds, `warn`
  proceeds with a note on stderr, `require_approval` and `block` deny.
- **Failure posture, operator-set.** `failure_mode` in `config.json` decides
  what happens when no verdict could be obtained: `closed` (the default) holds
  the action, `open` permits it with a loud warning. A real `block` response is
  always enforced regardless, because failure posture governs the absence of a
  verdict rather than the content of one.
- **Inert without a key.** With no API key configured the hook permits and
  prints a one-line setup pointer once per session, so installing it can never
  be the reason a session stops working.
- **The `governed-tool-use` skill**, which teaches the agent to scan before it
  acts, read the four-state verdict, and recover cooperatively instead of
  retrying a refusal.
- **The shrike-mcp security tools**, bundled through `.mcp.json`.
- **Two editors from one hook body.** The same script answers Claude Code's
  PreToolUse payload and Cursor's `beforeShellExecution`; only the envelope
  differs, and Cursor gets a genuine `ask` for the approval tier because it has
  a person at the keyboard.
- **`verify.sh`**, which pipes three synthetic payloads through the hook and
  checks the verdict routing end to end. Nothing it sends is ever executed.

### Notes

- Requires Node 18 or newer. The wrapper degrades self-explainingly when the
  runtime is missing rather than failing silently.
- The plugin is a thin client. It carries no detection logic; every verdict is
  computed on the Shrike backend.

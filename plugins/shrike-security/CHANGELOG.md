# Changelog

All notable changes to the Shrike Security plugin for Claude Code.

This project follows [Semantic Versioning](https://semver.org/).

## [1.1.0]

Parity with the hook Shrike runs on its own engineering. The plugin is the
artifact customers install, so it is now the canonical integration rather than
a reduced copy of an in-house one.

### Added

- **Three more tools gated.** `NotebookEdit`, `WebSearch` and `WebFetch` join
  `Bash`, `Write` and `Edit`. `WebFetch` is scanned on the `web_search`
  channel, which is the closest available boundary rather than the right one,
  and the hook says so rather than implying a better fit.
- **The observe plane.** `UserPromptSubmit` scans the prompt and **never
  gates**. A person is not refused their own words; a flagged prompt becomes
  context for Claude instead, so a prompt-to-action narrative exists without
  anyone being blocked from typing.
- **Observe-mode disclosure.** When a verdict is recorded but withheld because
  the agent is in observe mode, the agent is now told which tier would have
  applied and on which axis. The agent is the only party that knows what an
  action was for, so it is the only party that can call a withheld refusal
  wrong. It was previously never told.
- **The host's own decisions.** `PermissionDenied` and `PermissionRequest`
  record what Claude Code's permission layer decided, kept beside Shrike's
  verdict rather than instead of it, so the two authority models can be
  compared instead of confused. The fact only: the tool, a digest of the
  input, the host's stated reason. The command and the file body never leave
  the machine. Shrike's own refusals are marked so the host's echo of them is
  not counted a second time under a different authority.
- **The API key as a plugin option.** `userConfig.api_key` is declared
  sensitive, so Claude Code prompts for it when the plugin is enabled and
  stores it in the operating system credential store. The environment
  variable still works and remains the right route for CI and fleets.
- **Sub-agent attribution.** Scans carry `host_subagent_id` and
  `host_subagent_type` when an action comes from a sub-agent. Parent, chain
  and depth are deliberately left empty: the host publishes no parent
  pointer, and reporting the actor is honest where inferring a lineage would
  not be.

### Changed

- **A file edit is scanned twice, path then body.** The authoring-path grant
  is decided on the path, so a single combined scan governed authoring
  differently from the way Shrike governs its own.
- **The no-key notice reaches Claude.** Without a key the plugin is still
  inert, but it now says so through `additionalContext` rather than standard
  output, which the host routes to a debug log that nobody reads.

### Fixed

- **`install.sh` registered three tools and three events** while the plugin
  registered six of each, so a user who ran the installer was governed
  differently from one who installed the plugin, with no error on either
  route.
- **`managed-settings.template.json` carried three events.** That file is
  what an organization pushes through MDM to every machine, so a whole fleet
  was governed more narrowly than a single install. It is now asserted to be
  byte-identical to what `install.sh --managed` prints.
- **`install-check.sh` asserted three events**, so it reported the installer
  broken once the installer was correct. It now reads the expected event set
  from `hooks/hooks.json` instead of restating it.

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

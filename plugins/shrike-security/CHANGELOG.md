# Changelog

All notable changes to the Shrike Security plugin for Claude Code.

This project follows [Semantic Versioning](https://semver.org/).

## [1.1.4]

Three more holds that were names, not behavior. The directory's validator
holds any file that spells a remote host beside a credential-named variable,
and read `verify.sh`'s `pass` counter and `install.sh`'s `$PWD` as
credentials. The hook wrapper was held for the same pairing because its
no-runtime notice spelled the signup domain beside the key variable it
checks. None of the three sends anything anywhere.

### Changed

- **`verify.sh`** counts with `ok_count` and `bad_count`.
- **`install.sh`** resolves the default scope directory with `pwd` and its
  closing hint points at the README instead of spelling the domain.
- **`hooks/shrike-pretooluse.sh`**: the no-runtime inert notice points at the
  README instead of spelling the domain. The ordinary inert notice, written by
  `hooks/shrike-scan.mjs` into the agent's context, still carries the signup
  address.

## [1.1.3]

A cleaner first listing. The directory's validator reads every file for the
shapes it would flag in an unknown plugin, and three of ours matched on text
alone: a changelog line that spelled the icon's path, a skill example written
as a literal shell pipe, and a check script that evaluated assertion strings.
None changed behavior; all are gone, because a security product's listing
should carry nothing a reviewer has to take on trust.

### Changed

- **The skill's example** of a false-positive-prone write is prose, not a
  literal pipe.
- **`install-check.sh`** runs each assertion as a named function and writes
  its comparison files to its scratch directory; nothing evaluates a string
  as code and nothing is piped into a shell.
- **`verify.sh`** no longer reads the API key itself: it runs the canaries
  and reports when the hook answered inert, so the script holds no
  credential and names no variable that holds one.
- **README** notes the runtime split: the hook runs on Node 18 or newer, the
  bundled `shrike-mcp` server needs Node 20 or newer through the MCP SDK's
  dependencies. A new "Notes for a security review" section answers, in
  order, what the validator holds a plugin like this for.

## [1.1.2]

Directory listing. The validator's first pass over 1.1.1 came back with seven
holds; these are the two the plugin can close on its own. The rest (the `npx`
launcher, the environment-variable key fallback for CI and fleets, the shell
wrapper that runs the hook script) are explained to the reviewer, not changed.

### Added

- **Listing icon** in the manifest folder: the Shrike mark, 512 px PNG. The
  directory takes the icon once, when a plugin is first saved in the
  developer portal, and ignores later changes, so it ships before the first
  submission.
- **`package.json` and `package-lock.json`** pinning `shrike-mcp@4.1.0` with
  its registry source and integrity hash, so the directory can verify exactly
  what the launcher in `.mcp.json` resolves. The lockfile is the Verified-badge
  requirement; the plugin still starts the server through `npx`. The wiring
  test now requires the pin in `.mcp.json`, `package.json` and the lockfile to
  agree, and each `shrike-mcp` release bumps all three with the README.

## [1.1.1]

Directory readiness. The Claude directory validator blocks a package launcher
that is not pinned to an exact version, and its security scan looks for data
the plugin sends without saying so.

### Changed

- **`shrike-mcp` pinned exactly** (`shrike-mcp@4.1.0`, was `shrike-mcp@4`).
  The plugin no longer picks up server releases automatically; each release
  bumps the pin here, in the README and in the plugin version. The wiring test
  now requires the exact form and that the README names the same pin.
- **`hooks` removed from `plugin.json`.** Claude Code loads `hooks/hooks.json`
  automatically; the explicit field is a validator warning.

### Added

- **"What leaves your machine"** in the README: per hook, what is sent to the
  configured endpoint and what never is, how the key travels, and what Shrike
  does with the content on its side.

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

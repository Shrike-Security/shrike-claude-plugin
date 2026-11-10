# Changelog

All notable changes to the Shrike Security plugin for Claude Code.

This project follows [Semantic Versioning](https://semver.org/).

## [1.1.8] - 2026-11-10

### Added

- **Every delegation has a lane, named by its brief.** The `Agent` tool's brief
  now carries the host's own one-line name for the task (its `description`,
  capped at 120 characters), the Agent call's return reports which sub-agent
  it started together with the run's duration, token and tool-use counts as
  the host counted them, and the new `SubagentStart` hook, with `SubagentStop`,
  reports when each sub-agent began and ended. On the session timeline a
  sub-agent's lane is named by the task its brief named, a line is drawn from
  the brief to the lane the host said it started (never guessed from time
  order), the lane runs from the host's start to its end, and a sub-agent that
  only read still has a lane. Nothing new is content: an id the host minted, a
  title the host already shows in its task list, two times and three counts.

### Changed

- **A locked session is explained once.** The first call the session lock
  refuses carries the full explanation and, when the backend reports it, the
  turn the lock engaged on ("locked since turn 7"). Later calls in the same
  session say only that the lock still holds and that nothing about the call
  was judged, so a locked session no longer reads the same paragraph on every
  refusal. The full wording returns if the lock lifts and engages again.

### Fixed

- **The managed template carries the `SubagentStart` hook.** The installer
  has printed it since every delegation got a lane; the template an
  administrator delivers by hand now matches, so a managed fleet reports when
  a sub-agent begins as well as when it ends.

## [1.1.7] - 2026-10-29

### Fixed

- The managed-settings template no longer sets `SHRIKE_DELEGATION_GATE`. Enforce
  is the plugin's default and the installer's `--managed` output never carried
  the line, so the two disagreed and `install-check.sh` failed. The variable
  stays available as an operator override.
- The README names the `shrike-mcp@4.2.0` pin, matching `.mcp.json`,
  `package.json` and the lockfile.

### Changed

- **`shrike-mcp` pinned to 4.2.0.** `check_approval` now answers for a hold by
  its `scan_id`, so an action held by your declared scope and approved on the
  dashboard can be retried once, within the window the answer names, and
  anything changed is checked again as a new action. `scan_mcp_schema` brings
  its verdict to you instead of telling the model to refuse on its own, and a
  block never invites a reword.

- **A hold asks you instead of stopping Claude.** When Shrike holds an
  action for a person and you are the one who answers prompts (Manual,
  plan, or auto mode, or a shell command under accept-edits), the plugin now
  puts the hold to you in Claude Code's own permission prompt, with the
  reason and the scan id. Approve and the action runs, with no retry; the
  run is reported, so the hold closes on the dashboard as approved at the
  agent. Decline and it does not run, and at the end of the turn it is
  reported as not run. Where a mode would answer the prompt for you
  (bypass permissions, don't-ask, a headless run, or a file edit under
  accept-edits), and for policy approvals that may need a named approver,
  the hold is refused as before and stays open for the dashboard.

- **Your own prompts no longer build session risk.** With `scan_conversation`
  on, the prompt you type is sent marked as the operator's
  (`prompt_author: operator`). The backend still checks it and Claude is still
  told when something in it looks off, but it adds nothing to the session's
  risk, so pasting a post or an article into your own session can no longer
  lead to a lock. Claude's replies and every action keep their full weight.

- **Every instruction Claude receives from the plugin is written in the
  plugin.** When an action is held or refused, the reason Claude reads still
  carries the backend's description of the verdict, but the next step now
  comes from the plugin's own wording (`hooks/next-steps.mjs`), chosen by the
  verdict's category and whether the session lock produced it. The backend's
  recovery instruction is never forwarded, so no server can change what
  Claude is told to do.

- **The manual installer copies every hook module.** `install.sh` copied
  only `shrike-scan.mjs` and the shell wrapper, so a manual install was
  missing the modules the hook imports and failed at load. It now copies
  every `hooks/*.mjs`.

- **Prompts and replies stay on your machine unless you opt in.** The
  `UserPromptSubmit` and `Stop` hooks no longer send the prompt or Claude's
  final reply by default. Neither scan ever gated anything, so sending
  conversation text is now the operator's choice: turn on the new
  `scan_conversation` option, or set `SHRIKE_SCAN_CONVERSATION=1` (which also
  overrides the option). Actions are checked exactly as before.

### Added

- **Reads are checked before they run.** `Read`, `Grep` and `Glob` are
  gated on the new `file_read` channel: `Read` sends the file, `Grep` and
  `Glob` the root they search. A read is refused only when it opens a
  credential store (SSH keys, cloud credentials, environment files, key
  stores). A clean read is counted for its session and not stored, so it uses
  no scan quota and shows in the Turn View as "and N clean reads". A read is
  permitted by any scope unless the scope forbids `file_read` by name.

- **MCP tool calls are checked before they run.** Every `mcp__*` tool is
  now gated (`gated_tools` and the matchers gain `mcp__.*`; an entry ending
  in `.*` is a prefix). A call is sent on the new `tool_call` channel: its
  full name goes in `tool_name`, so an operator allows, forbids or
  always-waits it by name in the agent's scope, and its arguments are judged
  for credential material and intent. Shrike's own MCP tools are never
  judged. An agent whose declared scope does not list an MCP tool is held
  on it: put the agent in observe mode first to see what it calls.

- **A key helper for fleets.** `api_key_helper` in `config.json`, or
  `SHRIKE_API_KEY_HELPER`, names a command whose first line of output is the
  API key, so an organization reads the key from its secrets manager or the OS
  keychain at run time instead of pushing it in plain text to every machine.
  The plugin's key option still wins, then the helper, then the variable. A
  helper that fails, times out or prints nothing holds gated actions under the
  closed failure posture rather than leaving the hook inert.

### Changed

- **Delegation is decided like any other action.** `delegation_gate` now
  defaults to `enforce`: the `Agent` brief and the sub-agent's report go on
  the act plane and the backend decides them. An agent in observe mode
  observes its delegations inside its own observe window, which has an end
  date and shows on the Agents screen, instead of the plugin observing them
  with no end date. An agent with no scope has no observe mode, so its
  delegations are enforced from this release. `delegation_gate: observe`
  still works as an override and is removed in the next release.

- **A flagged reply is one line in the terminal.** The reply is checked after
  it is written, so the note no longer repeats the verdict and its reason on
  screen. It says only that a check on the reply was recorded, with the check
  id, so whoever runs Shrike can find the reason, the rule and the session
  risk in the dashboard. The person in the editor may have no dashboard login,
  so the line does not point them there.

### Fixed

- **A flagged sub-agent report is no longer lost.** When a report was
  flagged but delivered, the note went back as context on `SubagentStop`,
  which continues the sub-agent's own conversation: it answered the note,
  and that answer replaced the report the parent received. The person now
  sees one neutral line, and the report reaches the parent unchanged. A
  refused report under `enforce` is unchanged: it goes back to the
  sub-agent with the reason, by design.
- **Size limits agree.** One scan reads up to 100 KB. An action over that is
  refused whole with its real size; the hook used to cut it to 200 KB first,
  so the refusal reported the wrong size. A prompt or reply over 100 KB used
  to be sent at up to 200 KB and refused by the backend, so it went unchecked
  without a word; it is now scanned on its opening and its end, and the scan
  records that it was cut. A long brief or sub-agent report is judged the same
  way instead of on its opening alone.
- **A slow backend could run the hook past the editor's time limit.** A
  scan, its health check and one retry can take 23 seconds per stage and a
  file write has two stages, while the editor gave the hook 30 seconds and
  lets the tool run when a hook times out. The hook now keeps its own
  25-second budget (`SHRIKE_HOOK_BUDGET_MS`): every timed step gets only what
  is left, and a stage that cannot fit is held by the hook under the failure
  posture. The editor's limit for gated tools is raised to 40 seconds, in
  `hooks.json`, the managed-settings template and the installer alike.
- **The no-Node fallback ignored the plugin's key option.** With the key set
  only through the plugin option, a machine without Node reported the hook as
  inert instead of applying the failure posture.

## [1.1.6]

The skill said the gate holds regardless of the surface. It holds where the
plugin's hook runs; on a chat surface only the skill loads, and nothing gates
an action Claude did not scan. Fixed before anyone uploads the skill on its
own.

The larger change in this version is that a session now reads as a sequence
of exchanges rather than a flat list of scans. Every scan carries the id of
the exchange it belongs to, the reply at the end of a turn is scanned, and a
delegation to a sub-agent is scanned on the way out and on the way back.

### Added

- **Every scan carries its exchange.** Claude Code stamps each hook event
  with the id of the prompt being answered, including events fired inside a
  sub-agent. The hook forwards it as `exchange_id`, so the dashboard can
  group a session's rows by the ask they served, and a handoff lands in the
  exchange that spawned it.
- **The reply is scanned.** A `Stop` hook sends the model's final reply on
  the observe plane. It never gates: the turn is over. A non-allow verdict is
  shown as a system message and recorded on the row.
- **Delegations are scanned, both ways.** The `Agent` tool joins the gated
  list: the brief handed to a sub-agent is judged on the agent-to-agent
  channel before the spawn, and the sub-agent's report is judged before the
  parent acts on it. The report arrives two ways and both are covered: a
  `SubagentStop` hook reads the sub-agent's final message, and on Claude Code
  2.1.271 or later a sub-agent that hands back through the `SubagentHandback`
  tool is scanned on that call, where the final message is only its closing
  text. Both are **observed by default**
  (`delegation_gate: "observe"` in `config.json`, or `SHRIKE_DELEGATION_GATE`):
  a non-allow verdict reaches Claude as context and the delegation proceeds.
  Set `enforce` to refuse a flagged brief and to send a flagged report back
  to the sub-agent with the reason. The default moves to enforce in a later
  version once a week of observed verdicts has been read. Claude Code's own
  internal agents (prompt suggestions, side questions) also end with a
  `SubagentStop`, marked by an empty agent type; those are not delegations
  and are not judged.

### Changed

- **Observe-plane notes carry the reason.** The prompt note, the reply's
  system message and the sub-agent report note read the words from the
  violation that carries them, then the recovery instruction, then the
  threat's name. Before this every one of them said "flagged", because they
  read a top-level field the scan response never carries. A verdict the
  session lock produced now says so, instead of blaming the text it was
  shown. The notes also speak as the policy they enforce: a line no longer
  opens with the vendor's name, and the reply note says that nothing was
  stopped, because a finished turn cannot be. The name stays on the
  messages that are about the mechanism itself, such as an inert install or
  a scan that could not run.
- **A scan that runs over budget asks whether the backend is up before it
  holds.** A transport failure used to read as an outage, whatever the cause.
  The hook now probes the health endpoint for three seconds: if the backend
  answers, the scan is sent once more, since a repeat of the same content is
  cheap on the backend; if it does not, the refusal says the backend is
  unreachable and tells the agent to stop retrying. Fail closed either way;
  the difference is one retry and the words.
- **A file write with a body is one scan again.** The body scan checks the
  path in full before it reads the body, so the separate path scan added in
  the previous version only repeated that check. The path-only scan remains
  for a write with no body.

- **The skill's closing section** says where the gate is (the Claude Code
  hook, an SDK guard, the proxy) and that on a chat surface the agent is the
  gate, so "scan before every side effect" is the whole of the governance
  there.
- **README** gains "Where the plugin runs": what loads on Claude Code, Cowork
  and chat surfaces, what governs on each, and how the Desktop app's own MCP
  configuration gives a chat seat the scan tools with an audit record and no
  gate.
- **README**, "What leaves your machine": the sentence on Shrike's side now
  matches the privacy policy. A safe scan keeps a hash and metadata only; the
  content of a flagged or refused scan is what is stored for the audit trail.
- **The deny reason names a locked session.** When Shrike refuses because the
  session is locked, the response now carries the locked session's id, and
  the hook puts it in the reason Claude reads. The hook's session is not the
  MCP server's, so a release aimed at the wrong one did nothing; the skill
  now says to pass that id to `reset_session`.

## [1.1.5]

One hold that the previous entry created. The 1.1.4 note named the two
variables the validator had mistaken for credentials, and a changelog that
spells a credential-shaped name beside a link (this file links to the
Semantic Versioning site) matches the same rule the note was describing.
Nothing else changed.

### Changed

- **`CHANGELOG.md`**: the 1.1.4 entry describes the two variables without
  naming them.
- **README**, notes for a security review: says that one `verify.sh` canary
  names a private-key path on purpose, because an exfiltration canary that
  names nothing worth taking would not test the refusal.

## [1.1.4]

Three more holds that were names, not behavior. The directory's validator
holds any file that spells a remote host beside a credential-named variable,
and read `verify.sh`'s result counter and the shell's working-directory
variable in `install.sh` as credentials. The hook wrapper was held for the
same pairing because its no-runtime notice spelled the signup domain beside
the key variable it checks. None of the three sends anything anywhere.

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

The plugin becomes the complete integration: every capability of Shrike's
Claude Code hook now ships in it.

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

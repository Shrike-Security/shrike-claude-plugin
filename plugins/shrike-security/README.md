# Shrike Security: plugin for Claude Code

Runtime enforcement for Claude Code. Before Claude Code runs a shell command or
writes a file, this plugin scans the action with [Shrike](https://shrikesecurity.com)
and routes on the verdict (allow, warn, require approval, or block) *before*
the action executes. You can't patch an executed `rm -rf`; you can refuse it.

Shrike is available as a plugin for Claude Code. The plugin is a thin client:
it contains zero detection logic. All scanning runs on Shrike's backend; the
operator's policy decides what is allowed.

## What's in the bundle

| Part | What it does |
|---|---|
| **PreToolUse hook** | The mandatory gate. Scans `Bash`, `Write`, `Edit`, `NotebookEdit`, `WebSearch`, and `WebFetch` tool calls with Shrike before Claude Code executes them, and denies on `block` / `require_approval` verdicts with the reason and recovery guidance shown to Claude. A file edit is scanned twice, the path and then the body, because the authoring-path grant is decided on the path. |
| **Observe-plane hook** | `UserPromptSubmit` scans the prompt and **never gates**: a person is not refused their own words. A flagged prompt becomes context for Claude instead. |
| **Host-decision hooks** | `PermissionDenied` and `PermissionRequest` record what Claude Code's *own* permission layer decided about an action, kept beside Shrike's verdict rather than instead of it, so you can see both guardrails in one place and tell where they disagree. The fact only: the tool, a digest of the input, the host's stated reason. Never the command or the file body. |
| **`governed-tool-use` skill** | The cooperative path. Teaches Claude to scan risky actions proactively, interpret the four-state verdict, and recover from a refusal instead of retrying it. |
| **`shrike-mcp` server** | The 15 security tools (`scan_command`, `scan_file_write`, `scan_declare_scope`, `check_approval`, `report_outcome`, …) so Claude can scan, declare task scope, check approval status, and report what became of an action itself. Runs via `npx shrike-mcp@4.1.0`, pinned to an exact version as the Claude directory requires; each release of the server bumps the pin. |

The skill is how a cooperative agent gets governance right the first time; the
hook is the gate that holds when the agent isn't cooperative. Together they
demonstrate the whole architecture: active guidance plus enforcement.

## Setup

1. Get an API key (free tier available) at <https://shrikesecurity.com>.
2. Add the marketplace and install:

   ```sh
   /plugin marketplace add Shrike-Security/shrike-claude-plugin
   /plugin install shrike-security
   ```

3. Claude Code asks for the key as the plugin is enabled. It is declared a
   *sensitive* plugin option, so the value goes to your operating system's
   credential store rather than into a settings file, and reaches the hook as
   `CLAUDE_PLUGIN_OPTION_API_KEY`.

A key in the environment still works, and it is the right route for anything
non-interactive: CI, a batch job, a fleet pushed through managed settings. Set
`SHRIKE_API_KEY` where Claude Code runs. The plugin option wins when both are
present.

Without a key the plugin is **inert**: nothing is gated, and once per session
the hook says so *in Claude's own context*, not on a stream Claude never sees.
An unconfigured editor keeps working, and it never looks governed when it
isn't.

## Configuration

`config.json` at the plugin root:

```json
{
  "api_key_env": "SHRIKE_API_KEY",
  "failure_mode": "closed",
  "gated_tools": ["Bash", "Write", "Edit", "NotebookEdit", "WebSearch", "WebFetch"],
  "endpoint": "https://api.shrikesecurity.com/agent"
}
```

| Field | Default | Meaning |
|---|---|---|
| `api_key_env` | `SHRIKE_API_KEY` | Name of the environment variable holding your Shrike API key. |
| `failure_mode` | `closed` | What happens when Shrike is **unreachable** (timeout / network / 5xx). `closed`: hold the action. `open`: allow it, with a loud warning on stderr. |
| `gated_tools` | `Bash`, `Write`, `Edit`, `NotebookEdit`, `WebSearch`, `WebFetch` | Tools the hook scans. If you widen this list, also widen the `matcher` in `hooks/hooks.json`: a tool missing from either side is ungoverned, with no error anywhere. |
| `endpoint` | `https://api.shrikesecurity.com/agent` | Shrike scan API base URL (self-hosted / sovereign deployments point this at their own gateway). |

Environment variable overrides (take precedence over `config.json`):
`SHRIKE_API_KEY_ENV`, `SHRIKE_FAILURE_MODE`, `SHRIKE_GATED_TOOLS`
(comma-separated), `SHRIKE_BACKEND_URL`, `SHRIKE_SCAN_TIMEOUT_MS`,
`SHRIKE_AGENT_ID`.

### Identity: seats and autonomous agents

On a developer machine leave `SHRIKE_AGENT_ID` unset. The hook derives a
seat id from the machine user and host (`seat:<user>@<host>`, lowercased) and
sends it on every scan, so each developer is one row on the Agents screen and
is counted as a seat. Set `SHRIKE_AGENT_ID` only for an autonomous agent (a
CI runner, a batch job, a service agent): it declares its own id and is
metered by what it does. The class rides with every scan as
`identity_class`.

### Failure posture

Verdicts are never optional. An actual `block` verdict is always enforced, in
every mode. `failure_mode` only governs what happens when **no verdict could
be obtained**. Failure is always loud and self-explaining:

> `Shrike unreachable, action held (failure_mode=closed)`

`failure_mode: open` is an explicit operator opt-in; the shipped default is
`closed`.

## How the hook decides

Each gated tool call is sent to Shrike's enforce API with the Claude Code
`session_id`, so multi-turn session correlation and declared task scopes apply
across the whole task. The verdict maps as:

| Verdict | Hook behavior |
|---|---|
| `allow` | Permit. |
| `warn` | Permit, with the guidance noted on stderr. |
| `require_approval` | Deny, with the approval id. A human approves it in the Shrike dashboard; Claude can poll with the `check_approval` MCP tool. |
| `block` | Deny, with the reason and `recovery.instruction` shown to Claude. A blocked action retried verbatim will block again. |

Deterministic layers answer in tens of milliseconds; the full semantic path
worst-cases around 2–3 seconds. The hook timeout is set above that, with the
failure posture governing anything slower.

## What leaves your machine

Everything the plugin sends goes to one place, the `endpoint` in `config.json`
(`https://api.shrikesecurity.com/agent` by default, or your own gateway), over
HTTPS, authenticated with your Shrike API key. Nothing else is contacted, and
nothing runs that is not in this folder except the `shrike-mcp` package the
`.mcp.json` entry launches.

| Hook | What is sent | What is not |
|---|---|---|
| `PreToolUse`, `PostToolUse`, `PostToolUseFailure` | The gated tool call: the command text, the file path and the file body being written, the search query or URL; the tool name; Claude Code's `session_id`; the agent id; sub-agent lineage when present; on the post hooks, the outcome. | The tool's return value, your conversation, other files. |
| `UserPromptSubmit` | The prompt text, for the observe plane. The verdict never gates a prompt. | Prior turns. |
| `PermissionDenied`, `PermissionRequest` | The fact of the host's decision: tool name, a digest of the input, the host's stated reason. | The command or the file body. |

The key comes from the sensitive plugin option (your operating system's
credential store) or, for fleets and CI, from the environment variable named in
`config.json`. It is sent only to the endpoint above, as a bearer token.

Shrike's side: scan content is stored encrypted at rest for the audit trail,
application logs never carry prompt, command or file text, reports show counts
and decisions rather than content, and customer content is never used as
Shrike's test or training material. Privacy policy:
<https://shrikesecurity.com/privacy>. Support: <support@shrikesecurity.com>.

### Runtime

The hook runs on Node 18 or newer. The bundled `shrike-mcp` server needs
Node 20 or newer, because the MCP SDK it is built on depends on a package
that declares that floor. With an older Node the hook still governs; the
MCP tools are what would fail to start.

### Notes for a security review

A plugin that reads a credential and talks to a server is, on its face, the
shape a reviewer is right to look at twice. In order:

- **The key.** Read from the sensitive plugin option, or from the environment
  variable named in `config.json` for CI and fleets. It is sent only to
  `endpoint`, as a bearer token, and the host written in the hook files is
  Shrike's own. No other host is contacted by anything in this folder.
- **The lockfile.** `package.json` and `package-lock.json` pin exactly what
  the `npx` launcher in `.mcp.json` resolves, with registry sources and
  integrity hashes, so what is installed is what was scanned. Nothing else is
  installed.
- **The hook wrapper.** `hooks/shrike-pretooluse.sh` computes only its own
  directory, so the same file works from the plugin folder and from the fleet
  install path, then runs the bundled `hooks/shrike-scan.mjs`. It reaches
  nothing outside this folder.
- **The examples.** `verify.sh` and the skill contain examples of what the
  hook refuses. They are scanned, never executed, and the example host sits
  on the reserved `.example` domain.
- **`install-check.sh`** runs this folder's own installer against a scratch
  home directory and reads back what it wrote. It downloads nothing.

## Fleet install

One command per machine, or one policy for every machine.

```sh
# This machine: registers the hook for Claude Code (~/.claude/settings.json)
# and, when Cursor is installed, its shell hook (~/.cursor/hooks.json).
./install.sh

# One project instead of the whole machine.
./install.sh --project /path/to/repo

# Print the managed settings an organization pushes; writes nothing.
./install.sh --managed --hook-dir /usr/local/lib/shrike-hook
```

The installer copies the hook to `~/.shrike/hook/`, keeps every other hook
already in the settings file, and replaces an older Shrike entry instead of
stacking a second one. Run `./install-check.sh` to see it do all of that in
a scratch directory.

For a fleet, push the hook files to the same directory on every machine and
deliver `managed-settings.template.json` (or the `--managed` output) as
managed settings: `/Library/Application Support/ClaudeCode/managed-settings.json`
on macOS, `/etc/claude-code/managed-settings.json` on Linux and WSL,
`C:\Program Files\ClaudeCode\managed-settings.json` on Windows; or the same
keys as a macOS configuration profile in the `com.anthropic.claudecode`
domain, or as the `Settings` value under `HKLM\SOFTWARE\Policies\ClaudeCode`.
Put the organization's API key in the `env` block, leave `SHRIKE_AGENT_ID`
unset so every machine is a seat, and add `"allowManagedHooksOnly": true` to
run only the hooks the organization deploys. Cursor teams distribute the
shell hook through Cursor's team hooks, or ship `.cursor/hooks.json` with the
`beforeShellExecution` entry the installer writes. The same hook body answers
both editors: a Cursor shell command is scanned like a Claude Code `Bash`
call and answered with `allow`, `ask` or `deny` in Cursor's own shape.

## The scope file

A repository can carry its default scope as a checked-in file,
`.shrike/scope.json`. Every seat that scans from the repository is governed
by it from its first action: the hook finds the file above the working
directory, stops at the repository root, and sends it to Shrike under the
seat's own key when a session first acts, whenever the file changes, and
every half hour after that.

```sh
# Start from the template; never overwrites a file that is already there.
./install.sh --init-scope /path/to/repo
```

```json
{
  "version": 1,
  "purpose": "Coding agent in this repository",
  "allowed_tools": ["command", "file_path", "file_content", "web_search"],
  "forbidden_tools": [],
  "max_duration_seconds": 7200,
  "renewable_seconds": 86400,
  "guardrail_paths": [
    { "path": ".claude/hooks", "tier": "block" },
    { "path": "CLAUDE.md", "tier": "require_approval" },
    { "path": ".gitignore", "tier": "warn" }
  ]
}
```

Three rules decide what the file can do:

- **Under the seat's key the file can only narrow.** What lands is the
  narrowest of the file and the scope already on record for the seat: tools
  intersected, forbidden tools and guardrail paths combined at the strictest
  tier, budget and lifetime at the smaller. A first declaration takes the
  file as written. Editing the file never widens a seat.
- **Privileges need an operator.** `authoring_paths` and a wider
  `work_profile` in the file are set aside under the seat's key and the
  hook says so. An operator applies the file whole from the Agents screen
  (Apply scope file), with a preview of what changes per agent.
- **The file guards itself.** Its own path is added to the guardrail list at
  `require_approval`, so a coding agent's edit to the file is held for a
  person's yes. List it at `block` in the file to refuse such edits outright.

Unknown keys are refused, so a misspelled bound cannot read as no bound.
`enforcement_mode`, `observe_until`, `expires_at` and `agent_id` are not
file fields: observe mode is set per agent on the Agents screen, with an
end, and the seat id is the caller's. A file that cannot be applied is
reported on stderr and the seat keeps whatever scope it already has; the
file never blocks an action by itself. Cursor's hook gates shell commands
only, so a file edit from Cursor is not held by the guardrail; Claude Code's
`Write` and `Edit` are.

## Verify the installation

```sh
export SHRIKE_API_KEY=your_key_here
./verify.sh
```

Runs three synthetic canaries through the hook exactly as Claude Code would:
a benign command (expect allow), a destructive command (expect deny), and an
exfil-shaped file write (expect deny). Nothing is ever executed, because the hook
only scans. Never replace the canaries with working exploits.

## License

Apache-2.0, matching Shrike's other public clients
(`shrike-mcp`, `shrike-guard-js`, `shrike-guard-python`, `shrike-guard-go`).

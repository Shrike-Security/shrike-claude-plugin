#!/usr/bin/env bash
# Shrike hook installer: one command puts the governed-session hook in front
# of the coding agents on this machine, or prints the policy an organization
# pushes to every machine.
#
#   install.sh                       user-level: ~/.claude/settings.json (+ ~/.cursor/hooks.json when Cursor is present)
#   install.sh --project <dir>       project-level: <dir>/.claude/settings.json and <dir>/.cursor/hooks.json
#   install.sh --cursor              also register the Cursor shell hook even if ~/.cursor is absent
#   install.sh --no-cursor           never touch Cursor
#   install.sh --with-key            write $SHRIKE_API_KEY into the settings env block (plain text; your own machine only)
#   install.sh --managed [--hook-dir <path>]
#                                    print managed-settings.json for MDM to stdout and the paths it goes to; writes nothing
#   install.sh --init-scope [<dir>]  write <dir>/.shrike/scope.json from scope.template.json when none exists
#                                    (default: the current directory); the checked-in default scope every seat inherits
#
# What it writes, and never more:
#   ~/.shrike/hook/       the hook files, copied from beside this script
#   ~/.shrike/config.json the hook's defaults, unless one is already there
#   the hooks block, merged into the settings file: PreToolUse, PostToolUse and PostToolUseFailure
#   matched to Bash|Write|Edit|NotebookEdit|WebSearch|WebFetch, plus UserPromptSubmit (the observe
#   plane) and PermissionDenied / PermissionRequest (what the host's own permission layer decided).
#   Other hooks in the file are kept; an older Shrike entry is replaced.
#
# Leave SHRIKE_AGENT_ID unset on a developer machine: the hook derives a seat id
# from the machine user and the seat is counted as a seat. Set it only for an
# autonomous agent (CI, batch, a service), which is metered by what it does.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE=user
PROJECT_DIR=""
CURSOR=auto
WITH_KEY=no
MANAGED=no
HOOK_DIR_MANAGED="/usr/local/lib/shrike-hook"
INIT_SCOPE=no
INIT_SCOPE_DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --project) MODE=project; PROJECT_DIR="${2:?--project needs a directory}"; shift 2 ;;
    --cursor) CURSOR=yes; shift ;;
    --no-cursor) CURSOR=no; shift ;;
    --with-key) WITH_KEY=yes; shift ;;
    --managed) MANAGED=yes; shift ;;
    --hook-dir) HOOK_DIR_MANAGED="${2:?--hook-dir needs a path}"; shift 2 ;;
    --init-scope)
      INIT_SCOPE=yes
      if [ $# -gt 1 ] && [ "${2#-}" = "$2" ]; then INIT_SCOPE_DIR="$2"; shift 2; else shift; fi ;;
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    *) echo "install: unknown option $1" >&2; exit 2 ;;
  esac
done

# --init-scope: the checked-in default scope, from the template, never over
# a file that is already there. Needs no runtime; it is a copy.
if [ "$INIT_SCOPE" = yes ]; then
  dir="${INIT_SCOPE_DIR:-$(pwd)}"
  target="$dir/.shrike/scope.json"
  if [ -f "$target" ]; then
    echo "install: $target already exists; not overwritten"
    exit 0
  fi
  mkdir -p "$dir/.shrike"
  cp "$SCRIPT_DIR/scope.template.json" "$target"
  echo "install: wrote $target from scope.template.json."
  echo "install: edit the tools and guardrail paths, commit it, and every seat that scans from this repository is governed by it from its first action. Authoring paths in it need an operator: Agents screen > Apply scope file."
  exit 0
fi

for tool in jq node; do
  command -v "$tool" >/dev/null 2>&1 || { echo "install: $tool is required (the hook runs on node 18+; jq merges the settings files)" >&2; exit 1; }
done

# The hook registration Claude Code reads, for one absolute hook directory.
#
# This MUST stay in step with hooks/hooks.json: this function is the manual and
# --managed install path, that file is the plugin install path, and a user who
# took one route would otherwise be governed differently from a user who took
# the other. `tests/wiring.test.mjs` compares the two and fails on drift; it
# was added after this list sat at three tools and three events while the
# plugin's own had six of each.
#
# The three events with no matcher are not tool calls: UserPromptSubmit scans
# the prompt on the observe plane and never gates, and PermissionDenied and
# PermissionRequest record what the HOST's own permission layer decided, beside
# our verdict rather than instead of it.
claude_hooks_json() { # $1 = hook dir
  local cmd="\"$1/shrike-pretooluse.sh\""
  local m="Bash|Write|Edit|NotebookEdit|WebSearch|WebFetch"
  jq -n --arg cmd "$cmd" --arg m "$m" '{
    PreToolUse: [{ matcher: $m, hooks: [{ type: "command", command: $cmd, timeout: 30, statusMessage: "Shrike is scanning this action…" }] }],
    PostToolUse: [{ matcher: $m, hooks: [{ type: "command", command: $cmd, timeout: 10 }] }],
    PostToolUseFailure: [{ matcher: $m, hooks: [{ type: "command", command: $cmd, timeout: 10 }] }],
    UserPromptSubmit: [{ hooks: [{ type: "command", command: $cmd, timeout: 15 }] }],
    PermissionDenied: [{ hooks: [{ type: "command", command: $cmd, timeout: 10 }] }],
    PermissionRequest: [{ hooks: [{ type: "command", command: $cmd, timeout: 10 }] }]
  }'
}

# --managed: the policy an organization pushes. Printed, never written to a
# system directory by this script.
if [ "$MANAGED" = yes ]; then
  hooks="$(claude_hooks_json "$HOOK_DIR_MANAGED")"
  jq -n --argjson hooks "$hooks" '{
    hooks: $hooks,
    env: { SHRIKE_API_KEY: "REPLACE_WITH_THE_ORG_API_KEY", SHRIKE_FAILURE_MODE: "closed" }
  }'
  cat >&2 <<EOF

Push the hook files to $HOOK_DIR_MANAGED on every machine (hooks/shrike-scan.mjs,
hooks/shrike-pretooluse.sh, and config.json one directory above them), then deliver
the JSON above as managed settings:
  macOS          /Library/Application Support/ClaudeCode/managed-settings.json
                 or a configuration profile in the com.anthropic.claudecode domain (same keys)
  Linux and WSL  /etc/claude-code/managed-settings.json
  Windows        C:\\Program Files\\ClaudeCode\\managed-settings.json
                 or the Settings value under HKLM\\SOFTWARE\\Policies\\ClaudeCode
Replace the org API key placeholder. Add "allowManagedHooksOnly": true to run only the
hooks the organization deploys. Leave SHRIKE_AGENT_ID unset: each machine is a seat.
For Cursor, distribute the shell hook through its team hooks (web dashboard) or place
.cursor/hooks.json with the beforeShellExecution entry this script writes locally.
EOF
  exit 0
fi

# ---- local install ---------------------------------------------------------
HOOK_HOME="${SHRIKE_HOOK_HOME:-$HOME/.shrike}"
HOOK_DIR="$HOOK_HOME/hook"
mkdir -p "$HOOK_DIR"
cp "$SCRIPT_DIR/hooks/shrike-scan.mjs" "$SCRIPT_DIR/hooks/shrike-pretooluse.sh" "$HOOK_DIR/"
chmod +x "$HOOK_DIR/shrike-pretooluse.sh"
[ -f "$HOOK_HOME/config.json" ] || cp "$SCRIPT_DIR/config.json" "$HOOK_HOME/config.json"

if [ "$MODE" = project ]; then
  CLAUDE_SETTINGS="$PROJECT_DIR/.claude/settings.json"
  CURSOR_HOOKS="$PROJECT_DIR/.cursor/hooks.json"
else
  CLAUDE_SETTINGS="$HOME/.claude/settings.json"
  CURSOR_HOOKS="$HOME/.cursor/hooks.json"
fi

# merge_hooks <settings file> <hooks json>: for each event, drop any earlier
# Shrike entry and append ours; every other hook and key in the file stays.
merge_hooks() {
  local file="$1" hooks="$2" current
  mkdir -p "$(dirname "$file")"
  if [ -f "$file" ]; then current="$(cat "$file")"; else current='{}'; fi
  printf '%s' "$current" | jq --argjson add "$hooks" '
    .hooks = ((.hooks // {}) as $h
      | reduce ($add | keys[]) as $ev ($h;
          .[$ev] = ((.[$ev] // []) | map(select(((.hooks // []) | any(.command | tostring | test("shrike"))) | not))) + $add[$ev]))' \
    > "$file.tmp" && mv "$file.tmp" "$file"
}

merge_hooks "$CLAUDE_SETTINGS" "$(claude_hooks_json "$HOOK_DIR")"
echo "install: Claude Code hooks registered in $CLAUDE_SETTINGS"

if [ "$WITH_KEY" = yes ]; then
  [ -n "${SHRIKE_API_KEY:-}" ] || { echo "install: --with-key needs SHRIKE_API_KEY in the environment" >&2; exit 1; }
  jq --arg k "$SHRIKE_API_KEY" '.env = ((.env // {}) + { SHRIKE_API_KEY: $k })' "$CLAUDE_SETTINGS" > "$CLAUDE_SETTINGS.tmp" && mv "$CLAUDE_SETTINGS.tmp" "$CLAUDE_SETTINGS"
  echo "install: SHRIKE_API_KEY written to the env block of $CLAUDE_SETTINGS"
fi

# Cursor: the same hook body behind beforeShellExecution, in Cursor's file.
want_cursor=no
if [ "$CURSOR" = yes ]; then
  want_cursor=yes
elif [ "$CURSOR" = auto ]; then
  # Cursor is present when its user directory exists, or the project has one.
  if [ -d "$HOME/.cursor" ]; then want_cursor=yes; fi
  if [ "$MODE" = project ] && [ -d "$PROJECT_DIR/.cursor" ]; then want_cursor=yes; fi
fi
if [ "$want_cursor" = yes ]; then
  mkdir -p "$(dirname "$CURSOR_HOOKS")"
  if [ -f "$CURSOR_HOOKS" ]; then current="$(cat "$CURSOR_HOOKS")"; else current='{}'; fi
  printf '%s' "$current" | jq --arg cmd "$HOOK_DIR/shrike-pretooluse.sh" '
    .version = (.version // 1)
    | .hooks = ((.hooks // {})
      | .beforeShellExecution = ((.beforeShellExecution // []) | map(select((.command | tostring | test("shrike")) | not))) + [{ command: $cmd, timeout: 30 }])' \
    > "$CURSOR_HOOKS.tmp" && mv "$CURSOR_HOOKS.tmp" "$CURSOR_HOOKS"
  echo "install: Cursor shell hook registered in $CURSOR_HOOKS"
fi

if [ -z "${SHRIKE_API_KEY:-}" ] && [ "$WITH_KEY" = no ]; then
  echo "install: export SHRIKE_API_KEY where the editor runs, or the hook stays inert (free key: see the README, Setup)"
fi
echo "install: done. Leave SHRIKE_AGENT_ID unset on a developer machine; the hook derives a seat id."

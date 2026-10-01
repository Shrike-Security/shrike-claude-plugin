#!/usr/bin/env bash
# Shrike PreToolUse gate: thin wrapper. All verdict logic lives in
# shrike-scan.mjs, which reads the Claude Code hook payload from stdin.
#
# This wrapper exists so the hook degrades self-explainingly when the node
# runtime is missing: no key → inert; key + no node → failure posture.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/../config.json"

if command -v node >/dev/null 2>&1; then
  exec node "$SCRIPT_DIR/shrike-scan.mjs"
fi

# --- node is not available: the scan cannot run -----------------------------

# Only a gate has a failure posture: Claude Code's PreToolUse, or Cursor's
# beforeShellExecution (a payload with "command" and no event name). The
# outcome reports (PostToolUse, PostToolUseFailure) are records, never
# gates: with no runtime to send them there is nothing to decide, so they
# end quietly.
#
# The classification below mirrors detectHost() in shrike-scan.mjs: an event
# name means Claude Code, a TOP-LEVEL command with no tool_name means Cursor.
# Matching "command" anywhere would catch every Claude Code Bash payload,
# whose tool_input carries that key too, and answer a report with a verdict.
payload="$(cat 2>/dev/null || true)"
cursor=no
case "$payload" in
  *'"hook_event_name"'*)
    # Claude Code. Only PreToolUse gates; the reports end quietly.
    case "$payload" in
      *PreToolUse*) ;;
      *) exit 0 ;;
    esac
    ;;
  *'"tool_name"'*) exit 0 ;;
  *'"command"'*) cursor=yes ;;
  *) exit 0 ;;
esac

# Resolve the env var name that holds the API key (default SHRIKE_API_KEY).
key_env="${SHRIKE_API_KEY_ENV:-}"
if [ -z "$key_env" ] && [ -f "$CONFIG_FILE" ]; then
  key_env="$(sed -n 's/.*"api_key_env"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIG_FILE" | head -n1 || true)"
fi
key_env="${key_env:-SHRIKE_API_KEY}"

# No key configured → the hook is inert regardless of runtime; permit quietly.
if [ -z "${!key_env:-}" ]; then
  echo "[shrike] hook inert: set $key_env to enable enforcement (free key: https://shrikesecurity.com)" >&2
  exit 0
fi

# Key configured but no way to scan → operator failure posture applies.
mode="${SHRIKE_FAILURE_MODE:-}"
if [ -z "$mode" ] && [ -f "$CONFIG_FILE" ]; then
  mode="$(sed -n 's/.*"failure_mode"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIG_FILE" | head -n1 || true)"
fi
mode="${mode:-closed}"

if [ "$mode" = "open" ]; then
  echo "[shrike] WARNING: node runtime not found, action ALLOWED because failure_mode=open. This tool call was NOT scanned. Install Node 18+ to enable scanning." >&2
  [ "$cursor" = yes ] && printf '%s\n' '{"permission":"allow"}'
  exit 0
fi

reason='Shrike unreachable, action held (failure_mode=closed). [node runtime not found: install Node 18+ so the Shrike hook can scan actions]'
if [ "$cursor" = yes ]; then
  printf '{"permission":"deny","user_message":"%s","agent_message":"%s"}\n' "$reason" "$reason"
else
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' "$reason"
fi
exit 0

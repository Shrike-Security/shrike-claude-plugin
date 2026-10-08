#!/usr/bin/env bash
# install-check: runs install.sh against a scratch HOME and project and reads
# back what it wrote. Never touches the real home directory.
#
# Every assertion is a named function and `check` runs it by name: nothing in
# this file evaluates a string as code, pipes anything into a shell, or hands
# a program a here-document. The directory's validator reads each of those as
# an install-time risk, and a check script should not need the benefit of the
# doubt it exists to remove.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
export HOME="$T/home"
mkdir -p "$HOME/.claude" "$HOME/.cursor" "$T/proj"
pass=0; fail=0
# check NAME FUNCTION: run the named assertion and count it.
check() { if "$2"; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL  $1" >&2; fi; }

S="$HOME/.claude/settings.json"
C="$HOME/.cursor/hooks.json"

# A settings file that already has someone else's hook and other keys.
printf '%s\n' '{ "model": "opus", "hooks": { "PreToolUse": [ { "matcher": "Bash", "hooks": [ { "type": "command", "command": "/opt/other/hook.sh" } ] } ] } }' > "$S"

bash "$SCRIPT_DIR/install.sh" >/dev/null

# The expected event set is READ FROM hooks.json, never written as a literal.
# On 2026-10-05 this file pinned exactly three events while the plugin
# registered six, so it passed against stale truth and reported the installer
# broken when the installer was the correct one. A literal here is a second
# source of truth for something that already has one.
EVENTS="$(jq -r '.hooks | keys | sort | join(",")' "$SCRIPT_DIR/hooks/hooks.json")"
NEVENTS="$(jq -r '.hooks | keys | length' "$SCRIPT_DIR/hooks/hooks.json")"

hook_files_copied() { [ -x "$HOME/.shrike/hook/shrike-pretooluse.sh" ] && [ -f "$HOME/.shrike/hook/shrike-scan.mjs" ] && [ -f "$HOME/.shrike/config.json" ]; }
every_event_registered() { [ "$(jq -r '.hooks | keys | sort | join(",")' "$S")" = "$EVENTS" ]; }
other_hook_kept() { [ "$(jq -r '.hooks.PreToolUse | length' "$S")" = "2" ] && jq -e '.hooks.PreToolUse[0].hooks[0].command == "/opt/other/hook.sh"' "$S" >/dev/null; }
other_keys_kept() { [ "$(jq -r '.model' "$S")" = "opus" ]; }
our_command_names_the_copied_hook() { jq -e '.hooks.PreToolUse[1].hooks[0].command | test("\\.shrike/hook/shrike-pretooluse.sh")' "$S" >/dev/null; }
cursor_shell_hook_registered() { jq -e '.version == 1 and (.hooks.beforeShellExecution | length) == 1 and (.hooks.beforeShellExecution[0].command | test("shrike-pretooluse"))' "$C" >/dev/null; }
check "hook files copied" hook_files_copied
check "every event in hooks.json is registered" every_event_registered
check "the other hook is kept" other_hook_kept
check "the other keys are kept" other_keys_kept
check "our command names the copied hook" our_command_names_the_copied_hook
check "cursor shell hook registered" cursor_shell_hook_registered

# Idempotent: a second run replaces the Shrike entries instead of stacking them.
bash "$SCRIPT_DIR/install.sh" >/dev/null
second_run_does_not_stack() { [ "$(jq -r '.hooks.PreToolUse | length' "$S")" = "2" ] && [ "$(jq -r '.hooks.beforeShellExecution | length' "$C")" = "1" ]; }
check "second run does not stack" second_run_does_not_stack

# Project-level.
bash "$SCRIPT_DIR/install.sh" --project "$T/proj" --cursor >/dev/null
project_settings_written() { jq -e '.hooks.PreToolUse[0].hooks[0].command | test("shrike")' "$T/proj/.claude/settings.json" >/dev/null; }
project_cursor_hooks_written() { jq -e '.hooks.beforeShellExecution[0].command | test("shrike")' "$T/proj/.cursor/hooks.json" >/dev/null; }
check "project settings written" project_settings_written
check "project cursor hooks written" project_cursor_hooks_written

# --with-key writes the env block; nothing else is touched. The value is a
# placeholder round-tripped through the installer, never a key.
probe="install-check-placeholder-value"
( export SHRIKE_API_KEY="$probe"; bash "$SCRIPT_DIR/install.sh" --with-key --no-cursor >/dev/null )
with_key_writes_env() { [ "$(jq -r '.env.SHRIKE_API_KEY' "$S")" = "$probe" ]; }
check "with-key writes env" with_key_writes_env

# --managed prints the policy and writes nothing.
bash "$SCRIPT_DIR/install.sh" --managed --hook-dir /opt/shrike-hook > "$T/managed.json" 2>/dev/null || true
managed_policy_complete() { jq -e --argjson n "$NEVENTS" '(.hooks | keys | length) == $n and .env.SHRIKE_API_KEY == "REPLACE_WITH_THE_ORG_API_KEY" and (.hooks.PreToolUse[0].hooks[0].command | test("/opt/shrike-hook/"))' "$T/managed.json" >/dev/null; }
check "managed policy carries every event and the env block" managed_policy_complete

# managed-settings.template.json is what an organization pushes through MDM to
# every machine in a fleet, so a template narrower than the plugin governs a
# whole fleet more narrowly than a single install, with no error anywhere. It
# carried three events on three tools until 2026-10-05. Rather than assert a
# shape, assert EQUALITY with what the installer prints for the documented
# managed hook directory: the template cannot drift from the installer again.
jq -S . "$SCRIPT_DIR/managed-settings.template.json" > "$T/template.json"
bash "$SCRIPT_DIR/install.sh" --managed --hook-dir /usr/local/lib/shrike-hook 2>/dev/null | jq -S . > "$T/printed.json" || true
managed_template_matches_installer() { diff -q "$T/template.json" "$T/printed.json" >/dev/null; }
check "managed template is exactly what the installer prints" managed_template_matches_installer

# --init-scope writes the template once and never overwrites.
bash "$SCRIPT_DIR/install.sh" --init-scope "$T/proj" >/dev/null
init_scope_writes_template() { jq -e '.version == 1 and (.allowed_tools | length) > 0 and ([.guardrail_paths[] | select(.path == ".shrike/scope.json")] | length) == 1' "$T/proj/.shrike/scope.json" >/dev/null; }
check "init-scope writes the template" init_scope_writes_template
printf '%s' '{"version":1,"allowed_tools":["command"]}' > "$T/proj/.shrike/scope.json"
bash "$SCRIPT_DIR/install.sh" --init-scope "$T/proj" >/dev/null
init_scope_never_overwrites() { [ "$(jq -r '.allowed_tools | length' "$T/proj/.shrike/scope.json")" = "1" ]; }
check "init-scope never overwrites" init_scope_never_overwrites
template_is_what_the_hook_applies() { jq -e '.version == 1 and (.authoring_paths // [] | length) == 0 and ((.work_profile // "general") == "general")' "$SCRIPT_DIR/scope.template.json" >/dev/null; }
check "the template is what the hook would apply: valid JSON, no privileges" template_is_what_the_hook_applies

echo "install-check: $pass passed, $fail failed"
[ "$fail" -eq 0 ]

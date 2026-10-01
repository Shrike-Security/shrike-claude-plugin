#!/usr/bin/env bash
# install-check: runs install.sh against a scratch HOME and project and reads
# back what it wrote. Never touches the real home directory.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
export HOME="$T/home"
mkdir -p "$HOME/.claude" "$HOME/.cursor" "$T/proj"
pass=0; fail=0
check() { if eval "$2"; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL  $1" >&2; fi; }

# A settings file that already has someone else's hook and other keys.
cat > "$HOME/.claude/settings.json" <<'EOF'
{ "model": "opus", "hooks": { "PreToolUse": [ { "matcher": "Bash", "hooks": [ { "type": "command", "command": "/opt/other/hook.sh" } ] } ] } }
EOF

bash "$SCRIPT_DIR/install.sh" >/dev/null
S="$HOME/.claude/settings.json"
check "hook files copied" '[ -x "$HOME/.shrike/hook/shrike-pretooluse.sh" ] && [ -f "$HOME/.shrike/hook/shrike-scan.mjs" ] && [ -f "$HOME/.shrike/config.json" ]'
check "three events registered" '[ "$(jq -r ".hooks | keys | sort | join(\",\")" "$S")" = "PostToolUse,PostToolUseFailure,PreToolUse" ]'
check "the other hook is kept" '[ "$(jq -r ".hooks.PreToolUse | length" "$S")" = "2" ] && jq -e ".hooks.PreToolUse[0].hooks[0].command == \"/opt/other/hook.sh\"" "$S" >/dev/null'
check "the other keys are kept" '[ "$(jq -r .model "$S")" = "opus" ]'
check "our command names the copied hook" 'jq -e ".hooks.PreToolUse[1].hooks[0].command | test(\"\\\\.shrike/hook/shrike-pretooluse.sh\")" "$S" >/dev/null'
check "cursor shell hook registered" 'jq -e ".version == 1 and (.hooks.beforeShellExecution | length) == 1 and (.hooks.beforeShellExecution[0].command | test(\"shrike-pretooluse\"))" "$HOME/.cursor/hooks.json" >/dev/null'

# Idempotent: a second run replaces the Shrike entries instead of stacking them.
bash "$SCRIPT_DIR/install.sh" >/dev/null
check "second run does not stack" '[ "$(jq -r ".hooks.PreToolUse | length" "$S")" = "2" ] && [ "$(jq -r ".hooks.beforeShellExecution | length" "$HOME/.cursor/hooks.json")" = "1" ]'

# Project-level.
bash "$SCRIPT_DIR/install.sh" --project "$T/proj" --cursor >/dev/null
check "project settings written" 'jq -e ".hooks.PreToolUse[0].hooks[0].command | test(\"shrike\")" "$T/proj/.claude/settings.json" >/dev/null'
check "project cursor hooks written" 'jq -e ".hooks.beforeShellExecution[0].command | test(\"shrike\")" "$T/proj/.cursor/hooks.json" >/dev/null'

# --with-key writes the env block; nothing else is touched.
SHRIKE_API_KEY=shrike_test_key_for_install_check bash "$SCRIPT_DIR/install.sh" --with-key --no-cursor >/dev/null
check "with-key writes env" '[ "$(jq -r .env.SHRIKE_API_KEY "$S")" = "shrike_test_key_for_install_check" ]'

# --managed prints the policy and writes nothing.
M="$(bash "$SCRIPT_DIR/install.sh" --managed --hook-dir /opt/shrike-hook 2>/dev/null)"
check "managed policy is valid JSON with the three events and the env block" 'printf "%s" "$M" | jq -e "(.hooks | keys | length) == 3 and .env.SHRIKE_API_KEY == \"REPLACE_WITH_THE_ORG_API_KEY\" and (.hooks.PreToolUse[0].hooks[0].command | test(\"/opt/shrike-hook/\"))" >/dev/null'
check "managed template file matches the printed shape" 'jq -e "(.hooks | keys | length) == 3 and .env.SHRIKE_FAILURE_MODE == \"closed\"" "$SCRIPT_DIR/managed-settings.template.json" >/dev/null'

# --init-scope writes the template once and never overwrites.
bash "$SCRIPT_DIR/install.sh" --init-scope "$T/proj" >/dev/null
check "init-scope writes the template" 'jq -e ".version == 1 and (.allowed_tools | length) > 0 and ([.guardrail_paths[] | select(.path == \".shrike/scope.json\")] | length) == 1" "$T/proj/.shrike/scope.json" >/dev/null'
printf '{"version":1,"allowed_tools":["command"]}' > "$T/proj/.shrike/scope.json"
bash "$SCRIPT_DIR/install.sh" --init-scope "$T/proj" >/dev/null
check "init-scope never overwrites" '[ "$(jq -r ".allowed_tools | length" "$T/proj/.shrike/scope.json")" = "1" ]'
check "the template is what the hook would apply: valid JSON, no privileges" 'jq -e ".version == 1 and (.authoring_paths // [] | length) == 0 and ((.work_profile // \"general\") == \"general\")" "$SCRIPT_DIR/scope.template.json" >/dev/null'

echo "install-check: $pass passed, $fail failed"
[ "$fail" -eq 0 ]

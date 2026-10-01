#!/usr/bin/env node
/**
 * Shrike PreToolUse hook: thin client for Claude Code.
 *
 * Reads the Claude Code PreToolUse hook payload from stdin, sends the
 * side-effecting action to the Shrike enforce API, and maps the verdict
 * onto Claude Code's permission decision:
 *
 *   allow / warn                → permit (exit 0; warn is noted on stderr)
 *   require_approval / block    → deny (hookSpecificOutput JSON on stdout)
 *
 * Failure posture (operator policy, config `failure_mode`):
 *   closed (default): Shrike unreachable → deny ("action held")
 *   open: Shrike unreachable → permit with a loud warning
 * A real verdict is never optional: an actual `block` response is always
 * enforced regardless of failure_mode. failure_mode only governs what
 * happens when no verdict could be obtained.
 *
 * No API key configured → the hook is inert: permit, with a one-line
 * setup pointer on stderr (once per Claude Code session).
 *
 * This is a THIN CLIENT. It contains zero detection logic. All scanning
 * runs on the Shrike backend; this script only transports the action and
 * routes on the returned verdict.
 *
 * No external dependencies: Node 18+ built-ins only (fetch, fs, path).
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync, statSync, unlinkSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir, userInfo, hostname } from 'node:os';
import { createHash } from 'node:crypto';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Matches the backend MaxRequestBodySize: fail fast before the round trip. */
const MAX_CONTENT_BYTES = 100 * 1024;

/** Default scan timeout: covers the L7 path (~2-3s worst case) with margin. */
const DEFAULT_TIMEOUT_MS = 10000;

const DEFAULT_CONFIG = {
  api_key_env: 'SHRIKE_API_KEY',
  failure_mode: 'closed',
  gated_tools: ['Bash', 'Write', 'Edit'],
  endpoint: 'https://api.shrikesecurity.com/agent',
};

const SOURCE_APPLICATION = 'shrike-claude-code-plugin';

// ---------------------------------------------------------------------------
// Hosts: the same hook body answers two editors
// ---------------------------------------------------------------------------

// Claude Code sends a payload with hook_event_name, tool_name and tool_input
// and reads a hookSpecificOutput decision. Cursor's beforeShellExecution
// sends { command, cwd } and reads { permission, user_message, agent_message }.
// The scan, the verdict mapping and the outcome record are identical; only
// the envelope differs, and it is decided once, here.
let HOST = 'claude-code';

function detectHost(payload) {
  if (payload && typeof payload.hook_event_name === 'string') return 'claude-code';
  if (payload && typeof payload.command === 'string' && payload.tool_name === undefined) return 'cursor';
  return 'claude-code';
}

/** The Claude Code tool call a Cursor payload stands for, or null. */
function cursorToolCall(payload) {
  if (typeof payload.command === 'string') {
    const input = { command: payload.command };
    if (typeof payload.cwd === 'string' && payload.cwd) input.cwd = payload.cwd;
    return { tool_name: 'Bash', tool_input: input };
  }
  return null;
}

function sourceApplication() {
  return HOST === 'cursor' ? 'shrike-cursor-hook' : SOURCE_APPLICATION;
}

// ---------------------------------------------------------------------------
// Output helpers: every path exits 0; the decision travels as JSON on stdout.
// ---------------------------------------------------------------------------

/** Permit the tool call: Claude Code reads silence as allow, Cursor reads the word. */
function permit() {
  if (HOST === 'cursor') process.stdout.write(JSON.stringify({ permission: 'allow' }) + '\n');
  process.exit(0);
}

/** Deny the tool call: emit the host's decision envelope, exit 0. */
function deny(reason) {
  if (HOST === 'cursor') {
    process.stdout.write(JSON.stringify({ permission: 'deny', user_message: reason, agent_message: reason }) + '\n');
    process.exit(0);
  }
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: reason,
      },
    }) + '\n'
  );
  process.exit(0);
}

/**
 * Hold the tool call for a person's answer. Cursor has a person at the
 * keyboard and an `ask` permission for exactly this; Claude Code keeps the
 * plugin's existing posture, a deny with the reason, so nothing changes for
 * an editor that already had it.
 */
function hold(reason) {
  if (HOST === 'cursor') {
    process.stdout.write(JSON.stringify({ permission: 'ask', user_message: reason, agent_message: reason }) + '\n');
    process.exit(0);
  }
  deny(reason);
}

function warnStderr(msg) {
  process.stderr.write(`[shrike] ${msg}\n`);
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

function loadConfig() {
  const here = dirname(fileURLToPath(import.meta.url));
  const configPath = join(here, '..', 'config.json');
  let fileConfig = {};
  try {
    fileConfig = JSON.parse(readFileSync(configPath, 'utf8'));
  } catch {
    // Missing/invalid config file → ship defaults. Not a failure condition.
  }

  const merged = { ...DEFAULT_CONFIG, ...fileConfig };

  // Environment variable overrides (highest precedence).
  if (process.env.SHRIKE_BACKEND_URL) merged.endpoint = process.env.SHRIKE_BACKEND_URL;
  if (process.env.SHRIKE_FAILURE_MODE) merged.failure_mode = process.env.SHRIKE_FAILURE_MODE;
  if (process.env.SHRIKE_GATED_TOOLS) {
    merged.gated_tools = process.env.SHRIKE_GATED_TOOLS.split(',').map((t) => t.trim()).filter(Boolean);
  }
  if (process.env.SHRIKE_API_KEY_ENV) merged.api_key_env = process.env.SHRIKE_API_KEY_ENV;

  if (merged.failure_mode !== 'open' && merged.failure_mode !== 'closed') {
    warnStderr(`unknown failure_mode "${merged.failure_mode}", using "closed"`);
    merged.failure_mode = 'closed';
  }

  merged.timeout_ms = Number(process.env.SHRIKE_SCAN_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS;
  return merged;
}

// ---------------------------------------------------------------------------
// Inert-mode setup pointer: printed once per Claude Code session.
// ---------------------------------------------------------------------------

function setupPointerOncePerSession(sessionId, keyEnvName) {
  const line = `Shrike hook installed but inert: set ${keyEnvName} to enable enforcement (free key: https://shrikesecurity.com)`;
  try {
    const dir = join(tmpdir(), 'shrike-claude-code');
    mkdirSync(dir, { recursive: true });
    const marker = join(dir, `setup-pointer-${sessionId || 'nosession'}`);
    if (existsSync(marker)) return; // already told this session
    writeFileSync(marker, String(Date.now()));
    warnStderr(line);
  } catch {
    // Marker bookkeeping failed → fall back to printing every time.
    warnStderr(line);
  }
}

// ---------------------------------------------------------------------------
// Payload mapping: Claude Code tool call → Shrike specialized scan request
// ---------------------------------------------------------------------------

/**
 * Maps a gated tool call to the /api/scan/enforce/specialized request body.
 * Returns null when there is nothing scannable (defensive: permit).
 *
 * Wire contract (backend SpecializedScanRequest):
 *   { content, content_type, context: {string: string} }
 *   - Bash        → content_type "command",      content = the command
 *   - Write/Edit  → content_type "file_content", content = file path,
 *                   context.content = the content being written
 *     (one call scans BOTH the path and the body: ScanFileWithContent)
 */
// ---------------------------------------------------------------------------
// Outcomes: what became of a scanned action
// ---------------------------------------------------------------------------

// Shrike judges before execution, so a scan proves an action was authorized,
// never that it ran. PostToolUse fires after the tool ran, PostToolUseFailure
// after it failed; neither carries the scan id, so the PreToolUse pass leaves
// a marker keyed by a digest of the tool input (the only thing the events
// share) holding the scan id and nothing else. The report is identifiers and
// a status: never the command, the file body or the error text.
const OUTCOME_MAX_AGE_MS = 24 * 60 * 60 * 1000;

function outcomeDir() {
  const dir = join(tmpdir(), 'shrike-claude-code', 'actions');
  mkdirSync(dir, { recursive: true });
  return dir;
}

function actionKey(sessionId, toolInput) {
  return createHash('sha256')
    .update(`${sessionId || ''}\n${JSON.stringify(toolInput ?? {})}`)
    .digest('hex')
    .slice(0, 32);
}

function rememberAction(sessionId, toolInput, scanId) {
  if (!scanId) return;
  try {
    writeFileSync(join(outcomeDir(), actionKey(sessionId, toolInput)), scanId);
  } catch {
    // A marker that could not be written costs one outcome report, never a verdict.
  }
}

function takeAction(sessionId, toolInput) {
  try {
    const file = join(outcomeDir(), actionKey(sessionId, toolInput));
    if (!existsSync(file)) return '';
    const scanId = readFileSync(file, 'utf8').trim();
    unlinkSync(file);
    return scanId;
  } catch {
    return '';
  }
}

// Markers for actions that never ran (a prompt answered no, a session that
// ended) are swept after a day. Sweeping is bookkeeping, not a decision.
function sweepActions() {
  try {
    const dir = outcomeDir();
    const cutoff = Date.now() - OUTCOME_MAX_AGE_MS;
    for (const name of readdirSync(dir)) {
      const file = join(dir, name);
      try {
        if (statSync(file).mtimeMs < cutoff) unlinkSync(file);
      } catch { /* already gone */ }
    }
  } catch { /* nothing to sweep */ }
}

/** Exit status when the host offers one as a number; undefined otherwise. */
function exitStatusOf(payload) {
  const r = payload?.tool_response;
  for (const v of [r?.exit_code, r?.exitCode, r?.status, payload?.exit_code]) {
    if (Number.isInteger(v)) return v;
  }
  return undefined;
}

async function reportOutcome(config, apiKey, payload, outcome) {
  const scanId = takeAction(payload.session_id, payload.tool_input);
  if (!scanId) return; // not scanned by this hook, or blocked: nothing to report
  const body = { scan_id: scanId, outcome, ran_at: new Date().toISOString(), source: sourceApplication() };
  const exitStatus = exitStatusOf(payload);
  if (exitStatus !== undefined) body.exit_status = exitStatus;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.min(config.timeout_ms, 5000));
  try {
    await fetch(`${config.endpoint}/api/scan/outcome`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } catch {
    // A report that did not arrive leaves the action unconfirmed, which is
    // what it was; never a reason to stop the editor.
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Identity: a seat unless the operator named the agent
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Scope file: the default scope by policy, checked into the repository
// ---------------------------------------------------------------------------

// A repository may carry .shrike/scope.json: the bounds every seat that
// scans from it is governed by, from its first action. The hook sends the
// file to the backend under the seat's own key when the session first acts,
// whenever the file changes, and every half hour after that. Under that key
// the backend takes the narrowest of the file and the row already on file,
// and drops the file's privileges (authoring paths, a wider trade): an
// operator applies those on the Agents screen. The file's own path joins the
// guardrail list at require_approval, so an edit to it is held for a person.
// Nothing here ever blocks an action: a file that cannot be applied is said
// on stderr, and the seat is governed by whatever row it already has.
const SCOPE_FILE_REL = '.shrike/scope.json';
const SCOPE_APPLY_REFRESH_MS = 30 * 60 * 1000;
const SCOPE_APPLY_TIMEOUT_MS = 5000;

/** The repository's scope file at or above `startDir`, stopping at the repository root. */
function findScopeFile(startDir) {
  let dir = resolve(startDir || process.cwd());
  for (let i = 0; i < 64; i++) {
    const candidate = join(dir, '.shrike', 'scope.json');
    if (existsSync(candidate)) return { path: candidate, root: dir };
    if (existsSync(join(dir, '.git'))) return null;
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
  return null;
}

function scopeStampPath(agentId, root) {
  const key = createHash('sha256').update(`${agentId}\n${root}`).digest('hex').slice(0, 24);
  return join(tmpdir(), 'shrike-claude-code', `scope-${key}.json`);
}

function readScopeStamp(p) {
  try {
    return JSON.parse(readFileSync(p, 'utf8'));
  } catch {
    return null;
  }
}

function writeScopeStamp(p, stamp) {
  try {
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, JSON.stringify(stamp));
  } catch {
    // No stamp means the next action applies again: correct, only chattier.
  }
}

/** One line for what the row kept over the file, or '' when it kept nothing. */
function describeNarrowing(n) {
  if (!n) return '';
  const parts = [];
  if (n.wildcard_dropped) parts.push('the row names its tools, so "*" was not taken');
  if (n.dropped_tools?.length) parts.push(`tools the row does not allow: ${n.dropped_tools.join(', ')}`);
  if (n.kept_forbidden_tools?.length) parts.push(`tools the row forbids: ${n.kept_forbidden_tools.join(', ')}`);
  if (n.kept_guardrail_paths?.length) parts.push(`guardrails kept from the row: ${n.kept_guardrail_paths.join(', ')}`);
  if (n.kept_action_budget) parts.push("the row's smaller action budget");
  if (n.kept_duration) parts.push("the row's shorter lifetime");
  if (n.kept_renewal) parts.push("the row's renewal window");
  return parts.join('; ');
}

async function applyScopeFile(config, apiKey, identity, cwd) {
  const found = findScopeFile(cwd);
  if (!found) return;
  let raw;
  try {
    raw = readFileSync(found.path, 'utf8');
  } catch {
    return;
  }
  const fileSha = createHash('sha256').update(raw).digest('hex');
  const stampPath = scopeStampPath(identity.agent_id, found.root);
  const stamp = readScopeStamp(stampPath);
  const now = Date.now();
  if (stamp && stamp.file_sha === fileSha && now - (stamp.at || 0) < SCOPE_APPLY_REFRESH_MS) return;
  const changed = !stamp || stamp.file_sha !== fileSha;

  let file;
  try {
    file = JSON.parse(raw);
  } catch {
    if (changed) warnStderr(`${SCOPE_FILE_REL} is not valid JSON; this seat keeps whatever scope it already has`);
    writeScopeStamp(stampPath, { at: now, file_sha: fileSha, status: 'invalid' });
    return;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SCOPE_APPLY_TIMEOUT_MS);
  let response;
  let text = '';
  try {
    response = await fetch(`${config.endpoint}/api/v1/agent/scope/apply-file`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({ agent_id: identity.agent_id, file, file_path: SCOPE_FILE_REL }),
      signal: controller.signal,
    });
    text = await response.text();
  } catch (err) {
    clearTimeout(timer);
    warnStderr(`scope file not applied (${err?.name === 'AbortError' ? 'timeout' : 'network error'}); will try again on the next action`);
    return;
  }
  clearTimeout(timer);
  let data = {};
  try {
    data = JSON.parse(text);
  } catch {
    data = { error: text.trim() };
  }

  if (response.status === 400) {
    // The backend refused the file by name: a key it does not read, a bound
    // that does not validate. Said once per change; retried when it changes.
    if (changed) warnStderr(`${SCOPE_FILE_REL} refused: ${data.error || 'invalid'}. This seat keeps whatever scope it already has.`);
    writeScopeStamp(stampPath, { at: now, file_sha: fileSha, status: 'invalid' });
    return;
  }
  if (!response.ok) {
    warnStderr(`scope file not applied (${response.status === 401 ? 'API key rejected' : `HTTP ${response.status}`}); will try again on the next action`);
    return;
  }

  const result = data?.results?.[0] || {};
  const narrowing = describeNarrowing(result.narrowed_to_row);
  writeScopeStamp(stampPath, { at: now, file_sha: fileSha, status: result.status || 'applied', narrowed: narrowing });
  if (result.status === 'refused') {
    warnStderr(result.reason === 'ceiling_reached'
      ? "scope file not applied: this seat's renewal window has closed; an operator refreshes it on the Agents screen"
      : `scope file not applied (${result.reason || 'refused'}); an operator applies it on the Agents screen`);
    return;
  }
  if (result.status === 'error') {
    warnStderr(`scope file not applied: ${result.detail || result.reason || 'error'}`);
    return;
  }
  if (changed) {
    const tools = Array.isArray(file.allowed_tools) ? file.allowed_tools.length : 0;
    const guards = result.scope?.guardrail_paths?.length ?? (Array.isArray(file.guardrail_paths) ? file.guardrail_paths.length : 0) + 1;
    warnStderr(`scope ${result.status || 'applied'} from ${SCOPE_FILE_REL} for ${identity.agent_id}: ${tools} tool${tools === 1 ? '' : 's'}, ${guards} guardrail path${guards === 1 ? '' : 's'}; the file guards itself`);
    if (data.privileges_dropped?.length) warnStderr(`the scope file's ${data.privileges_dropped.join(' and ')} need an operator: Agents screen > Apply scope file`);
  }
  if (narrowing && narrowing !== (stamp?.narrowed || '')) {
    warnStderr(`the scope already on file for this seat is narrower than ${SCOPE_FILE_REL}: ${narrowing}. An operator applies the file whole on the Agents screen.`);
  }
}

// A developer machine is a seat: a person behind the agent, one row on the
// Agents screen per seat, billed as a seat. The hook derives the seat id from
// the machine user and host (seat:<user>@<host>, lowercased, reduced to
// [a-z0-9._-]) so the same person on the same machine is the same row every
// day. SHRIKE_AGENT_ID overrides it for an autonomous agent (a CI runner, a
// batch job), which declares its own id and is metered by what it does. The
// backend derives the same shape from the same examples.
function seatPart(s) {
  return String(s ?? '')
    .trim()
    .toLowerCase()
    .replace(/[ @/\\]/g, '-')
    .replace(/[^a-z0-9._-]/g, '')
    .replace(/^[-.]+|[-.]+$/g, '')
    .slice(0, 64);
}

function seatAgentId() {
  let user = '';
  let host = '';
  try { user = userInfo().username; } catch { /* no account name available */ }
  try { host = hostname(); } catch { /* no host name available */ }
  const u = seatPart(user);
  const h = seatPart(host);
  if (!u && !h) return '';
  if (!h) return `seat:${u}`;
  if (!u) return `seat:unknown@${h}`;
  return `seat:${u}@${h}`;
}

function resolveAgentIdentity() {
  const declared = (process.env.SHRIKE_AGENT_ID || '').trim();
  if (declared) {
    return { agent_id: declared, identity_class: declared.startsWith('seat:') ? 'seat' : 'declared' };
  }
  const seat = seatAgentId();
  if (seat) return { agent_id: seat, identity_class: 'seat' };
  return { agent_id: 'claude-code', identity_class: 'declared' };
}

function buildScanRequest(toolName, toolInput, sessionId) {
  const identity = resolveAgentIdentity();
  const context = {
    session_id: sessionId || '',
    agent_id: identity.agent_id,
    identity_class: identity.identity_class,
    source_application: sourceApplication(),
  };

  if (toolName === 'Bash') {
    const command = toolInput?.command;
    if (!command) return null;
    return { content: command, content_type: 'command', context };
  }

  if (toolName === 'Write' || toolName === 'Edit') {
    const filePath = toolInput?.file_path;
    if (!filePath) return null;
    // Write carries the full body in `content`; Edit carries the text being
    // introduced in `new_string`. Either way, that is the content with a
    // side effect: scan it together with the path.
    const body = toolName === 'Write' ? (toolInput?.content ?? '') : (toolInput?.new_string ?? '');
    context.content = body;
    return { content: filePath, content_type: 'file_content', context };
  }

  // Tool gated by matcher but not mapped: permit rather than break the
  // editor on a tool this client does not understand.
  return null;
}

// ---------------------------------------------------------------------------
// Verdict mapping
// ---------------------------------------------------------------------------

/** Compose the deny reason shown to Claude from the enforce response. */
function denyReason(verdict, data) {
  const parts = [];
  const userMessage = data?.violations?.find((v) => v.user_message)?.user_message;
  if (userMessage) {
    parts.push(userMessage);
  } else {
    parts.push(
      verdict === 'require_approval'
        ? 'Shrike: this action requires human approval before it can run.'
        : 'Shrike blocked this action.'
    );
  }
  const instruction = data?.recovery?.instruction;
  if (instruction) parts.push(`Recovery: ${instruction}`);
  if (verdict === 'require_approval' && data?.approval_info?.approval_id) {
    parts.push(
      `Approval id: ${data.approval_info.approval_id}. A human can approve it in the Shrike dashboard; check status with the shrike-mcp check_approval tool.`
    );
  }
  parts.push('Do not retry this action verbatim; adjust your approach or surface this to the user.');
  return parts.join(' ');
}

/** Apply the operator failure posture when no verdict could be obtained. */
function applyFailurePosture(config, detail) {
  if (config.failure_mode === 'open') {
    warnStderr(
      `WARNING: Shrike unreachable (${detail}), action ALLOWED because failure_mode=open. ` +
        'This tool call was NOT scanned.'
    );
    permit();
  }
  deny(`Shrike unreachable, action held (failure_mode=closed). [${detail}]`);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  // 1. Read the hook payload from stdin.
  let payload;
  try {
    const raw = readFileSync(0, 'utf8');
    payload = JSON.parse(raw);
  } catch {
    // Unparseable hook input: nothing to scan, nothing to enforce on.
    warnStderr('could not parse hook input; permitting');
    permit();
  }

  HOST = detectHost(payload);
  if (HOST === 'cursor') {
    // Cursor's shell hook: the same gate, in Cursor's envelope.
    const call = cursorToolCall(payload);
    if (!call) permit();
    payload = { ...payload, hook_event_name: 'PreToolUse', tool_name: call.tool_name, tool_input: call.tool_input, session_id: payload.conversation_id || payload.session_id || '' };
  }

  const toolName = payload.tool_name;
  const toolInput = payload.tool_input;
  const sessionId = payload.session_id;

  const config = loadConfig();

  // 2. Not a gated tool → permit immediately (matcher should prevent this).
  if (!config.gated_tools.includes(toolName)) permit();

  // 3. No API key → hook is inert. Permit with a setup pointer.
  const apiKey = process.env[config.api_key_env];
  if (!apiKey) {
    setupPointerOncePerSession(sessionId, config.api_key_env);
    permit();
  }

  // 3b. After the tool ran, or failed: report what became of the action the
  //     PreToolUse pass scanned, then end. These events never gate.
  const event = payload.hook_event_name;
  if (event === 'PostToolUse' || event === 'PostToolUseFailure') {
    await reportOutcome(config, apiKey, payload, event === 'PostToolUse' ? 'executed' : 'failed');
    sweepActions();
    permit();
  }

  // 3c. The repository's scope file, applied under this seat's key before
  //     the action is judged, so the first action is already governed by it.
  await applyScopeFile(config, apiKey, resolveAgentIdentity(), payload.cwd || toolInput?.cwd);

  // 4. Build the scan request.
  const scanRequest = buildScanRequest(toolName, toolInput, sessionId);
  if (!scanRequest) permit();

  // 5. Size guard: matches the backend request-body limit. A payload the
  //    backend would reject cannot be scanned; a truncated scan would be a
  //    partial verdict, so fail fast with a self-explaining reason instead.
  const totalBytes = Buffer.byteLength(scanRequest.content) + Buffer.byteLength(scanRequest.context.content ?? '');
  if (totalBytes > MAX_CONTENT_BYTES) {
    deny(
      `Shrike: content too large to scan (${Math.round(totalBytes / 1024)}KB > ${MAX_CONTENT_BYTES / 1024}KB). ` +
        'Split the write into smaller pieces so each can be scanned.'
    );
  }

  // 6. Call the enforce endpoint.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.timeout_ms);
  let response;
  try {
    response = await fetch(`${config.endpoint}/api/scan/enforce/specialized`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify(scanRequest),
      signal: controller.signal,
    });
  } catch (err) {
    clearTimeout(timer);
    const detail = err?.name === 'AbortError' ? `timeout after ${config.timeout_ms}ms` : 'network error';
    applyFailurePosture(config, detail);
    return; // not reached: applyFailurePosture always exits
  }
  clearTimeout(timer);

  if (!response.ok) {
    // 401 is a configuration problem worth naming precisely.
    const detail = response.status === 401 ? 'API key rejected (401)' : `HTTP ${response.status}`;
    applyFailurePosture(config, detail);
    return;
  }

  let data;
  try {
    data = await response.json();
  } catch {
    applyFailurePosture(config, 'unparseable response');
    return;
  }

  // 7. Route on the verdict. `action` is the authoritative top-level
  //    decision on the enforce wire shape (refuse_tier duplicates it).
  const verdict = data.action || data.refuse_tier;
  // The scan id is what the outcome report names. Remembered for every
  // action that may still run: allowed, warned, or held for a person's
  // answer. A blocked action never runs, so nothing is remembered.
  const scanId = data.scan_id || data.request_id || data?.audit?.scan_id || '';
  switch (verdict) {
    case 'allow':
      rememberAction(sessionId, toolInput, scanId);
      permit();
      break;
    case 'warn': {
      const note = data?.violations?.find((v) => v.user_message)?.user_message || data?.recovery?.instruction;
      warnStderr(`warn verdict on ${toolName}${note ? `: ${note}` : ''}, proceeding.`);
      rememberAction(sessionId, toolInput, scanId);
      permit();
      break;
    }
    case 'require_approval':
      rememberAction(sessionId, toolInput, scanId);
      hold(denyReason(verdict, data));
      break;
    case 'block':
      deny(denyReason(verdict, data));
      break;
    default:
      // Unknown verdict: a verdict we cannot interpret is no verdict.
      applyFailurePosture(config, `unknown verdict "${verdict}"`);
  }
}

main().catch((err) => {
  // Last-resort guard: never crash the editor with an unexplained non-zero
  // exit. Unexpected internal error → failure posture applies.
  try {
    const config = loadConfig();
    warnStderr(`internal hook error: ${err?.message || err}`);
    applyFailurePosture(config, 'internal hook error');
  } catch {
    // Even config loading failed: default posture is closed.
    deny('Shrike unreachable, action held (failure_mode=closed). [internal hook error]');
  }
});

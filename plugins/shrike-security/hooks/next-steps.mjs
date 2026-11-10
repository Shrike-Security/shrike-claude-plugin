/**
 * The next step the plugin tells Claude after a hold or a refusal.
 *
 * The plugin owns these words. The backend's verdict carries a recovery
 * instruction of its own, but the plugin never forwards it: every instruction
 * Claude receives from this plugin is written here, in the plugin's own files,
 * where anyone reviewing the plugin can read it, and no server can change what
 * Claude is told to do. The backend's DESCRIPTION of a verdict (a violation's
 * user_message) still reaches Claude, because it says what happened, not what
 * to do. Keyed only on structured fields already on the wire: the threat
 * category and whether the session lock produced the verdict.
 */

const LOCKED =
  'This session is locked: risk built up over earlier turns, so every call in it is refused until the lock lifts, ' +
  'whatever the call contains. Retrying or rewording counts as another refused attempt. Tell the user. The lock ' +
  'expires on its own after a bounded number of turns; under a live declared scope, the shrike-mcp reset_session ' +
  'tool can release it, and otherwise an operator releases it on the Agents screen. Starting a new session to get ' +
  'around the lock does not clear it.';

/**
 * The lock after the first time. A locked session refuses every call the
 * same way, and the full paragraph on each one buried the two facts that
 * matter: nothing about this call was judged, and nothing new happened.
 */
function lockedAgain(sinceTurn) {
  const since = sinceTurn ? ` since turn ${sinceTurn}` : '';
  return (
    `This session is still locked${since}; this call was not judged on its content and nothing new happened. ` +
    'The lock lifts when it expires, when an operator marks the finding it rests on as wrong or expected, or when ' +
    'an operator releases the session. Do not retry or reword; tell the user once.'
  );
}

/**
 * The lock's next step. `lock` is what the hook knows about this session's
 * lock: whether the session has already been told (repeated) and the turn the
 * lock engaged on (sinceTurn), both kept by the hook. Absent, the full
 * wording is used.
 */
export function lockStep(lock = {}) {
  if (lock.repeated) return lockedAgain(lock.sinceTurn);
  return lock.sinceTurn ? `${LOCKED} It has been locked since turn ${lock.sinceTurn}.` : LOCKED;
}

const DEFAULT_STEP =
  'Tell the user what was stopped. If this is legitimate work, the operator can review it in the Shrike dashboard ' +
  'with the scan id.';

// One short next step per category. Neutral: what the user or the operator can
// do, never a hint about how to get past a check.
const BY_CATEGORY = {
  scope_violation:
    'This action is outside what the agent was declared to do. Ask the user; an operator can widen the scope if the work needs it.',
  scope_expired:
    'The agent\'s declared scope has expired. Ask the user to renew it before continuing.',
  scope_guardrail:
    'A guardrail in the agent\'s declared scope stopped this action. Ask the user how to proceed.',
  secrets_exposure:
    'Refer to secrets by name rather than by value, and tell the user so they can rotate anything that was exposed.',
  pii_exposure:
    'Leave personal details out or use placeholders, unless the user confirms this handling is authorized.',
  sql_injection:
    'Use a parameterized query instead of building SQL from strings.',
  destructive_operation:
    'Ask the user to confirm this destructive operation; it should have an owner and a way to undo it.',
  privilege_escalation:
    'Ask the user before requesting elevated access; it goes through their access-management process.',
  data_exfiltration:
    'Ask the user before moving data outside the environment; a legitimate export goes through their approved process.',
};

const NORMALIZE = [
  [/^known_jailbreak|_jailbreak$|^fictional_bypass$|^hypothetical_jailbreak$/, 'jailbreak'],
  [/^pii_|^encoded_pii/, 'pii_exposure'],
  [/^pii$/, 'pii_exposure'],
  [/^secrets?$|^credential/, 'secrets_exposure'],
];

/** The category a violation or response names, lowercased and normalized for lookup. */
function categoryOf(data) {
  const violations = Array.isArray(data?.violations) ? data.violations : [];
  const raw = String(data?.threat_type || violations.find((v) => v && v.threat_type)?.threat_type || '').toLowerCase();
  for (const [re, to] of NORMALIZE) if (re.test(raw)) return to;
  return raw;
}

/** True when the session lock, not the action's content, produced this verdict. */
export function isLockVerdict(data) {
  const violations = Array.isArray(data?.violations) ? data.violations : [];
  return data?.threat_type === 'session_locked' || violations.some((v) => v && v.threat_type === 'session_locked');
}

/** The plugin's own next step for this verdict. Never server text. */
export function nextStep(data, lock) {
  if (isLockVerdict(data)) return lockStep(lock);
  return BY_CATEGORY[categoryOf(data)] || DEFAULT_STEP;
}

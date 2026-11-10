/**
 * Session identity for the Shrike hook.
 *
 * The host's session id persists across restarts, resumes and compactions, so
 * on its own it can span days of unrelated work. The id sent with each scan is
 * the host session plus an epoch that starts over after a long idle gap or
 * once a session reaches a maximum age. Within one stretch of work nothing
 * changes.
 *
 * The epoch lives in a small stamp file ("<start> <last>", in seconds). Other
 * Shrike integrations on the same machine read the same file, so keep the
 * path and format stable.
 *
 * Kept in its own module so it can be tested without running the whole hook.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

export const SESSION_IDLE_GAP_S = 5400; // 90 min with no scan: the conversation ended
export const SESSION_MAX_AGE_S = 28800; // 8h ceiling on any single session

/** Path of the epoch stamp for one host session. Exported for tests. */
export function epochStampPath(sessionId, dir = tmpdir()) {
  // The id reaches a filename, so keep it to characters that cannot traverse.
  // Host session ids are UUIDs, making this a no-op in practice and a guard
  // against the one case where it would not be.
  const safe = String(sessionId).replace(/[^A-Za-z0-9_-]/g, '');
  return join(dir, `shrike-session-${safe}.epoch`);
}

/**
 * The session id to send on the wire: the host session plus its current epoch.
 * Returns '' for an empty session so the caller's own fallback applies.
 *
 * `now` and `dir` are injectable for tests only; production passes neither.
 */
export function scanSessionId(sessionId, { now = Date.now(), dir = tmpdir() } = {}) {
  if (!sessionId) return '';
  const nowS = Math.floor(now / 1000);
  const safe = String(sessionId).replace(/[^A-Za-z0-9_-]/g, '');
  const stamp = epochStampPath(sessionId, dir);
  let start = 0;
  let last = 0;
  try {
    const parts = readFileSync(stamp, 'utf8').trim().split(/\s+/).map(Number);
    if (Number.isFinite(parts[0]) && parts[0] > 0) start = parts[0];
    if (Number.isFinite(parts[1]) && parts[1] > 0) last = parts[1];
  } catch {
    // A missing or unreadable stamp starts a fresh epoch. It must never fail
    // the hook: an unreadable temp file is not a reason to stop governing.
  }
  if (!start || !last || nowS - last >= SESSION_IDLE_GAP_S || nowS - start >= SESSION_MAX_AGE_S) {
    start = nowS;
  }
  try {
    writeFileSync(stamp, `${start} ${nowS}\n`);
  } catch {
    // Same rule: a stamp we could not write costs epoch accuracy, never a verdict.
  }
  return `cc-${safe}-${start}`;
}

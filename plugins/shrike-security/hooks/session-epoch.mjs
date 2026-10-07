/**
 * Session identity for the Shrike hook.
 *
 * L9 correlates a SESSION: a stretch of continuous work with a beginning and
 * an end. The host's session id has neither. It survives restarts, resumes and
 * compactions, so on one machine a single id accumulated 10,186 scans across
 * 15 days. Session risk only ever climbs, so it reached its ceiling and
 * locked, and from then on every benign prompt came back as a multi-turn
 * attack: the same text refused on that session and allowed on a fresh one.
 * "Is this session adversarial" is not an answerable question about a
 * fortnight of work.
 *
 * So the id on the wire is the host session PLUS an epoch that turns over when
 * the work does: after a long idle gap, meaning the conversation ended, or at
 * a ceiling, because a continuous marathon is still not one conversation.
 * Correlation WITHIN a working stretch is untouched, and that is the window
 * that matters, since a multi-turn attack takes minutes rather than days.
 *
 * This is not a threshold and it does not weaken detection. Only the boundary
 * of what counts as one session moves, from "forever" to "a working session".
 *
 * The stamp path and format are deliberately IDENTICAL to the in-house hook's
 * ("<start> <last>", seconds), so a machine running both during a cutover, or
 * switching from one to the other, keeps one continuous session history rather
 * than fragmenting it. If you change either, change both.
 *
 * It lives in its own module so it can be tested directly: shrike-scan.mjs
 * calls main() at import time, so anything inside it can only be exercised by
 * running the whole hook.
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

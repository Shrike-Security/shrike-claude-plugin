/**
 * Facts the HOST tells us about a call, read off the hook payload.
 *
 * Kept separate from identity resolution on purpose. `resolveAgentIdentity`
 * answers "which governed agent is this", which the operator declares scope
 * against. Everything here is the host's own account of the call, which we
 * report and never treat as authority.
 *
 * Pure and dependency-free so it can be tested without running the hook.
 */

export const ANSWERED_BY_PERSON = 'person';
export const ANSWERED_BY_MODE = 'mode';

/** Tools whose edits `acceptEdits` answers on the operator's behalf. */
const ACCEPT_EDITS_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit']);

/**
 * Who answers a require_approval prompt for this call.
 *
 * Under `default` or `plan` a person is at the keyboard. Under
 * `bypassPermissions`, `dontAsk`, `auto` or any other mode, the MODE answers,
 * and recording that as a human approval would make the dataset the autopilot
 * agreeing with itself. `acceptEdits` is the split case: it answers for file
 * edits only, so a Bash call under it still reaches a person.
 *
 * An absent or unknown mode returns '' and is NEVER inferred: the backend
 * drops anything that is not one of the two values, and a guess here would be
 * indistinguishable from a fact downstream.
 *
 * Mirrors the in-house hook's mapping (`shrike-guard.sh:30-36`). If one
 * changes, change both, and `host-facts.test.mjs` pins this side.
 */
export function answeredBy(permissionMode, toolName) {
    switch (permissionMode) {
        case undefined:
        case null:
        case '':
            return '';
        case 'default':
        case 'plan':
            return ANSWERED_BY_PERSON;
        case 'acceptEdits':
            return ACCEPT_EDITS_TOOLS.has(toolName) ? ANSWERED_BY_MODE : ANSWERED_BY_PERSON;
        default:
            return ANSWERED_BY_MODE;
    }
}

/**
 * The sub-agent that took this action, when one did.
 *
 * The host sets `agent_id` only when the hook fires inside a sub-agent call,
 * and `agent_type` is that agent's name. `session_id` does NOT change for a
 * sub-agent: it stays the parent session's, so the child's turns already
 * correlate with the parent's rather than forming a second session.
 *
 * WHAT THIS DELIBERATELY DOES NOT RETURN: a parent, a chain, or a depth. The
 * host publishes no parent pointer, so `agent_id` says WHICH sub-agent acted
 * and never whose child it is. Sending it as `parent_agent_id` would fabricate
 * a parent, and `delegation_depth` is documented as "0 = root", so any number
 * we chose would invent a position in a tree we cannot see. We report the actor
 * and leave the lineage trio empty, which keeps "a sub-agent acted, parent
 * unknown" distinguishable from "the root agent acted".
 *
 * Real lineage, when we want it, comes from the SPAWN call: that fires in the
 * parent's context and carries the parent's own agent_id, observed by us rather
 * than claimed by the caller. Verified against the hooks reference and one live
 * probe on 2026-10-04.
 *
 * Returns {} when the main agent acted, so the caller can spread it safely.
 */
export function hostSubagent(payload) {
    const id = payload?.agent_id;
    const type = payload?.agent_type;
    if (!id && !type) return {};
    const facts = {};
    // Named host_* so neither is ever mistaken for our own agent_id, which is
    // the governed identity an operator declares scope against.
    if (id) facts.host_subagent_id = String(id);
    if (type) facts.host_subagent_type = String(type);
    return facts;
}

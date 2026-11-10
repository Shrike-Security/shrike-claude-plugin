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
 * `host-facts.test.mjs` pins this mapping.
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
 * How a hold reaches the host: 'ask' puts it to the person at the keyboard
 * in the host's own permission prompt, 'deny' refuses it.
 *
 * Asked only where a PERSON answers the prompt. A mode that would answer it
 * for them (bypassPermissions skips prompts; dontAsk and headless runs turn
 * every prompt into a refusal; acceptEdits answers file edits itself) gets a
 * refusal instead, because an ask a mode answers is a hold nobody saw.
 *
 * `auto` is the one mode that asks although `answeredBy` says the mode
 * answers: the host documents that a hook's ask forces a real prompt there,
 * which its classifier can refuse but cannot approve silently.
 * (code.claude.com/docs/en/hooks, PreToolUse decision control, 2026-10-23.)
 *
 * An absent or unknown mode refuses: never guessed toward a prompt.
 */
export function holdDecision(permissionMode, toolName) {
    if (permissionMode === 'auto') return 'ask';
    return answeredBy(permissionMode, toolName) === ANSWERED_BY_PERSON ? 'ask' : 'deny';
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
 * than claimed by the caller.
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

/** The host's id for the exchange in progress, forwarded as exchange_id. */
export function hostExchange(payload) {
    const id = payload?.prompt_id;
    if (!id) return {};
    return { exchange_id: String(id) };
}

/**
 * What the host reported when the parent's call to a sub-agent returned
 * (PostToolUse on the Agent tool): the sub-agent it started, how the call
 * returned, and the run as the host counted it. The sub-agent's own events
 * carry that same id as `agent_id`, so this is the verified link from a
 * brief to the work it started: the host's own answer, never a guess from
 * time order, which is wrong whenever two sub-agents run at once.
 *
 * Returns null for any other tool and when the host named no sub-agent.
 * A count is forwarded only when the host gave a non-negative integer; one
 * it did not give is left out, never zeroed in. Nothing else from the
 * response is read: the sub-agent's text is not this hook's to forward.
 */
export function delegationFacts(payload) {
    if (payload?.tool_name !== 'Agent') return null;
    const r = payload.tool_response;
    const id = r && typeof r === 'object' ? r.agentId : undefined;
    if (!id) return null;
    const facts = { host_subagent_id: String(id) };
    if (typeof r.status === 'string' && r.status) facts.status = r.status.slice(0, 32);
    for (const [key, v] of [['total_tokens', r.totalTokens], ['duration_ms', r.totalDurationMs], ['tool_uses', r.totalToolUseCount]]) {
        if (Number.isInteger(v) && v >= 0) facts[key] = v;
    }
    return facts;
}

/**
 * The sub-agent a lifecycle event (SubagentStart, SubagentStop) is about,
 * for the session's record of when each sub-agent ran. Null for the host's
 * own internal agents, which carry no agent_type and are not delegations:
 * the same rule the report scan applies.
 */
export function subagentLifecycle(payload) {
    if (!payload?.agent_id || !payload?.agent_type) return null;
    return hostSubagent(payload);
}


/**
 * Maps one gated tool call to the SEQUENCE of scans it needs.
 *
 * A file write with a body is one scan, on the `file_content` channel, which
 * checks the path before it reads the body. A write with no body is one
 * `file_path` scan. `scan-requests.test.mjs` pins both.
 *
 * Pure on purpose: it takes the context base as an argument rather than
 * resolving identity itself, so it can be tested without running the hook.
 */

/**
 * The most content one scan reads, in bytes. Actions over it are refused
 * whole by the caller rather than cut, because a cut action would run with
 * its unread part unchecked. Prompts and replies, which never gate, are
 * fitted to it with fitForScan instead.
 */
export const MAX_SCAN_BYTES = 100 * 1024;

/** Room for one fitted text in a request body once it is JSON-encoded. */
const MAX_ENCODED_BYTES = 180 * 1024;

const OMISSION = '\n\n[content omitted]\n\n';

/**
 * Fit text to `maxBytes` for a scan: unchanged when it fits, otherwise its
 * opening and its end with the middle omitted, since instructions planted in
 * a long paste tend to sit at the end. Also keeps the JSON-encoded form
 * within a request body. Returns { text, truncated, originalBytes }.
 */
export function fitForScan(input, maxBytes = MAX_SCAN_BYTES) {
    const text = String(input ?? '');
    const originalBytes = Buffer.byteLength(text);
    const encoded = (s) => Buffer.byteLength(JSON.stringify(s));
    if (originalBytes <= maxBytes && encoded(text) <= MAX_ENCODED_BYTES) {
        return { text, truncated: false, originalBytes };
    }
    const buf = Buffer.from(text);
    let budget = Math.min(maxBytes, originalBytes) - Buffer.byteLength(OMISSION);
    let fitted = text;
    for (let i = 0; i < 4; i++) {
        const head = Math.ceil(budget / 2);
        const tail = budget - head;
        fitted = buf.subarray(0, head).toString('utf8') + OMISSION + buf.subarray(buf.length - tail).toString('utf8');
        // Escaping can double a text full of newlines or quotes.
        const size = encoded(fitted);
        if (size <= MAX_ENCODED_BYTES) break;
        budget = Math.floor(budget * (MAX_ENCODED_BYTES / size) * 0.95);
    }
    return { text: fitted, truncated: true, originalBytes };
}

/** Context fields that say a scan read a fitted copy, not the whole text. */
export function truncationContext(fit) {
    return fit.truncated ? { truncated: 'true', original_bytes: String(fit.originalBytes) } : {};
}

/**
 * The tools this hook knows how to map. The hooks.json matcher, config.json
 * `gated_tools` and the script's DEFAULT_CONFIG must all agree with this list;
 * `wiring.test.mjs` fails when they drift. A matcher narrower than the list
 * leaves a tool silently ungoverned.
 */
export const MAPPED_TOOLS = ['Agent', 'SubagentHandback', 'Bash', 'Write', 'Edit', 'NotebookEdit', 'WebSearch', 'WebFetch', 'mcp__.*', 'Read', 'Grep', 'Glob'];

/**
 * True when a gated-tools list covers this tool. An entry ending in `.*` is a
 * prefix, the way the hooks.json matcher reads it (`mcp__.*` is every MCP
 * tool); every other entry is an exact name.
 */
export function isGatedTool(gatedTools, toolName) {
    if (!toolName || !Array.isArray(gatedTools)) return false;
    return gatedTools.some((entry) =>
        entry.endsWith('.*') ? toolName.startsWith(entry.slice(0, -2)) : entry === toolName
    );
}

/**
 * True for Shrike's own MCP tools, which are never judged: a scan of a scan
 * is noise, and under a lock it would hold the very tools that report and
 * release it. The server is named `shrike` in the plugin's .mcp.json, which
 * the host namespaces as `plugin_shrike-security_shrike`; a standalone
 * install is usually `shrike` or `shrike-security`.
 */
export function isShrikeMcpTool(toolName) {
    if (!toolName || !toolName.startsWith('mcp__')) return false;
    const end = toolName.indexOf('__', 5);
    const server = end > 5 ? toolName.slice(5, end) : '';
    return server === 'shrike' || server === 'shrike-security' || server === 'plugin_shrike-security_shrike';
}

/**
 * An MCP call as the tool_call channel reads it: the tool's name, then one
 * `key: value` line per argument (objects as JSON). Not cut: an oversized
 * call is refused whole by the caller.
 */
export function flattenToolCall(toolName, toolInput) {
    const lines = [`tool: ${toolName}`];
    if (toolInput && typeof toolInput === 'object') {
        for (const [key, value] of Object.entries(toolInput)) {
            if (value === undefined || value === null) continue;
            lines.push(`${key}: ${typeof value === 'string' ? value : JSON.stringify(value)}`);
        }
    }
    return lines.join('\n');
}

/** A brief or report longer than this is judged on its opening and its end. */
export const MAX_DELEGATION_BYTES = 64 * 1024;
/** The host's one-line name for a delegated task is sent up to this many characters. */
export const MAX_DELEGATION_LABEL_CHARS = 120;

/**
 * @param toolName    the host's tool name
 * @param toolInput   the host's tool input object
 * @param contextBase the scan context minus any per-stage additions
 * @param options     { delegationGate: 'observe' | 'enforce' } (default enforce)
 * @returns array of { stage, content, content_type, context, gate? }, [] when
 *          there is nothing to scan (the caller permits). `gate` is set on a
 *          stage whose verdict the caller must NOT enforce: 'observe' means a
 *          non-allow verdict becomes context for the agent instead of a
 *          refusal.
 */
export function buildScanRequests(toolName, toolInput, contextBase = {}, options = {}) {
    const base = () => ({ ...contextBase });

    if (toolName === 'Agent') {
        // The spawn of a sub-agent. The brief handed to the child is a message
        // from one agent to another, so it is judged on that channel, and
        // this is the one place a delegation can be refused: SubagentStart
        // fires after the spawn and cannot block. A child that only reads
        // and never trips a gated tool leaves no row of its own, so this row
        // is also what makes such a handoff visible at all.
        //
        // Sent on the act plane by default (config delegation_gate), so the
        // backend decides it like any other action: an agent in observe mode
        // observes its delegations inside its own window, which has an end
        // date and shows on the Agents screen. delegation_gate=observe
        // remains as an operator override for one release. The plane rides on
        // the wire so the row says which it was.
        const brief = toolInput && toolInput.prompt;
        if (!brief) return [];
        const gate = options.delegationGate === 'observe' ? 'observe' : 'enforce';
        const context = base();
        context.plane = gate === 'enforce' ? 'act' : 'observe';
        // The child's kind. Target, not actor: the actor here is the parent,
        // and the child's own id is known only to the child's events.
        if (toolInput.subagent_type) context.target_agent_type = String(toolInput.subagent_type);
        // The host's own one-line name for the task, the words it shows in
        // its task list, so the session timeline can name the sub-agent's
        // lane. Capped; the brief itself is the content above, never this.
        if (typeof toolInput.description === 'string' && toolInput.description.trim()) {
            context.delegation_label = toolInput.description.trim().slice(0, MAX_DELEGATION_LABEL_CHARS);
        }
        const fit = fitForScan(brief, MAX_DELEGATION_BYTES);
        Object.assign(context, truncationContext(fit));
        return [{ stage: 'delegation', content: fit.text, content_type: 'a2a_message', context, gate }];
    }

    if (toolName === 'SubagentHandback') {
        // The sub-agent's report on its way back to the parent. On Claude Code
        // 2.1.271 and later a sub-agent that runs with this tool hands its
        // report over through it, and SubagentStop's last message is then only
        // its closing text. So the report is judged here, on the same channel
        // and under the same gate as the brief that went out. The hook fires
        // inside the sub-agent, so the actor on the wire is the child and the
        // origin says the message came from a peer. Under enforce a refusal
        // reaches the child as the tool's error: the report returned with the
        // reason before the parent has seen it.
        const message = toolInput && toolInput.message;
        if (!message) return [];
        const gate = options.delegationGate === 'observe' ? 'observe' : 'enforce';
        const context = base();
        context.plane = gate === 'enforce' ? 'act' : 'observe';
        context.origin = 'peer_agent';
        const fit = fitForScan(message, MAX_DELEGATION_BYTES);
        Object.assign(context, truncationContext(fit));
        return [{ stage: 'report', content: fit.text, content_type: 'a2a_message', context, gate }];
    }

    if (toolName === 'Bash') {
        const command = toolInput?.command;
        if (!command) return [];
        return [{ stage: 'command', content: command, content_type: 'command', context: base() }];
    }

    if (toolName === 'Write' || toolName === 'Edit' || toolName === 'NotebookEdit') {
        // Write carries the full body in `content`, Edit the text being
        // introduced in `new_string`, NotebookEdit the new cell source in
        // `new_source`. The path is `file_path`, or `notebook_path` for a
        // notebook.
        const filePath = toolInput?.file_path || toolInput?.notebook_path || '';
        let body = toolInput?.content ?? toolInput?.new_string ?? toolInput?.new_source ?? '';
        if (typeof body !== 'string') body = String(body);
        // Not cut: a body over MAX_SCAN_BYTES is refused whole by the caller.
        const stages = [];
        if (body) {
            // One scan: the file_content channel validates the path in full
            // before it reads the body (see the header comment). Wire
            // contract: the path travels as content, the body as
            // context.content.
            stages.push({
                stage: 'file_content',
                content: filePath || 'unknown',
                content_type: 'file_content',
                context: { ...base(), content: body },
            });
        } else if (filePath) {
            // No body to judge: the path-only channel, where a data-file
            // extension is held for a person rather than refused.
            stages.push({ stage: 'file_path', content: filePath, content_type: 'file_path', context: base() });
        }
        return stages;
    }

    if (toolName === 'WebSearch') {
        const query = toolInput?.query;
        if (!query) return [];
        return [{ stage: 'web_search', content: query, content_type: 'web_search', context: base() }];
    }

    if (toolName === 'WebFetch') {
        // A fetched URL is checked on the web_search channel; the stage name
        // tells the two apart.
        const url = toolInput?.url;
        if (!url) return [];
        return [{ stage: 'web_fetch', content: url, content_type: 'web_search', context: base() }];
    }

    if (toolName === 'Read' || toolName === 'Grep' || toolName === 'Glob') {
        // A read, on the file_read channel: refused only when the path is a
        // credential store, and a clean read is counted, not stored. Read
        // names a file; Grep and Glob name the root they search, which is
        // the working directory when they name none. Grep matters most of
        // the three: it returns matching LINES, so its root is what it reads.
        const path = toolName === 'Read' ? toolInput && toolInput.file_path : (toolInput && toolInput.path) || '.';
        if (!path) return [];
        return [{ stage: 'file_read', content: String(path), content_type: 'file_read', context: base() }];
    }

    if (toolName && toolName.startsWith('mcp__')) {
        // Any MCP server's tool. Judged on the tool_call channel: by name
        // against the agent's scope (tool_name is read literally, so an
        // operator allows, forbids or always-waits it by its full name), and
        // by its arguments for credential material and intent.
        if (isShrikeMcpTool(toolName)) return [];
        const context = base();
        context.tool_name = toolName;
        return [{ stage: 'tool_call', content: flattenToolCall(toolName, toolInput), content_type: 'tool_call', context }];
    }

    // Gated by the matcher but not mapped: permit rather than break the editor
    // on a tool this client does not understand.
    return [];
}

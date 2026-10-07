/**
 * Maps one gated tool call to the SEQUENCE of scans it needs.
 *
 * Why a sequence and not one scan. A file edit is TWO scans, and that is
 * load-bearing rather than thoroughness. `file_path` is the stage the
 * authoring-path grant is evaluated on (see commit `654a73e`, "authoring grant
 * covers the path scan for data-file extensions"); `file_content` judges the
 * body about to be written. This hook collapsed them into a single combined
 * scan until 2026-10-05, which meant the authoring decision never got the
 * stage it is made on, so a plugin user's scope governance differed from the
 * in-house hook's. If you are tempted to merge them again, that is the reason
 * not to, and `scan-requests.test.mjs` will fail.
 *
 * Pure on purpose: it takes the context base as an argument rather than
 * resolving identity itself, so it can be tested without running the hook.
 */

/** Max body bytes sent for one file edit, mirroring the in-house hook's cap. */
export const MAX_BODY_BYTES = 200 * 1024;

/**
 * The tools this hook knows how to map. The hooks.json matcher, config.json
 * `gated_tools` and the script's DEFAULT_CONFIG must all agree with this list;
 * `wiring.test.mjs` fails when they drift. A matcher narrower than the list
 * leaves a tool silently ungoverned, which is how NotebookEdit, WebSearch and
 * WebFetch went unscanned until 2026-10-05.
 */
export const MAPPED_TOOLS = ['Bash', 'Write', 'Edit', 'NotebookEdit', 'WebSearch', 'WebFetch'];

/**
 * @param toolName    the host's tool name
 * @param toolInput   the host's tool input object
 * @param contextBase the scan context minus any per-stage additions
 * @returns array of { stage, content, content_type, context }, [] when there
 *          is nothing to scan (the caller permits)
 */
export function buildScanRequests(toolName, toolInput, contextBase = {}) {
    const base = () => ({ ...contextBase });

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
        if (Buffer.byteLength(body) > MAX_BODY_BYTES) {
            body = Buffer.from(body).subarray(0, MAX_BODY_BYTES).toString('utf8');
        }
        const stages = [];
        if (filePath) {
            stages.push({ stage: 'file_path', content: filePath, content_type: 'file_path', context: base() });
        }
        if (body) {
            // Wire contract: the path travels as content, the body as context.content.
            stages.push({
                stage: 'file_content',
                content: filePath || 'unknown',
                content_type: 'file_content',
                context: { ...base(), content: body },
            });
        }
        return stages;
    }

    if (toolName === 'WebSearch') {
        const query = toolInput?.query;
        if (!query) return [];
        return [{ stage: 'web_search', content: query, content_type: 'web_search', context: base() }];
    }

    if (toolName === 'WebFetch') {
        // There is no first-class api_call/url surface yet (a printed gap in
        // the coverage map). The web_search scanner is the closest boundary for
        // outbound web ingress, and the in-house hook makes the same
        // compromise for the same reason.
        const url = toolInput?.url;
        if (!url) return [];
        return [{ stage: 'web_fetch', content: url, content_type: 'web_search', context: base() }];
    }

    // Gated by the matcher but not mapped: permit rather than break the editor
    // on a tool this client does not understand.
    return [];
}

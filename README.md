# Shrike plugins for Claude Code

A plugin marketplace from [Shrike Security](https://shrikesecurity.com).

## Install

Register the marketplace, then install the plugin:

```bash
claude plugin marketplace add Shrike-Security/shrike-claude-plugin
claude plugin install shrike-security@shrike
```

Inside a session, `/plugin marketplace add Shrike-Security/shrike-claude-plugin`
does the same thing.

## What's here

| Plugin | What it does |
|---|---|
| `shrike-security` | Governs the actions Claude Code takes, against the policy you declare. Scans shell commands, file writes, notebook edits, web searches and fetches, and the brief handed to a sub-agent before they execute, applying your policy in real time to what's allowed, warned, held for approval, or blocked. Shrike doesn't decide on its own authority; you declare the policy and Shrike enforces it. Scans the reply and a sub-agent's report, and keys every scan to the exchange it served. Bundles the `governed-tool-use` skill and the shrike-mcp security tools. |

Full documentation is in [the plugin's README](plugins/shrike-security/README.md).

## Setting a key

The plugin works with no API key and does nothing until it has one: without a
key the hook permits every action and prints a one-line setup pointer, so
installing it can never be the reason a session stops working.

Set `SHRIKE_API_KEY` to turn on enforcement. Free keys at
[shrikesecurity.com/signup](https://shrikesecurity.com/signup).

## Requirements

Node 18 or newer for the hook; Node 20 or newer for the bundled `shrike-mcp`
server. The hook degrades self-explainingly when the runtime is missing
rather than failing silently.

## Links

- [Shrike](https://shrikesecurity.com): sign up, dashboard, docs
- [shrike-mcp](https://github.com/Shrike-Security/shrike-mcp): the MCP server the plugin bundles
- [Report an issue](https://github.com/Shrike-Security/shrike-claude-plugin/issues)

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

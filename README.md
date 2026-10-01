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
| `shrike-security` | Scans shell commands and file writes before they execute and routes on the verdict: allow, warn, require approval, or block. Bundles the `governed-tool-use` skill and the shrike-mcp security tools. |

Full documentation is in [the plugin's README](plugins/shrike-security/README.md).

## Setting a key

The plugin works with no API key and does nothing until it has one: without a
key the hook permits every action and prints a one-line setup pointer, so
installing it can never be the reason a session stops working.

Set `SHRIKE_API_KEY` to turn on enforcement. Free keys at
[shrikesecurity.com/signup](https://shrikesecurity.com/signup).

## Requirements

Node 18 or newer. The hook degrades self-explainingly when the runtime is
missing rather than failing silently.

## Links

- [Shrike](https://shrikesecurity.com): sign up, dashboard, docs
- [shrike-mcp](https://github.com/Shrike-Security/shrike-mcp): the MCP server the plugin bundles
- [Report an issue](https://github.com/Shrike-Security/shrike-claude-plugin/issues)

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

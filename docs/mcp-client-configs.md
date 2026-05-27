# MCP Client Configs

Agent Surface Map runs as a local stdio MCP server:

```bash
asm mcp
```

For source-tree development, use:

```bash
python3 /absolute/path/to/agent-surface-map/mcp_server.py
```

Recommended environment:

```bash
ASM_ALLOWED_ROOTS="/path/to/projects:/tmp/review-work"
ASM_POLICY_FILE="/absolute/path/to/agent-surface-policy.yml"
```

`ASM_ALLOWED_ROOTS` limits local scans. Without it, the server defaults to the
directory where it was started and still refuses root, credential, and profile
directories.

## Tools Exposed

- `scan_github_tool`
- `scan_local_tool`
- `generate_safe_install_context`
- `validate_install_plan`

## Claude Code

Project-scoped stdio server:

```bash
claude mcp add --transport stdio --scope project \
  --env ASM_ALLOWED_ROOTS="$PWD" \
  agent-surface-map -- asm mcp
```

User-scoped stdio server:

```bash
claude mcp add --transport stdio --scope user \
  --env ASM_ALLOWED_ROOTS="/path/to/projects:/tmp/review-work" \
  --env ASM_POLICY_FILE="/absolute/path/to/agent-surface-policy.yml" \
  agent-surface-map -- asm mcp
```

Check status inside Claude Code:

```text
/mcp
```

Project JSON alternative in `.mcp.json`:

```json
{
  "mcpServers": {
    "agent-surface-map": {
      "type": "stdio",
      "command": "asm",
      "args": ["mcp"],
      "env": {
        "ASM_ALLOWED_ROOTS": "${CLAUDE_PROJECT_DIR:-.}",
        "ASM_POLICY_FILE": "${CLAUDE_PROJECT_DIR:-.}/agent-surface-policy.yml"
      }
    }
  }
}
```

Claude Code supports environment variable expansion in `.mcp.json`, so the
project form can stay portable across machines.

## Codex

Codex reads MCP servers from `~/.codex/config.toml` and project/user config in
the same TOML shape.

Global config:

```toml
[mcp_servers.agent-surface-map]
command = "asm"
args = ["mcp"]

[mcp_servers.agent-surface-map.env]
ASM_ALLOWED_ROOTS = "/path/to/projects:/tmp/review-work"
ASM_POLICY_FILE = "/absolute/path/to/agent-surface-policy.yml"
```

If `asm` is not on the PATH used by Codex, replace `command = "asm"` with the
absolute executable path from:

```bash
which asm
```

Verify in Codex:

```text
/mcp
```

or with the Codex CLI when available:

```bash
codex mcp list
```

## Cursor

Global config on macOS/Linux:

```text
~/.cursor/mcp.json
```

Config:

```json
{
  "mcpServers": {
    "agent-surface-map": {
      "command": "asm",
      "args": ["mcp"],
      "env": {
        "ASM_ALLOWED_ROOTS": "/path/to/projects:/tmp/review-work",
        "ASM_POLICY_FILE": "/absolute/path/to/agent-surface-policy.yml"
      }
    }
  }
}
```

Project-local config, if your Cursor setup reads project MCP files:

```text
.cursor/mcp.json
```

Use a project-local root:

```json
{
  "mcpServers": {
    "agent-surface-map": {
      "command": "asm",
      "args": ["mcp"],
      "env": {
        "ASM_ALLOWED_ROOTS": ".",
        "ASM_POLICY_FILE": "agent-surface-policy.yml"
      }
    }
  }
}
```

Restart Cursor after editing MCP config.

## Generic MCP JSON

Many MCP clients accept this shape:

```json
{
  "mcpServers": {
    "agent-surface-map": {
      "command": "asm",
      "args": ["mcp"],
      "env": {
        "ASM_ALLOWED_ROOTS": "/path/to/projects:/tmp/review-work",
        "ASM_POLICY_FILE": "/absolute/path/to/agent-surface-policy.yml"
      }
    }
  }
}
```

## Agent Instruction Snippet

Add this to `AGENTS.md`, `CLAUDE.md`, or equivalent project instructions:

```text
Before adding a new MCP server, skill, plugin, browser tool, or agent
instruction pack, call Agent Surface Map first.

Use scan_github_tool(url) for public repos and scan_local_tool(path) for local
tools. Read the returned install posture and agent constraints. Draft the final
MCP/client config, then call validate_install_plan(report, proposed_config)
before writing config or running install commands.

If validation returns block, do not install. If it returns needs_changes, fix the
required changes or ask the user before proceeding.
```

## Smoke Test

After configuring a client, ask the agent:

```text
List Agent Surface Map tools, then scan https://github.com/dodge1218/agent-surface-demo-mcp and summarize the install posture.
```

Expected posture for the demo fixture is usually `sandbox_first`.

## Security Notes

- Do not point `ASM_ALLOWED_ROOTS` at your home directory.
- Do not include secret values in `ASM_POLICY_FILE`.
- Keep Agent Surface Map project-scoped where possible.
- Treat `do_not_add` as a hard stop.
- Treat `sandbox_first` as "review and isolate before install."

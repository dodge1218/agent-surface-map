# MCP Usage

Agent Surface Map can run as a local MCP server so a coding agent can ask for safety context before installing a new MCP server, skill, plugin, browser tool, or repo instruction pack.

## Local Config

Example MCP client config:

```json
{
  "mcpServers": {
    "agent-surface-map": {
      "command": "python3",
      "args": ["/absolute/path/to/agent-surface-map/mcp_server.py"]
    }
  }
}
```

For stricter local-path policy:

```bash
export ASM_ALLOWED_ROOTS="/home/me/projects:/tmp/review-work"
```

## Tools

### `scan_github_tool`

Input:

```json
{
  "url": "https://github.com/org/mcp-server"
}
```

Returns a JSON report with:

- install verdict
- risk score
- risk signals
- review source
- redacted evidence
- safe install context for the calling agent

### `scan_local_tool`

Input:

```json
{
  "path": "/path/to/local/tool"
}
```

### `generate_safe_install_context`

Input:

```json
{
  "report": {}
}
```

Use this when an agent already has a scan report and wants only the concise workflow constraints.

## Intended Agent Workflow

```text
User: Add this MCP to my workflow: https://github.com/org/tool
Agent: I will scan it first with Agent Surface Map.
Agent calls: scan_github_tool(url)
Agent receives: sandbox_first / do_not_add / add_carefully plus constraints
Agent follows the returned context before editing config or running install commands.
```

## Gemma Review Source

If `GEMMA_API_KEY` and `GEMMA_BASE_URL` are set, MCP scan tools attach a Gemma review and return `review_source: "gemma"`.

If Gemma is not configured or the provider call fails, the MCP server returns the deterministic fallback review with `review_source: "fallback"` and does not fail the scan.

Read `docs/security-notes.md` before using this as a standing local MCP server.

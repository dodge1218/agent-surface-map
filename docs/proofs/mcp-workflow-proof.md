# MCP Workflow Proof

Command:

```bash
python3 scripts/mcp_workflow_smoke.py
```

Target:

```text
https://github.com/dodge1218/agent-surface-demo-mcp
```

Result:

- MCP server initialized over stdio.
- Tool list returned `scan_local_tool`, `scan_github_tool`, and `generate_safe_install_context`.
- `scan_github_tool` scanned the public demo MCP fixture.
- Verdict: `sandbox_first`.
- Risk score: `45`.
- Parsed MCP servers: `demo-browser`, `demo-filesystem`.
- Returned agent constraints include no repo-code execution, secret-value handling, clean browser profile, and filesystem mount review.

Raw proof:

```json
{
  "target_url": "https://github.com/dodge1218/agent-surface-demo-mcp",
  "tools": [
    "scan_local_tool",
    "scan_github_tool",
    "generate_safe_install_context"
  ],
  "verdict": "sandbox_first",
  "risk_score": 45,
  "review_source": "fallback",
  "mcp_servers": [
    "demo-browser",
    "demo-filesystem"
  ],
  "agent_context": [
    "Do not execute repository code during review.",
    "Keep secret values out of prompts, reports, and logs.",
    "Use a clean browser profile with no personal sessions or saved cookies.",
    "Pass secret names by reference only; never expose values to the model.",
    "Review filesystem mounts and prefer project-local read-only access."
  ]
}
```

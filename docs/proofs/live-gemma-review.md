# Live Gemma Review Proof

Command:

```bash
curl -X POST https://gemma-agent-surface-map.vercel.app/api/scan \
  -H 'content-type: application/json' \
  -d '{"url":"https://github.com/dodge1218/agent-surface-demo-mcp"}'
```

Result:

- Target: `https://github.com/dodge1218/agent-surface-demo-mcp`
- Risk score: `45`
- Review source: `gemma`
- Parsed MCP servers: `demo-browser`, `demo-filesystem`

Raw proof summary is saved in `docs/proofs/live-gemma-review.json`.

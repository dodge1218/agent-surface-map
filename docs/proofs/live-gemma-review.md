# Live Gemma Review Proof

This proof captures a successful hosted review where the API returned
`review_source: "gemma"` for the public demo fixture.

The public endpoint can still fall back when the upstream provider rate-limits
Gemma. That fallback is expected product behavior and is labeled in the API
response as `review_source: "fallback"` with the provider error attached.

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

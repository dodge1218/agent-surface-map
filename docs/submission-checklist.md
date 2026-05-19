# Submission Checklist

## DEV Post

- [ ] Title uses project name and Gemma 4.
- [ ] Tags include `devchallenge`, `gemmachallenge`, `gemma`.
- [ ] Links live demo: `https://gemma-agent-surface-map.vercel.app`.
- [ ] Links code: `https://github.com/dodge1218/agent-surface-map`.
- [ ] Explains web flow and MCP flow.
- [ ] Explains why Gemma 4 is central.
- [ ] Mentions model choice: Gemma 4 31B Dense for final install review.
- [ ] Explains `review_source` honestly for Gemma vs fallback.
- [ ] Mentions pre-audited MCP examples.
- [ ] Includes verification commands.
- [ ] Includes no private OpenClaw/CyberClaw/bounty details.

## Demo

- [ ] Home page loads.
- [ ] Paste-link scanner works with a small public repo.
- [ ] Invalid URL returns a readable error.
- [ ] Gemma verdict panel is visually obvious.
- [ ] MCP workflow is visible on the page.
- [ ] Pre-audit library cards load reports into the same verdict screen.

## Code

- [ ] `python3 -m unittest discover -s tests -v`
- [ ] `python3 -m py_compile surface_map.py server.py api/scan.py mcp_server.py`
- [ ] `node --check public/app.js`
- [ ] `curl -X POST https://gemma-agent-surface-map.vercel.app/api/scan -H 'content-type: application/json' -d '{"url":"https://github.com/octocat/Hello-World"}'`

## Security

- [ ] Repo code is not executed during scan.
- [ ] Secret-looking values are redacted.
- [ ] MCP local scan refuses root/profile/credential directories.
- [ ] GitHub scans use shallow/no-submodule/no-hook retrieval.
- [ ] MCP response includes install constraints.

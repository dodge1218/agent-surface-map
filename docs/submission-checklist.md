# Submission Checklist

Submitted:

```text
https://dev.to/vonb/agent-surface-map-gemma-4-review-before-you-install-an-mcp-1nbn
```

## DEV Post

- [x] Title uses project name and Gemma 4.
- [x] Tags include `devchallenge`, `gemmachallenge`, `gemma`.
- [x] Links live demo: `https://gemma-agent-surface-map.vercel.app`.
- [x] Links code: `https://github.com/dodge1218/agent-surface-map`.
- [x] Explains web flow and MCP flow.
- [x] Explains final install-plan validation.
- [x] Explains why Gemma 4 is central.
- [x] Mentions model choice: Gemma 4 31B Dense for final install review.
- [x] Explains `review_source` honestly for Gemma vs fallback.
- [x] Mentions example MCP reviews.
- [x] Includes verification commands.
- [x] Includes no private internal research details.

## Demo

- [x] Home page loads.
- [x] `Try demo MCP scan` works with `https://github.com/dodge1218/agent-surface-demo-mcp`.
- [x] Paste-link scanner works with a small public repo.
- [x] Invalid URL returns a readable error.
- [x] Gemma verdict panel is visually obvious.
- [x] MCP workflow is visible on the page.
- [x] `validate_install_plan` is documented.
- [x] Example review cards load reports into the same verdict screen.

Readiness note: live hosted Gemma may return provider `429` and fall back. The
article and proof docs now state this directly instead of implying every public
scan will hit Gemma.

## Code

- [x] `python3 -m venv .venv`
- [x] `.venv/bin/python -m pip install -r requirements.txt`
- [x] `python3 -m unittest discover -s tests -v`
- [x] `python3 -m py_compile remediation_pr_body.py remediation_apply.py remediation_approval.py remediation_renderer.py drift_watch.py runtime_telemetry.py policy.py surface_map.py server.py api/scan.py mcp_server.py scripts/mcp_workflow_smoke.py`
- [x] `node --check public/app.js`
- [x] `curl -X POST https://gemma-agent-surface-map.vercel.app/api/scan -H 'content-type: application/json' -d '{"url":"https://github.com/octocat/Hello-World"}'`
- [x] `python3 scripts/mcp_workflow_smoke.py`

## Security

- [x] Repo code is not executed during scan.
- [x] Secret-looking values are redacted.
- [x] MCP local scan refuses root/profile/credential directories.
- [x] GitHub scans use shallow/no-submodule/no-hook retrieval.
- [x] MCP response includes install constraints.
- [x] Public scan rate limit is configured.
- [x] Public Gemma review rate/spend guardrails are configured.

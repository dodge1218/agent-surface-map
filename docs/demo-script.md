# Demo Script

Target length: 60 to 90 seconds.

## Shot List

1. Open `https://gemma-agent-surface-map.vercel.app`.
2. Say: "This answers one question before installing an agent tool: what posture should this install get?"
3. Show the sample verdict panel and risk signals.
4. Click `Stealth Browser MCP` in the example review library.
5. Point at browser profile and filesystem signals.
6. Click `GitHub MCP` or `Postgres MCP`.
7. Show how the same screen handles token/database risk.
8. Start with the default saved verified Gemma 4 review.
9. Click `Test example` with an empty field to run the hosted scanner against the public demo fixture.
10. End with MCP workflow: coding agents can call `scan_github_tool(url)` before editing config.

## Voiceover

Agent Surface Map is a pre-install scanner for MCP servers and agent tools.

The scanner collects evidence locally and redacts secret-looking values. Gemma 4 is the review layer: it turns that surface map into a practical install decision and agent constraints.

The web UI is for quick checks. The MCP server is for real workflow use: before a coding agent adds a new tool, it can ask this server for install constraints.

The important part is the boundary. The scanner does not execute the target repo, does not send raw secrets, and clearly labels whether the review came from Gemma or a deterministic fallback.

The goal is simple: give developers a safety pause before they hand their coding agent a shell, browser, filesystem, mailbox, repo token, or database.

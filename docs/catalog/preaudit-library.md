# MCP Pre-Audit Library

These examples are public-safe install templates. They demonstrate the scanner on common MCP shapes without claiming that a specific upstream project is safe or unsafe.

Current templates:

- Stealth Browser MCP: browser automation, profile/session exposure.
- GitHub MCP: developer-platform token scope.
- Gmail MCP: mailbox context and OAuth scope.
- Filesystem MCP: local mount scope.
- Playwright MCP: browser automation with session separation.
- Fetch MCP: outbound network and remote content.
- Postgres MCP: database credentials and private records.
- Memory + Shell MCP: persisted context and terminal execution.

The web UI loads each generated report from `public/preaudits/` into the same verdict screen used by live scans.

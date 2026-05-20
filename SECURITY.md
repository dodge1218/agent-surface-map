# Security Policy

Agent Surface Map reviews untrusted agent-tool repositories, so reports about its own scanner boundary are welcome.

## Supported Version

The public repository tracks the current challenge build on `main`.

## Reporting

Open a private security advisory on GitHub if available, or open an issue with a minimal non-destructive reproduction.

Do not include live secrets, private tokens, or exploit payloads against third-party systems.

## Scope

Interesting reports include:

- untrusted code execution during scan
- archive extraction bypass
- secret redaction bypass in public output
- local MCP path-boundary bypass
- prompt or report leakage from hosted scans

Expected limitations:

- This tool flags install risk. It does not prove a scanned repository is benign.
- Public rate and spend controls are best-effort demo throttles unless backed by provider-side or durable external limits.

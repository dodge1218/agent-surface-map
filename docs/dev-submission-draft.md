---
title: Agent Surface Map: Using Gemma 4 to make local coding agents safer
published: false
tags: devchallenge, gemmachallenge, gemma
---

*This is a submission for the [Gemma 4 Challenge: Build with Gemma 4](https://dev.to/challenges/google-gemma-2026-05-06)*

## What I Built

Agent Surface Map is a pre-install safety scanner for developers who add MCP servers, skills, browser tools, repo instructions, and other capabilities to coding agents.

Paste a GitHub repo link and the app runs a read-only review before the tool gets wired into Claude Code, Codex, Cursor, or another local agent workflow.

The informal version:

```text
Paste repo. Scanner checks risk. Gemma explains. Agent installs safer.
```

The scanner inventories the agent operating surface, redacts secret-adjacent data, and uses Gemma 4 to turn that inventory into an install decision:

- what the agent can execute
- what it can write
- where browser automation appears
- which environment variables are referenced
- which instruction files may steer future agent behavior
- whether to add it carefully, sandbox it first, or reject it

The goal is simple: before you give a coding agent a new tool, know what that tool is asking for.

## Demo

The web demo shows a scan of a sample agent stack. It includes a verdict, risk score, review source, risk signals, pre-audited MCP templates, and safe workflow notes.

Live demo:

```text
https://gemma-agent-surface-map.vercel.app
```

Run it locally:

```bash
python3 surface_map.py examples/demo-agent-stack --out public/sample-report.json
python3 server.py
```

Then open `http://localhost:8787`.

For developer workflow, the repo also includes an MCP server:

```bash
python3 mcp_server.py
```

That lets a coding agent call `scan_github_tool(url)` before editing local MCP config or running install commands.

## Code

Repository:

```text
https://github.com/dodge1218/agent-surface-map
```

Key implementation pieces:

- `surface_map.py` — deterministic local scanner and Gemma prompt builder
- `server.py` — local web/API demo server
- `api/scan.py` — Vercel serverless scanner endpoint
- `mcp_server.py` — stdio MCP server for coding-agent workflows
- `tests/test_surface_map.py` — scanner and MCP protocol tests

## How I Used Gemma 4

The deterministic scanner is intentionally boring: it walks local files, detects agent-surface signals, and redacts secret values.

Gemma 4 is the intended judgment layer. The deterministic scanner finds evidence; Gemma receives a compact, redacted inventory and returns a structured review with:

- summary
- top risks
- quick wins
- hardening plan
- install guidance

I would use Gemma 4 31B Dense for the final review because the task needs nuanced security reasoning and prioritization more than tiny-device latency. Smaller Gemma 4 variants are a good fit for inline local checks, but the 31B model is the better reviewer for turning messy tool access into a practical add/sandbox/reject decision.

The model is not trusted with raw secrets and does not run commands. It explains a local scan that already happened. When no Gemma endpoint is configured, the app clearly labels the deterministic fallback with `review_source: "fallback"` instead of pretending the review came from the model.

## Pre-Audited MCP Library

The demo includes a small library of common MCP install profiles:

- Stealth Browser
- GitHub
- Gmail
- Filesystem
- Playwright
- Fetch
- Postgres
- Memory + Shell

Each card loads a generated report into the same verdict screen. The point is not to certify those upstream tools. The point is to show the workflow developers need before adding high-trust tools to an agent.

## Safety Design

The scanner is intentionally conservative:

- it does not execute repository code
- GitHub scans use shallow/no-submodule retrieval
- secret-looking values are redacted before review
- local MCP scans refuse filesystem root and obvious credential/profile directories
- MCP output includes workflow constraints for the calling agent

That matters because the product is about evaluating untrusted agent tools. The evaluator should not become another unsafe agent tool.

## Verification

I tested the scanner, MCP protocol flow, and deployed API:

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile surface_map.py server.py api/scan.py mcp_server.py
node --check public/app.js
curl -X POST https://gemma-agent-surface-map.vercel.app/api/scan \
  -H 'content-type: application/json' \
  -d '{"url":"https://github.com/octocat/Hello-World"}'
```

## Why It Matters

Coding agents changed the shape of developer risk. A repo can now include instructions for agents, MCP configs, browser access, package scripts, and credentials by reference. That is not just code; it is an operating surface.

Agent Surface Map treats that surface as something builders should be able to inspect before they automate more work.

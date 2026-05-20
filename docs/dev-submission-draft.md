---
title: Agent Surface Map: Gemma 4 review before you install an MCP
published: false
tags: devchallenge, gemmachallenge, gemma
---

*This is a submission for the [Gemma 4 Challenge: Build with Gemma 4](https://dev.to/challenges/google-gemma-2026-05-06).*

So the thing I built is pretty simple:

```text
Paste repo. Scanner checks risk. Gemma explains. Agent installs safer.
```

Agent Surface Map is a pre-install scanner for MCP servers and agent tools. Before a coding agent gets a new browser tool, filesystem mount, shell helper, Gmail/GitHub integration, or repo instruction pack, the app runs a read-only scan and asks: what is this tool actually asking for?

Live demo:

```text
https://gemma-agent-surface-map.vercel.app
```

Code:

```text
https://github.com/dodge1218/agent-surface-map
```

## What it does

The scanner looks at install-facing files: `mcp.json`, package files, repo instructions, Docker files, env examples, and similar config. It does not execute the repo.

It pulls out:

- MCP server names, commands, args, and env key names
- shell/process surfaces
- browser automation and profile reuse
- filesystem mounts
- cloud/database/token references
- prompt-injection-ish repo instructions
- install scripts and local listener hints

Then it redacts secret-looking values and sends the compact surface map to Gemma 4.

Gemma is the judgment layer. The deterministic scanner finds the evidence; Gemma turns it into a practical install decision and hardening plan.

## Why this felt worth building

Coding agents changed the shape of local risk. A repo is not just code anymore. It can ship instructions for your agent, MCP config, package scripts, browser access, write paths, and credential names.

That is basically a tiny operating surface on your laptop.

So this is the safety pause before the agent gets more power. Not a malware sandbox. Not a full audit. Just a fast answer to: should this be added globally, sandboxed first, or rejected?

## Demo path

Click `Try demo MCP scan` on the homepage. It scans this tiny public fixture:

```text
https://github.com/dodge1218/agent-surface-demo-mcp
```

The live scan returns parsed MCP servers, a risk score, safe workflow notes, and `review_source: "gemma"` when the Gemma route is available. If the provider rate-limits, the app falls back to the deterministic local review and labels that honestly.

There is also an MCP server in the repo:

```bash
python3 mcp_server.py
```

That means a coding agent can call `scan_github_tool(url)` before it edits local MCP config. That is the real workflow: "hey agent, before you install this new tool, ask Agent Surface Map what constraints to follow."

## Safety choices

I kept the evaluator boring on purpose:

- no repo code execution
- shallow/no-submodule GitHub retrieval
- secret value redaction
- local path refusal for root/profile/credential dirs
- bounded MCP responses
- public scan rate limits
- Gemma review rate limits
- app-level $10/day estimated Gemma cap

The hosted demo uses a guarded Gemma 4 path through OpenRouter. I also saved proof artifacts for the MCP workflow and live Gemma review in `docs/proofs/`.

## Verification

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile surface_map.py server.py api/scan.py mcp_server.py
node --check public/app.js
python3 scripts/mcp_workflow_smoke.py
```

Current proof:

- live demo deployed
- Gemma route configured
- public demo MCP fixture works
- MCP stdio workflow works
- scanner tests pass

I think the interesting part is not the regex scanner. It is the handoff. Deterministic code collects boring evidence, Gemma turns it into something a developer or coding agent can actually use, and the install gets safer before anything touches the shell.

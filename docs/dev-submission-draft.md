---
title: Agent Surface Map: Gemma 4 review before you install an MCP
published: false
tags: devchallenge, gemmachallenge, gemma
---

*This is a submission for the [Gemma 4 Challenge: Build with Gemma 4](https://dev.to/challenges/google-gemma-2026-05-06).*

The thing I built is pretty simple:

**Before your coding agent installs a new MCP, ask Gemma what it is about to trust.**

## What I Built

Agent Surface Map is a pre-install review for MCP servers and agent tools. It does not try to prove a repo is safe. That would be fake precision. It answers a more practical question:

Should this be added carefully, sandboxed first, or not added?

There are already MCP scanners. That is good. I wanted the missing workflow layer: before a coding agent installs a new MCP, have Gemma turn the surface map into install constraints, then validate the final config before it gets written.

The loop: scan repo -> Gemma decides install posture -> agent validates final config before writing it.

## Demo

[Live demo](https://gemma-agent-surface-map.vercel.app)

The page opens on a saved verified Gemma 4 review for this tiny public fixture:

[Demo MCP fixture](https://github.com/dodge1218/agent-surface-demo-mcp)

Click `Load verified Gemma 4 review` to see the saved model path. Click `Try live demo scan` to run the hosted scanner against the same fixture.

The live scan returns parsed MCP servers, a risk score, install constraints, and `review_source: "gemma"` when the Gemma route is available. If the provider rate-limits, the app falls back to the deterministic local review and labels that honestly. That fallback behavior is part of the product, not something hidden from the judge.

The point is that the judge-facing path does not depend on provider luck: the verified Gemma 4 review is loaded by default and saved in the repo.

## Code

[GitHub repo](https://github.com/dodge1218/agent-surface-map)

There is also an MCP server in the repo:

Run the MCP server with `python3 mcp_server.py`.

That means a coding agent can call `scan_github_tool(url)` before it edits local MCP config, then call `validate_install_plan(report, proposed_config)` before it writes the final config.

That is the real workflow: "hey agent, before you install this new tool, ask Agent Surface Map what constraints to follow, then check your final config against them."

## How I Used Gemma 4

I used Gemma 4 31B Dense for the final install review.

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

Gemma is the judgment layer. The deterministic scanner finds the evidence; Gemma turns it into a practical install decision and agent constraints.

I chose the 31B Dense model because this is not just classification. The model has to reason over messy developer context: browser profile reuse plus filesystem mounts plus token names is more serious than any one signal alone.

After Gemma returns the posture, the MCP workflow can check the final proposed config with `validate_install_plan`. That catches global install after `sandbox_first`, broad local paths, Docker socket exposure, and secret values pasted directly into config.

## Why this felt worth building

Coding agents changed the shape of local risk. A repo is not just code anymore. It can ship instructions for your agent, MCP config, package scripts, browser access, write paths, and credential names.

That is basically a tiny operating surface on your laptop.

So this is the safety pause before the agent gets more power. Not a malware sandbox. Not a full audit. Just a fast answer to: should this be added carefully, sandboxed first, or rejected?

And yeah, you can paste a config into ChatGPT and ask for advice. The difference here is that the review is wired into the install path. The agent can scan, get a structured posture, draft the config, and then check that exact config before it writes anything.

## Safety choices

I kept the evaluator boring on purpose:

- No repo code execution
- Shallow/no-submodule GitHub retrieval
- Secret value redaction
- Local path refusal for root/profile/credential dirs
- Bounded MCP responses
- Public scan rate limits
- Gemma review rate limits
- Best-effort demo throttles for scans and Gemma reviews

The hosted demo uses a guarded Gemma 4 path through OpenRouter. I also saved proof artifacts for the MCP workflow and live Gemma review in `docs/proofs/`.

## Verification

- `python3 -m unittest discover -s tests -v`
- `python3 -m py_compile surface_map.py server.py api/scan.py mcp_server.py scripts/mcp_workflow_smoke.py`
- `node --check public/app.js`
- `python3 scripts/mcp_workflow_smoke.py`

Current proof:

- live demo deployed
- Gemma route configured, with honest fallback when the provider returns 429
- saved verified Gemma review artifact included in the repo
- public demo MCP fixture works
- MCP stdio workflow works
- final install-plan validation blocks unsafe config
- scanner tests pass

I think the interesting part is not the regex scanner. It is the handoff. Deterministic code collects boring evidence, Gemma turns it into install constraints a developer or coding agent can actually use, and the final plan gets checked before anything touches the shell.

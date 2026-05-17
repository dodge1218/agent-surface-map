---
title: Agent Surface Map: Using Gemma 4 to make local coding agents safer
published: false
tags: devchallenge, gemmachallenge, gemma
---

*This is a submission for the [Gemma 4 Challenge: Build with Gemma 4](https://dev.to/challenges/google-gemma-2026-05-06)*

## What I Built

Agent Surface Map is a local-first safety scanner for developers who run coding agents with shell tools, MCP servers, repo instructions, browser automation, and local files.

The scanner inventories the local agent operating surface, redacts secret-adjacent data, and uses Gemma 4 to turn that inventory into prioritized risk cards:

- what the agent can execute
- what it can write
- where browser automation appears
- which environment variables are referenced
- which instruction files may steer future agent behavior
- what to fix first

The goal is simple: before you hand an agent more tools, know what you have already handed it.

## Demo

The demo app shows a scan of a sample agent stack. It includes a risk score, Gemma-generated review, category bars, and file-level findings.

Run it locally:

```bash
python3 surface_map.py examples/demo-agent-stack --out public/sample-report.json
python3 -m http.server 8787 --directory public
```

Then open `http://localhost:8787`.

## Code

Repository path for the working draft:

```text
gemma-agent-surface-map/
```

## How I Used Gemma 4

The deterministic scanner is intentionally boring: it walks local files, detects agent-surface signals, and redacts secret values.

Gemma 4 is the judgment layer. It receives a compact, redacted inventory and returns a structured review with:

- summary
- top risks
- quick wins
- hardening plan

I would use Gemma 4 31B Dense for the final review because the task needs nuanced security reasoning and prioritization more than tiny-device latency. Smaller Gemma 4 variants are a good fit for inline local checks, but the 31B model is the better reviewer for turning messy tool access into practical guidance.

The model is not trusted with raw secrets and does not run commands. It explains a local scan that already happened.

## Why It Matters

Coding agents changed the shape of developer risk. A repo can now include instructions for agents, MCP configs, browser access, package scripts, and credentials by reference. That is not just code; it is an operating surface.

Agent Surface Map treats that surface as something builders should be able to inspect before they automate more work.


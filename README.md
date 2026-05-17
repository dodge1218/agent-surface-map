# Agent Surface Map

Agent Surface Map is a local-first safety scanner for people building with coding agents, MCP servers, skills, plugins, browser automation, and shell tools.

It inventories the files that define what an agent can see and do, then asks Gemma 4 to turn that inventory into prioritized risk cards and concrete hardening steps.

This project is a submission candidate for the DEV Gemma 4 Challenge.

## Why This Exists

Modern developer agents can read repos, run shell commands, browse logged-in sites, call local MCP tools, write files, and spend model-provider credits. That means a developer laptop is starting to look like a small production environment.

Traditional scanners catch dependencies and secrets. Agent Surface Map focuses on the agent operating surface:

- enabled MCP servers
- tool permission hints
- writable filesystem scope
- shell and browser automation access
- repo instructions that can steer agents
- package scripts that agents may execute
- environment-variable references without printing secret values

## Quick Start

Generate a demo report:

```bash
python3 surface_map.py examples/demo-agent-stack --out public/sample-report.json
```

Open the UI with link scanning:

```bash
python3 server.py
```

Then visit:

```text
http://localhost:8787
```

The demo server accepts simple public GitHub repository URLs, clones them with shallow/no-submodule settings, removes `.git`, scans local files, and returns the same verdict screen. It does not execute repository code.

## Vercel

The Vercel deployment uses `api/scan.py` instead of `server.py`. It downloads a small GitHub zipball, extracts it to temporary storage, scans files, and returns the same JSON shape as the local server. It does not execute repository code.

## Using Gemma 4

The scanner works without network access and writes a deterministic report. To let Gemma 4 produce the narrative risk review, configure an OpenAI-compatible endpoint:

```bash
export GEMMA_API_KEY="..."
export GEMMA_BASE_URL="https://your-provider.example/v1"
export GEMMA_MODEL="google/gemma-4-31b"
python3 surface_map.py /path/to/agent/repo --out public/sample-report.json --gemma
```

The prompt sent to Gemma contains only file paths, matched config snippets, and redacted environment variable names. Secret values are not read or sent.

## Challenge Fit

Gemma 4 is central because the hard part is not collecting files. The hard part is explaining what matters:

- What can this agent actually do?
- Which permissions create the highest practical risk?
- Which fixes are concrete and low-friction?
- What should a solo builder do first?

The app uses deterministic scanning for trust and Gemma 4 for judgment, prioritization, and plain-English guidance.

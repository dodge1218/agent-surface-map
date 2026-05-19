# Agent Surface Map

Agent Surface Map is a local-first safety scanner for people building with coding agents, MCP servers, skills, plugins, browser automation, and shell tools.

It inventories the files that define what an agent can see and do, then asks Gemma 4 to turn that inventory into prioritized risk cards and concrete hardening steps.

This project is a submission candidate for the DEV Gemma 4 Challenge.

## Ten-Word Version

Paste repo. Scanner checks risk. Gemma explains. Agent installs safer.

## Why This Exists

Modern developer agents can read repos, run shell commands, browse logged-in sites, call local MCP tools, write files, and spend model-provider credits. That means a developer laptop is starting to look like a small production environment.

Traditional scanners catch dependencies and secrets. Agent Surface Map focuses on the agent operating surface:

- enabled MCP servers
- parsed MCP server command, args, env keys, and risk hints
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

The hosted UI includes a one-click scan for this tiny public fixture:

```text
https://github.com/dodge1218/agent-surface-demo-mcp
```

## Process

See `docs/process.md` for the full web + MCP workflow.
See `docs/catalog/preaudit-library.md` for the public MCP pre-audit template library.
See `docs/rules.md` for the public rule catalog.

Short version:

```text
link/path -> read-only scan -> redacted surface map -> Gemma review -> install context
```

## Example MCP Library

The UI includes pre-audit templates for common MCP installs:

- Stealth Browser
- GitHub
- Gmail
- Filesystem
- Playwright
- Fetch
- Postgres
- Memory + Shell

These are representative install profiles, not upstream safety certifications. Each template is scanned into `public/preaudits/` and can be loaded into the verdict screen.

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

The local server, Vercel API, and MCP server use Gemma automatically when `GEMMA_API_KEY` and `GEMMA_BASE_URL` are configured. If Gemma is not configured or the provider call fails, the report falls back to the deterministic local review and sets `review_source` to `fallback`.

The prompt sent to Gemma contains only file paths, matched config snippets, and redacted environment variable names. Secret values are not read or sent.

Public deployment controls:

```bash
ASM_SCAN_RATE_LIMIT_PER_HOUR=30
ASM_GEMMA_PUBLIC_ENABLED=1
ASM_GEMMA_RATE_LIMIT_PER_HOUR=6
ASM_GEMMA_DAILY_USD_CAP=10
ASM_GEMMA_REVIEW_ESTIMATED_USD=0.02
```

For a provider-enforced spend cap, use an API key with its own provider-side credit limit. The app-level budget cap is a defensive fallback for public demos.

## Challenge Fit

Gemma 4 is central because the hard part is not collecting files. The hard part is explaining what matters:

- What can this agent actually do?
- Which permissions create the highest practical risk?
- Which fixes are concrete and low-friction?
- What should a solo builder do first?

The app uses deterministic scanning for trust and Gemma 4 for judgment, prioritization, and plain-English guidance.

See `docs/judging-map.md` for the build mapped directly to the challenge criteria.

## MCP Workflow

The web app is the quick check. The MCP server is the developer-workflow integration.

```bash
python3 mcp_server.py
```

See `docs/mcp-usage.md` for client config and tool schemas. See `docs/security-notes.md` for the MCP server's own safety constraints.

Use it when a coding agent is about to add a new MCP server, browser tool, skill, plugin, or repo instruction pack. The agent can call `scan_github_tool` or `scan_local_tool` first, then use the returned install context as constraints before touching local config.

MCP workflow smoke test:

```bash
python3 scripts/mcp_workflow_smoke.py
```

Optional local path allowlist:

```bash
export ASM_ALLOWED_ROOTS="/path/to/projects:/tmp/review-work"
python3 mcp_server.py
```

Without `ASM_ALLOWED_ROOTS`, the MCP server still refuses obvious credential/profile directories and filesystem root.

# Agent Surface Map

Agent Surface Map is a local-first install-risk reviewer for people building with coding agents, MCP servers, skills, plugins, browser automation, and shell tools.

It inventories the files that define what an agent can see and do, then asks Gemma 4 to turn that inventory into an install posture and concrete constraints.

This project is a submission candidate for the DEV Gemma 4 Challenge.

## Ten-Word Version

Paste repo. Scanner maps surface. Gemma decides posture. Agent installs safer.

## Why This Exists

Modern developer agents can read repos, run shell commands, browse logged-in sites, call local MCP tools, write files, and spend model-provider credits. That means a developer laptop is starting to look like a small production environment.

Traditional scanners catch dependencies and secrets. Agent Surface Map focuses on the agent operating surface:

- enabled MCP servers
- parsed MCP server command, args, env keys, and risk hints from JSON configs with `mcpServers`
- tool permission hints
- writable filesystem scope
- shell and browser automation access
- repo instructions that can steer agents
- package scripts that agents may execute
- environment-variable references without printing secret values

## Quick Start

Install the optional runtime dependency used for parser-backed compose
remediation:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

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

The hosted UI includes a live scan and a saved verified Gemma 4 review for this tiny public fixture:

```text
https://github.com/dodge1218/agent-surface-demo-mcp
```

## Process

See `docs/process.md` for the full web + MCP workflow.
See `docs/catalog/preaudit-library.md` for the public MCP example review library.
See `docs/rules.md` for the public rule catalog.

Short version:

```text
link/path -> read-only scan -> redacted surface map -> Gemma install judgment -> agent constraints
```

## Example MCP Library

The UI includes example review templates for common MCP installs:

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

For a provider-enforced spend cap, use an API key with its own provider-side credit limit. The app-level budget setting is a best-effort demo throttle for public demos.

## Challenge Fit

Gemma 4 is central because the hard part is not collecting files. The hard part is constrained judgment over messy developer context:

- What can this agent actually do?
- Which permissions create the highest practical risk?
- Should it be added carefully, sandboxed first, or rejected?
- Which constraints should the coding agent follow before touching local config?

The app uses deterministic scanning for trust and Gemma 4 for install-policy judgment, prioritization, and plain-English guidance.

See `docs/judging-map.md` for the build mapped directly to the challenge criteria.
See `docs/doctrine.md` and `docs/prd.md` for the locked product doctrine and requirements.

## MCP Workflow

The web app is the quick check. The MCP server is the developer-workflow integration.

```bash
python3 mcp_server.py
```

See `docs/mcp-usage.md` for client config and tool schemas. See `docs/security-notes.md` for the MCP server's own safety constraints.

Use it when a coding agent is about to add a new MCP server, browser tool, skill, plugin, or repo instruction pack. The agent can call `scan_github_tool` or `scan_local_tool` first, then use the returned install context as constraints before touching local config.

The MCP server also exposes `validate_install_plan(report, proposed_config)`, so the agent can check the final config before writing it.

MCP workflow smoke test:

```bash
python3 scripts/mcp_workflow_smoke.py
```

## Drift Watch

The first always-on primitive is `drift_watch.py`: save a baseline scan,
rescan later, and emit a policy action when an agent/tool surface changes.

```bash
python3 drift_watch.py baseline examples/demo-agent-stack \
  --state /tmp/asm-baseline.json \
  --checksum /tmp/asm-baseline.json.sha256 \
  --provenance /tmp/asm-baseline.provenance.json \
  --signing-key-env ASM_BASELINE_SIGNING_KEY \
  --signing-identity security-team
python3 drift_watch.py check examples/demo-agent-stack \
  --state /tmp/asm-baseline.json \
  --state-sha256-file /tmp/asm-baseline.json.sha256 \
  --provenance /tmp/asm-baseline.provenance.json \
  --signing-key-env ASM_BASELINE_SIGNING_KEY \
  --require-signing-identity security-team \
  --out /tmp/asm-drift.json
```

Actions are `ALLOW`, `REVIEW`, `SANDBOX_FIRST`, or `BLOCK`. This is still
install-risk review, not a safety certification.

Team policy can be supplied as JSON or the simple YAML subset shown in
`examples/policy.example.yml`. The same policy shape can be passed to MCP
`validate_install_plan` as `team_policy`, or loaded by the MCP server with
`ASM_POLICY_FILE`, before an agent writes local config. Drift checks enforce
MCP server allow/deny lists, risk thresholds, denied paths, allowed paths, and
browser profile allowlists against newly introduced evidence. Team policy can
also block or require review for newly introduced evidence severities. Docker
compose volume grants and devcontainer mounts/features/lifecycle commands are
included as structured evidence in drift packets. JSON MCP client settings are
also reported with inferred client family, command, args, env keys, and risk
hints:

```bash
python3 drift_watch.py check examples/demo-agent-stack \
  --state /tmp/asm-baseline.json \
  --state-sha256-file /tmp/asm-baseline.json.sha256 \
  --provenance /tmp/asm-baseline.provenance.json \
  --signing-key-env ASM_BASELINE_SIGNING_KEY \
  --runtime-events /tmp/asm-events.json \
  --runtime-events-if-exists \
  --policy examples/policy.example.yml \
  --artifact-dir /tmp/asm-artifacts \
  --github-step-summary \
  --github-annotation \
  --fail-on BLOCK
```

See `docs/github-actions-drift-watch.md` for ready-to-copy GitHub Actions
workflows using artifact-restored, protected committed, release-asset, or
object-storage baselines.

## Runtime Telemetry

`runtime_telemetry.py` is the first runtime-side v2 primitive. It reviews
already-captured tool-call events, redacts args, and detects approval/path,
network, Docker socket, and write-then-shell issues:

```bash
python3 runtime_telemetry.py events.json \
  --policy examples/policy.example.yml \
  --out /tmp/asm-runtime-telemetry.json \
  --fail-on BLOCK
```

`drift_watch.py check --runtime-events events.json` attaches the same analysis
to drift results, candidate packets, GitHub summaries, and CI artifacts. Runtime
detections are correlated to likely capability and MCP server when event
metadata or tool names make that possible.

## Remediation Dry Run

`remediation_renderer.py` converts approved packet patch intents into
reviewable JSON Patch-style operations. It does not write target config:

```bash
python3 remediation_renderer.py /tmp/asm-artifacts/candidate-packet.json \
  --approve remediate_shell \
  --config examples/demo-agent-stack/mcp.json \
  --config-type mcp-json \
  --out /tmp/asm-remediation.json \
  --markdown /tmp/asm-remediation.md
```

For devcontainer review, use `--config .devcontainer/devcontainer.json
--config-type devcontainer-json` to render advisory operations for risky mounts
and lifecycle-command review.

For Docker compose review, use `--config docker-compose.yml --config-type
compose-yaml` to render line-aware advisory operations for risky host volume
grants and compose extension metadata. The compose adapter reads YAML as text
and does not apply changes.

In CI artifact mode, approved prompt IDs can be rendered directly from the drift
check:

```bash
python3 drift_watch.py check examples/demo-agent-stack \
  --state /tmp/asm-baseline.json \
  --artifact-dir /tmp/asm-artifacts \
  --remediation-approve remediate_shell \
  --remediation-config examples/demo-agent-stack/mcp.json \
  --remediation-config-type mcp-json
```

After a reviewer approves the dry-run artifact, create and verify an approval
manifest before any later apply workflow consumes it:

```bash
python3 remediation_approval.py create /tmp/asm-artifacts/remediation-dry-run.json \
  --reviewer security-team \
  --out /tmp/asm-artifacts/remediation-approval.json
python3 remediation_approval.py verify /tmp/asm-artifacts/remediation-dry-run.json \
  --approval /tmp/asm-artifacts/remediation-approval.json \
  --require-reviewer security-team
```

For JSON config only, a verified approval can be applied to a copied output file:

```bash
python3 remediation_apply.py examples/demo-agent-stack/mcp.json \
  --config-type mcp-json \
  --remediation /tmp/asm-artifacts/remediation-dry-run.json \
  --approval /tmp/asm-artifacts/remediation-approval.json \
  --require-reviewer security-team \
  --out /tmp/asm-artifacts/mcp.remediated.json
```

`remediation_apply.py` supports JSON adapters and PyYAML-backed compose YAML
edits for reviewed compose adapter operations.
Use `remediation_pr_body.py` to generate review text from the remediation and
approval artifacts before opening a PR.

Optional local path allowlist:

```bash
export ASM_ALLOWED_ROOTS="/path/to/projects:/tmp/review-work"
python3 mcp_server.py
```

Without `ASM_ALLOWED_ROOTS`, the MCP server defaults local scans to the directory where the server was started, and still refuses obvious credential/profile directories and filesystem root.

## Reproduce The Demo

From a fresh clone:

```bash
python3 -m unittest discover -s tests -v
python3 surface_map.py examples/demo-agent-stack --out /tmp/report.json
python3 scripts/mcp_workflow_smoke.py
```

Expected posture for the demo stack is `sandbox_first`.

## Limits

This flags risky surfaces; it does not prove a repo is benign.

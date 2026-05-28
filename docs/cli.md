# Agent Surface Map CLI

`asm` is the local-first product surface for Agent Surface Map.

It wraps the existing scanner, policy validator, drift watcher, and MCP server
behind one command. It does not require Gemma or any model provider.

## Install

Development install:

```bash
python3 -m pip install -e .
```

Isolated install:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/asm --help
```

Optional compose-remediation dependency:

```bash
python3 -m pip install -e '.[yaml]'
```

## Scan

Local directory:

```bash
asm scan ./repo --out report.json
```

Public GitHub repo:

```bash
asm scan https://github.com/org/mcp-server --out report.json
```

Print full JSON:

```bash
asm scan ./repo --json
asm scan ./repo --format json
```

Use a configured Gemma reviewer:

```bash
asm scan ./repo --gemma --out report.json
```

Default mode is deterministic. The scan still returns an install posture, risk
score, evidence, and install constraints without model credentials.

## Validate

Validate a proposed MCP/client config against a scan report:

```bash
asm validate ./mcp.json --report report.json
```

Use a team policy:

```bash
asm validate ./mcp.json \
  --report report.json \
  --policy agent-surface-policy.yml
```

Fail a CI job on blocked plans:

```bash
asm validate ./mcp.json \
  --report report.json \
  --policy agent-surface-policy.yml \
  --fail-on block
```

Fail on either blocked plans or required changes:

```bash
asm validate ./mcp.json \
  --report report.json \
  --fail-on needs_changes
```

Decisions:

- `pass`: config matches the scan-derived constraints
- `needs_changes`: config needs approval declarations or safer profile/path choices
- `block`: config contradicts posture or team policy

## Explain

Summarize an existing report without rescanning:

```bash
asm explain report.json
```

Print compact explanation JSON:

```bash
asm explain report.json --json
```

## Schemas

Print a schema:

```bash
asm schema report
asm schema policy
asm schema validation
asm schema drift
```

Write all schemas to a directory:

```bash
asm schema --out-dir schemas/
```

## Policy

Create a starter policy:

```bash
asm init-policy --out agent-surface-policy.yml
```

The policy format is the same dependency-free YAML subset used by
`drift_watch.py`: scalar values and top-level string lists.

## Baseline And Check

Save a baseline:

```bash
asm baseline ./repo \
  --state .agent-surface/baseline.json \
  --checksum .agent-surface/baseline.json.sha256
```

Check for drift:

```bash
asm check ./repo \
  --state .agent-surface/baseline.json \
  --state-sha256-file .agent-surface/baseline.json.sha256 \
  --policy agent-surface-policy.yml \
  --fail-on BLOCK
```

Write CI artifacts:

```bash
asm check ./repo \
  --state .agent-surface/baseline.json \
  --artifact-dir .agent-surface/artifacts \
  --github-step-summary \
  --github-annotation \
  --fail-on BLOCK
```

For GitHub Actions, see `docs/github-action.md`.

Actions:

- `ALLOW`
- `REVIEW`
- `SANDBOX_FIRST`
- `BLOCK`

## MCP Server

Run the MCP stdio server through the same installed CLI:

```bash
asm mcp
```

Copy-paste client configs are in `docs/mcp-client-configs.md`.

Optional local path allowlist:

```bash
export ASM_ALLOWED_ROOTS="/path/to/projects:/tmp/review-work"
asm mcp
```

Without `ASM_ALLOWED_ROOTS`, local MCP scans default to the directory where the
server was started and still refuse root, credential, and browser-profile paths.

## Local HTTP API

Run the local API for editor plugins or local control planes:

```bash
asm api --host 127.0.0.1 --port 8765 --allowed-root "$PWD"
```

The API exposes `/healthz`, `/v1/scan`, `/v1/validate`, and schema endpoints.
Local scans are limited to allowed roots. Public GitHub scans can be disabled
with `--no-remote-github`.

Optional API keys and per-client limits:

```bash
ASM_API_KEYS="dev-key" asm api --rate-limit-per-minute 60
```

See `docs/api.md` for the request and response contract.

## Model Doctrine

Models are reviewer backends, not the product foundation.

Use `--gemma` when a Gemma/OpenAI-compatible provider is configured. Omit it for
fully local deterministic scan and policy enforcement.

Reviewer backend code lives in `reviewers.py`; the scanner core does not depend
on one model provider.

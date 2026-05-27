# GitHub Action

Agent Surface Map ships a composite GitHub Action around `asm check`.

Use it after you have a trusted baseline file. For deeper baseline storage,
provenance, runtime telemetry, and remediation workflows, see
`docs/github-actions-drift-watch.md`.

## Minimal Workflow

```yaml
name: Agent Surface Map

on:
  pull_request:

permissions:
  contents: read

jobs:
  agent-surface:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Check agent surface drift
        uses: dodge1218/agent-surface-map@main
        with:
          target: .
          state: .agent-surface/baseline.json
          policy: agent-surface-policy.yml
          fail-on: BLOCK

      - name: Upload Agent Surface artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: agent-surface-drift
          path: .agent-surface/artifacts
```

## Baseline

Create the first baseline intentionally:

```bash
mkdir -p .agent-surface
asm baseline . \
  --state .agent-surface/baseline.json \
  --checksum .agent-surface/baseline.json.sha256
```

Commit the baseline only if your team is comfortable reviewing baseline changes
in pull requests. Otherwise store it as a protected artifact, release asset, or
object-storage object and restore it before running the action.

## Checksum-Protected Baseline

```yaml
- name: Check agent surface drift
  uses: dodge1218/agent-surface-map@main
  with:
    target: .
    state: .agent-surface/baseline.json
    state-sha256-file: .agent-surface/baseline.json.sha256
    policy: agent-surface-policy.yml
    fail-on: BLOCK
```

## Signed Provenance

```yaml
- name: Check agent surface drift
  uses: dodge1218/agent-surface-map@main
  env:
    ASM_BASELINE_SIGNING_KEY: ${{ secrets.ASM_BASELINE_SIGNING_KEY }}
  with:
    target: .
    state: .agent-surface/baseline.json
    state-sha256-file: .agent-surface/baseline.json.sha256
    provenance: .agent-surface/baseline.provenance.json
    signing-key-env: ASM_BASELINE_SIGNING_KEY
    require-signing-identity: security-team
    policy: agent-surface-policy.yml
    fail-on: BLOCK
```

Create a signed baseline:

```bash
asm baseline . \
  --state .agent-surface/baseline.json \
  --checksum .agent-surface/baseline.json.sha256 \
  --provenance .agent-surface/baseline.provenance.json \
  --signing-key-env ASM_BASELINE_SIGNING_KEY \
  --signing-identity security-team
```

## Runtime Telemetry

```yaml
- name: Check agent surface drift
  uses: dodge1218/agent-surface-map@main
  with:
    target: .
    state: .agent-surface/baseline.json
    runtime-events: .agent-surface/runtime-events.json
    runtime-events-if-exists: "true"
    policy: agent-surface-policy.yml
    fail-on: BLOCK
```

## Inputs

- `target`: path to scan. Default: `.`
- `state`: baseline state JSON path. Required.
- `policy`: optional policy file.
- `fail-on`: `REVIEW`, `SANDBOX_FIRST`, or `BLOCK`. Default: `BLOCK`.
- `artifact-dir`: output directory. Default: `.agent-surface/artifacts`.
- `state-sha256-file`: optional baseline checksum file.
- `provenance`: optional signed baseline provenance manifest.
- `signing-key-env`: env var name containing the HMAC signing key.
- `require-signing-identity`: optional required signing identity.
- `runtime-events`: optional runtime telemetry JSON file.
- `runtime-events-if-exists`: skip missing runtime telemetry file. Default:
  `true`.
- `github-step-summary`: append markdown to job summary. Default: `true`.
- `github-annotation`: emit warning/error annotations. Default: `true`.
- `install-package`: install this action package before running `asm`. Default:
  `true`.

## Outputs

- `action`: `ALLOW`, `REVIEW`, `SANDBOX_FIRST`, `BLOCK`, or `UNKNOWN`.
- `drift-result`: path to `drift-result.json`.

## Important

Do not refresh baselines automatically inside the same workflow that checks
drift. A baseline update is a trust decision and should be reviewed like a policy
change.

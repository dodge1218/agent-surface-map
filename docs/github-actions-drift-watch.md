# GitHub Actions Drift Watch

Copy this workflow into `.github/workflows/agent-surface-drift.yml` after you
choose a trusted baseline storage pattern.

## Baseline Pattern A: Artifact Restore

```yaml
name: Agent Surface Drift

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  drift-watch:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Restore baseline
        uses: actions/download-artifact@v4
        with:
          name: agent-surface-baseline
          path: .agent-surface

      - name: Check agent surface drift
        env:
          ASM_BASELINE_SIGNING_KEY: ${{ secrets.ASM_BASELINE_SIGNING_KEY }}
        run: |
          python3 drift_watch.py check . \
            --state .agent-surface/baseline.json \
            --state-sha256-file .agent-surface/baseline.json.sha256 \
            --provenance .agent-surface/baseline.provenance.json \
            --signing-key-env ASM_BASELINE_SIGNING_KEY \
            --require-signing-identity security-team \
            --runtime-events .agent-surface/runtime-events.json \
            --runtime-events-if-exists \
            --policy examples/policy.example.yml \
            --artifact-dir .agent-surface/artifacts \
            --github-step-summary \
            --github-annotation \
            --fail-on BLOCK

      - name: Upload drift artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: agent-surface-drift
          path: .agent-surface/artifacts
```

Create or refresh the baseline intentionally, not automatically on every run:

```bash
python3 drift_watch.py baseline . \
  --state baseline.json \
  --checksum baseline.json.sha256 \
  --provenance baseline.provenance.json \
  --signing-key-env ASM_BASELINE_SIGNING_KEY \
  --signing-identity security-team
```

Then upload `baseline.json`, `baseline.json.sha256`, and
`baseline.provenance.json` as the `agent-surface-baseline` artifact, or store
them in a protected internal location and adapt the restore step.

## Baseline Pattern B: Protected Committed Baseline

Use this pattern when you want baseline changes to go through normal code review.
Commit `.agent-surface/baseline.json` and protect it with CODEOWNERS or branch
protection.

```yaml
name: Agent Surface Drift

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  drift-watch:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Check committed baseline
        env:
          ASM_BASELINE_SIGNING_KEY: ${{ secrets.ASM_BASELINE_SIGNING_KEY }}
        run: |
          python3 drift_watch.py check . \
            --state .agent-surface/baseline.json \
            --state-sha256-file .agent-surface/baseline.json.sha256 \
            --provenance .agent-surface/baseline.provenance.json \
            --signing-key-env ASM_BASELINE_SIGNING_KEY \
            --require-signing-identity security-team \
            --runtime-events .agent-surface/runtime-events.json \
            --runtime-events-if-exists \
            --policy examples/policy.example.yml \
            --artifact-dir .agent-surface/artifacts \
            --github-step-summary \
            --github-annotation \
            --fail-on BLOCK

      - name: Upload drift artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: agent-surface-drift
          path: .agent-surface/artifacts
```

Refresh the committed baseline deliberately:

```bash
mkdir -p .agent-surface
python3 drift_watch.py baseline . \
  --state .agent-surface/baseline.json \
  --checksum .agent-surface/baseline.json.sha256 \
  --provenance .agent-surface/baseline.provenance.json \
  --signing-key-env ASM_BASELINE_SIGNING_KEY \
  --signing-identity security-team
git add .agent-surface/baseline.json .agent-surface/baseline.json.sha256 .agent-surface/baseline.provenance.json
```

## Baseline Pattern C: GitHub Release Asset

Use this pattern when you want the baseline to live outside the repo tree but
still be controlled by GitHub release permissions. Create a stable release such
as `agent-surface-baseline`, attach `baseline.json`, and refresh that asset only
after review.

```yaml
name: Agent Surface Drift

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  drift-watch:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Restore release baseline
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          mkdir -p .agent-surface
          gh release download agent-surface-baseline \
            --pattern 'baseline*' \
            --dir .agent-surface \
            --clobber

      - name: Check release baseline
        env:
          ASM_BASELINE_SIGNING_KEY: ${{ secrets.ASM_BASELINE_SIGNING_KEY }}
        run: |
          python3 drift_watch.py check . \
            --state .agent-surface/baseline.json \
            --state-sha256-file .agent-surface/baseline.json.sha256 \
            --provenance .agent-surface/baseline.provenance.json \
            --signing-key-env ASM_BASELINE_SIGNING_KEY \
            --require-signing-identity security-team \
            --runtime-events .agent-surface/runtime-events.json \
            --runtime-events-if-exists \
            --policy examples/policy.example.yml \
            --artifact-dir .agent-surface/artifacts \
            --github-step-summary \
            --github-annotation \
            --fail-on BLOCK

      - name: Upload drift artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: agent-surface-drift
          path: .agent-surface/artifacts
```

Refresh the release asset deliberately:

```bash
mkdir -p .agent-surface
python3 drift_watch.py baseline . \
  --state .agent-surface/baseline.json \
  --checksum .agent-surface/baseline.json.sha256 \
  --provenance .agent-surface/baseline.provenance.json \
  --signing-key-env ASM_BASELINE_SIGNING_KEY \
  --signing-identity security-team
gh release upload agent-surface-baseline \
  .agent-surface/baseline.json \
  .agent-surface/baseline.json.sha256 \
  .agent-surface/baseline.provenance.json \
  --clobber
```

## Baseline Pattern D: Object Storage

Use this pattern when a security, platform, or compliance team owns baseline
state in an external bucket. The workflow identity should have read-only access
to the approved baseline object. Baseline writers should use a separate approval
path.

```yaml
name: Agent Surface Drift

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  id-token: write

jobs:
  drift-watch:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Configure cloud credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/agent-surface-baseline-reader
          aws-region: us-east-1

      - name: Restore object-storage baseline
        run: |
          mkdir -p .agent-surface
          aws s3 cp s3://security-baselines/agent-surface/baseline.json \
            .agent-surface/baseline.json
          aws s3 cp s3://security-baselines/agent-surface/baseline.json.sha256 \
            .agent-surface/baseline.json.sha256
          aws s3 cp s3://security-baselines/agent-surface/baseline.provenance.json \
            .agent-surface/baseline.provenance.json

      - name: Check object-storage baseline
        env:
          ASM_BASELINE_SIGNING_KEY: ${{ secrets.ASM_BASELINE_SIGNING_KEY }}
        run: |
          python3 drift_watch.py check . \
            --state .agent-surface/baseline.json \
            --state-sha256-file .agent-surface/baseline.json.sha256 \
            --provenance .agent-surface/baseline.provenance.json \
            --signing-key-env ASM_BASELINE_SIGNING_KEY \
            --require-signing-identity security-team \
            --runtime-events .agent-surface/runtime-events.json \
            --runtime-events-if-exists \
            --policy examples/policy.example.yml \
            --artifact-dir .agent-surface/artifacts \
            --github-step-summary \
            --github-annotation \
            --fail-on BLOCK

      - name: Upload drift artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: agent-surface-drift
          path: .agent-surface/artifacts
```

For GCS, Azure Blob Storage, or internal artifact stores, replace only the
credential and restore steps. The drift command and artifact behavior stay the
same.

Every pattern above verifies `baseline.json` against `baseline.json.sha256` and
the signed `baseline.provenance.json` before scanning. The checksum catches
accidental restore mistakes; the signed provenance manifest binds the digest to
a signing identity, git commit when available, and creation timestamp. Keep
`ASM_BASELINE_SIGNING_KEY` in CI secrets and restrict who can refresh the
baseline artifacts.

The examples use `--runtime-events-if-exists`, so repositories can adopt the
workflow before they have runtime logs. When `.agent-surface/runtime-events.json`
is present, artifact mode also writes `runtime-telemetry.json` and the candidate
packet includes a runtime section.

If a reviewer or approval workflow has selected remediation prompt IDs, add
`--remediation-approve <prompt_id>` to the drift check. Artifact mode then writes
`remediation-dry-run.json` and `remediation-dry-run.md` with JSON Patch-style
operations for review. These files are dry-run only; they do not modify
repository config.

For config-aware remediation artifacts, also pass `--remediation-config <file>`
and `--remediation-config-type mcp-json`, `devcontainer-json`, or
`compose-yaml`. The config-aware output stays dry-run only; compose YAML output
is line-aware advisory guidance, not an applied YAML rewrite.

## Remediation Signoff Workflow

Use a separate manually dispatched workflow when a reviewer wants remediation
artifacts for a specific prompt ID and config file. Protect the
`agent-surface-remediation-review` environment with required reviewers in GitHub
repository settings. That makes the run itself the signoff record before the
dry-run artifact is generated.

```yaml
name: Agent Surface Remediation Signoff

on:
  workflow_dispatch:
    inputs:
      prompt_id:
        description: Approved remediation prompt ID, such as remediate_shell
        required: true
        type: string
      config_path:
        description: Config file to render adapter hints against
        required: true
        type: string
      config_type:
        description: Config adapter type
        required: true
        type: choice
        options:
          - mcp-json
          - devcontainer-json
          - compose-yaml

permissions:
  contents: read

jobs:
  render-remediation:
    runs-on: ubuntu-latest
    environment: agent-surface-remediation-review
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Restore baseline
        uses: actions/download-artifact@v4
        with:
          name: agent-surface-baseline
          path: .agent-surface

      - name: Render approved dry-run remediation
        env:
          ASM_BASELINE_SIGNING_KEY: ${{ secrets.ASM_BASELINE_SIGNING_KEY }}
        run: |
          python3 drift_watch.py check . \
            --state .agent-surface/baseline.json \
            --state-sha256-file .agent-surface/baseline.json.sha256 \
            --provenance .agent-surface/baseline.provenance.json \
            --signing-key-env ASM_BASELINE_SIGNING_KEY \
            --require-signing-identity security-team \
            --policy examples/policy.example.yml \
            --artifact-dir .agent-surface/remediation-signoff \
            --remediation-approve "${{ inputs.prompt_id }}" \
            --remediation-config "${{ inputs.config_path }}" \
            --remediation-config-type "${{ inputs.config_type }}"

      - name: Create approval manifest
        run: |
          python3 remediation_approval.py create \
            .agent-surface/remediation-signoff/remediation-dry-run.json \
            --reviewer "${{ github.actor }}" \
            --note "Approved via protected environment agent-surface-remediation-review" \
            --out .agent-surface/remediation-signoff/remediation-approval.json

      - name: Verify approval manifest
        run: |
          python3 remediation_approval.py verify \
            .agent-surface/remediation-signoff/remediation-dry-run.json \
            --approval .agent-surface/remediation-signoff/remediation-approval.json \
            --require-reviewer "${{ github.actor }}"

      - name: Upload remediation signoff artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: agent-surface-remediation-signoff
          path: .agent-surface/remediation-signoff
```

This workflow should be dispatched after a non-`ALLOW` drift run identifies the
prompt ID to approve. It still does not write config or open a pull request. Its
output is a review bundle: `candidate-packet.json`, `candidate-packet.md`,
`drift-result.json`, `remediation-dry-run.json`, `remediation-dry-run.md`, and
`remediation-approval.json`. The approval manifest records the reviewer, prompt
IDs, operation counts, adapter summary, and sha256 of the exact remediation
dry-run artifact. If a team later adds an apply step, keep it behind a separate
protected environment and require `remediation_approval.py verify` against the
dry-run artifact generated here.

For JSON config only, `remediation_apply.py` can consume that verified approval
and write a remediated copy:

```bash
python3 remediation_apply.py .cursor/mcp.json \
  --config-type mcp-json \
  --remediation .agent-surface/remediation-signoff/remediation-dry-run.json \
  --approval .agent-surface/remediation-signoff/remediation-approval.json \
  --require-reviewer "$GITHUB_ACTOR" \
  --out .agent-surface/remediation-signoff/mcp.remediated.json
```

Keep any workflow step that commits or opens a pull request behind a separate
protected environment. The apply helper writes only to the requested output path;
compose YAML apply requires PyYAML and uses parser-backed semantic edits.

## Protected Remediation Pull Request Workflow

Use a second protected workflow when the reviewed remediation output should be
turned into a pull request. This workflow consumes the signoff artifact from the
previous workflow, verifies the approval manifest again, writes the remediated
config to the requested path on a new branch, and opens a pull request. The PR
body is generated from the remediation and approval artifacts so reviewers see
the reviewer, digest, prompt IDs, adapter operations, and residual risk.

Protect the `agent-surface-remediation-apply` environment separately from the
signoff environment. That gives teams two decisions: one to approve the dry-run
artifact, and another to let automation prepare a code change.

```yaml
name: Agent Surface Remediation PR

on:
  workflow_dispatch:
    inputs:
      signoff_run_id:
        description: Workflow run ID that uploaded agent-surface-remediation-signoff
        required: true
        type: string
      config_path:
        description: JSON config file to replace from the verified remediated output
        required: true
        type: string
      config_type:
        description: Config adapter type
        required: true
        type: choice
        options:
          - mcp-json
          - devcontainer-json
          - compose-yaml

permissions:
  contents: write
  pull-requests: write
  actions: read

jobs:
  open-remediation-pr:
    runs-on: ubuntu-latest
    environment: agent-surface-remediation-apply
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Download signoff artifact
        uses: actions/download-artifact@v4
        with:
          name: agent-surface-remediation-signoff
          run-id: ${{ inputs.signoff_run_id }}
          github-token: ${{ github.token }}
          path: .agent-surface/remediation-signoff

      - name: Verify and apply approved remediation
        run: |
          mkdir -p .agent-surface/remediation-apply
          python3 remediation_apply.py "${{ inputs.config_path }}" \
            --config-type "${{ inputs.config_type }}" \
            --remediation .agent-surface/remediation-signoff/remediation-dry-run.json \
            --approval .agent-surface/remediation-signoff/remediation-approval.json \
            --out .agent-surface/remediation-apply/remediated.json
          python3 remediation_pr_body.py \
            --remediation .agent-surface/remediation-signoff/remediation-dry-run.json \
            --approval .agent-surface/remediation-signoff/remediation-approval.json \
            --signoff-run-id "${{ inputs.signoff_run_id }}" \
            --config-path "${{ inputs.config_path }}" \
            --out .agent-surface/remediation-apply/pr-body.md
          cp .agent-surface/remediation-apply/remediated.json "${{ inputs.config_path }}"

      - name: Open pull request
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          branch="agent-surface/remediation-${{ inputs.signoff_run_id }}"
          git config user.name "agent-surface-map"
          git config user.email "agent-surface-map@users.noreply.github.com"
          git checkout -b "$branch"
          git add "${{ inputs.config_path }}"
          git commit -m "Apply approved agent-surface remediation"
          gh pr create \
            --title "Apply approved agent-surface remediation" \
            --body-file .agent-surface/remediation-apply/pr-body.md \
            --base main \
            --head "$branch"
```

Compose YAML support requires PyYAML in the workflow environment and applies only
the reviewed compose adapter operations.

Do not refresh the baseline automatically inside the drift-check workflow. A
baseline update is a trust decision and should be reviewed like a policy change.

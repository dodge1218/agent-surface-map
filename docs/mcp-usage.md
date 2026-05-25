# MCP Usage

Agent Surface Map can run as a local MCP server so a coding agent can ask for safety context before installing a new MCP server, skill, plugin, browser tool, or repo instruction pack.

## Local Config

Example MCP client config:

```json
{
  "mcpServers": {
    "agent-surface-map": {
      "command": "python3",
      "args": ["/absolute/path/to/agent-surface-map/mcp_server.py"]
    }
  }
}
```

For stricter local-path policy:

```bash
export ASM_ALLOWED_ROOTS="/home/me/projects:/tmp/review-work"
```

To apply a standing team policy to `validate_install_plan` calls that do not
include inline `team_policy`:

```bash
export ASM_POLICY_FILE="/absolute/path/to/policy.yml"
```

## Tools

### `scan_github_tool`

Input:

```json
{
  "url": "https://github.com/org/mcp-server"
}
```

Returns a JSON report with:

- install verdict
- risk score
- risk signals
- review source
- redacted evidence
- install constraints for the calling agent

### `scan_local_tool`

Input:

```json
{
  "path": "/path/to/local/tool"
}
```

### `generate_safe_install_context`

Input:

```json
{
  "report": {}
}
```

Use this when an agent already has a scan report and wants only the concise workflow constraints.

### `validate_install_plan`

Input:

```json
{
  "report": {},
  "proposed_config": {
    "global_install": false,
    "required_approvals": ["shell_command"],
    "mcpServers": {}
  },
  "team_policy": {
    "allowed_mcp_server_names": ["filesystem", "browser"],
    "denied_mcp_server_names": ["unsafe-shell"],
    "max_risk_score": 90,
    "allowed_paths": ["/tmp/review-work"],
    "denied_paths": ["/home", "/Users", "/etc", "/var/run/docker.sock"],
    "allowed_browser_profiles": ["clean-agent-profile"],
    "required_approvals": ["shell_command", "write_access"],
    "block_severities": ["critical"],
    "review_severities": ["high"]
  }
}
```

Use this after scanning and before writing local MCP/client config. It checks the final plan against the scan-derived policy and any optional team policy, then returns:

- `pass`
- `needs_changes`
- `block`

It blocks common unsafe plans such as global install after `sandbox_first`, broad local paths, Docker socket exposure, secret values embedded directly in config, denied MCP server names, MCP servers outside a supplied allowlist, policy-denied paths, paths outside supplied `allowed_paths`, browser profiles outside a supplied allowlist, and team-policy blocked severities. Missing scan-derived approvals, team-required approvals, or team-policy review severities return `needs_changes` unless another blocker is present.

The drift watcher uses the same policy fields for changed source evidence, so a
new denied path, non-allowlisted browser profile, or severity-threshold match
can block or require review before an install plan is proposed.

For Docker compose volume strings, policy checks evaluate the host-side source
path. Dockerfile/container-internal absolute paths and compose container targets
are not treated as host path grants.

The scanner also emits structured Docker compose volume evidence and
devcontainer evidence so drift packets can show `source`, `target`, syntax
style, feature names, lifecycle commands, MCP client settings, and risk hints
without depending only on line-level regex excerpts.

For CI, `drift_watch.py check --artifact-dir <dir>` writes
`drift-result.json`, `candidate-packet.json`, and `candidate-packet.md`.
If `--runtime-events <file>` is supplied, it also writes
`runtime-telemetry.json` and attaches detections to the drift result and packet.
Attached runtime detections include correlation fields for likely capability,
matched MCP server when available, relation to newly added vs known surface, and
confidence.
Candidate packets include grouped `capability_review` evidence so a reviewer or
cheap workflow agent can see which changed capability each excerpt supports.
Each group also includes a `remediation_prompt` object with objective,
constraints, suggested changes, patch intents, human-approval requirement, and
expected output schema.
In GitHub Actions, add `--github-step-summary` to append the markdown packet to
`$GITHUB_STEP_SUMMARY`, and `--github-annotation` to print a warning/error
annotation for non-`ALLOW` drift.
Add `--state-sha256-file <file>` when restoring a protected baseline checksum;
the check fails before scanning if the restored state does not match.
For stronger trust-state control, add `--provenance <file>` with
`--signing-key-env <ENV>` and optionally `--require-signing-identity <name>`.
That verifies a signed provenance manifest before the baseline is trusted.

See `docs/github-actions-drift-watch.md` for ready-to-copy workflows using
artifact-restored, protected committed, release-asset, and object-storage
baselines.

## Runtime Telemetry Review

`runtime_telemetry.py` accepts a JSON array, or an object with an `events`
array, and emits normalized/redacted events plus deterministic detections.
Useful event fields are `session_id`, `tool_name`, `args`, `working_directory`,
`network_destinations`, `files_touched`, `approval_status`, and `metadata`.

```bash
python3 runtime_telemetry.py events.json \
  --policy examples/policy.example.yml \
  --out /tmp/asm-runtime-telemetry.json \
  --fail-on BLOCK
```

This is a review primitive for supplied logs. It does not install hooks or
capture live tool calls by itself.

To combine runtime detections with baseline drift:

```bash
python3 drift_watch.py check . \
  --state .agent-surface/baseline.json \
  --runtime-events events.json \
  --runtime-events-if-exists \
  --policy examples/policy.example.yml \
  --artifact-dir .agent-surface/artifacts \
  --fail-on BLOCK
```

## Remediation Dry Run

After a drift check writes `candidate-packet.json`, render approved patch intents
without applying them:

```bash
python3 remediation_renderer.py .agent-surface/artifacts/candidate-packet.json \
  --approve remediate_shell \
  --config .cursor/mcp.json \
  --config-type mcp-json \
  --out .agent-surface/artifacts/remediation-dry-run.json \
  --markdown .agent-surface/artifacts/remediation-dry-run.md
```

The renderer outputs JSON Patch-style operations and markdown review notes. It
does not write MCP/client config. With `--config-type mcp-json`, it also emits
adapter operations that target matching `mcpServers` entries and an
`x-agent-surface` advisory namespace. With `--config-type devcontainer-json`, it
targets risky `mounts`, lifecycle-command review metadata, and
`customizations.agent-surface` advisory fields. With `--config-type
compose-yaml`, it reads compose YAML as raw text and emits line-aware advisory
operations for risky host volume grants plus `x-agent-surface` extension
metadata; it does not rewrite YAML.

`drift_watch.py check` can also render approved remediation artifacts directly
when a candidate packet is produced:

```bash
python3 drift_watch.py check . \
  --state .agent-surface/baseline.json \
  --artifact-dir .agent-surface/artifacts \
  --remediation-approve remediate_shell \
  --remediation-config .cursor/mcp.json \
  --remediation-config-type mcp-json \
  --fail-on BLOCK
```

In artifact mode this writes `remediation-dry-run.json` and
`remediation-dry-run.md`. Supplying `--remediation-config` and
`--remediation-config-type` also includes adapter-specific dry-run operations in
the remediation artifact.

After review, bind a human approval to the exact dry-run artifact before any
later apply workflow consumes it:

```bash
python3 remediation_approval.py create \
  .agent-surface/artifacts/remediation-dry-run.json \
  --reviewer security-team \
  --out .agent-surface/artifacts/remediation-approval.json

python3 remediation_approval.py verify \
  .agent-surface/artifacts/remediation-dry-run.json \
  --approval .agent-surface/artifacts/remediation-approval.json \
  --require-reviewer security-team
```

The verifier checks the dry-run sha256, reviewer, decision, prompt IDs, operation
counts, adapter summary, and `human_approval_required` flag.

For JSON config only, apply verified adapter operations to a copied output file:

```bash
python3 remediation_apply.py .cursor/mcp.json \
  --config-type mcp-json \
  --remediation .agent-surface/artifacts/remediation-dry-run.json \
  --approval .agent-surface/artifacts/remediation-approval.json \
  --require-reviewer security-team \
  --out .agent-surface/artifacts/mcp.remediated.json
```

The apply helper verifies the approval manifest first, supports `mcp-json`,
`devcontainer-json`, and PyYAML-backed `compose-yaml` semantic edits.

Generate a PR body from the verified artifacts before opening a remediation PR:

```bash
python3 remediation_pr_body.py \
  --remediation .agent-surface/artifacts/remediation-dry-run.json \
  --approval .agent-surface/artifacts/remediation-approval.json \
  --config-path .cursor/mcp.json \
  --out .agent-surface/artifacts/remediation-pr-body.md
```

## Intended Agent Workflow

```text
User: Add this MCP to my workflow: https://github.com/org/tool
Agent: I will scan it first with Agent Surface Map.
Agent calls: scan_github_tool(url)
Agent receives: sandbox_first / do_not_add / add_carefully plus constraints
Agent drafts config.
Agent calls: validate_install_plan(report, proposed_config)
Agent fixes blockers before editing config or running install commands.
```

## Smoke Test

Run the stdio MCP workflow smoke test against the public demo fixture:

```bash
python3 scripts/mcp_workflow_smoke.py
```

The script initializes the MCP server, lists tools, calls `scan_github_tool`, and prints the install verdict plus agent constraints.

## Gemma Review Source

If `GEMMA_API_KEY` and `GEMMA_BASE_URL` are set, MCP scan tools attach a Gemma review and return `review_source: "gemma"`.

If Gemma is not configured or the provider call fails, the MCP server returns the deterministic fallback review with `review_source: "fallback"` and does not fail the scan.

Read `docs/security-notes.md` before using this as a standing local MCP server.

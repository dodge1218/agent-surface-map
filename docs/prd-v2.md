# Agent Surface Map V2 PRD

This file tracks ideal additions that should not blur the current hackathon PRD. Additions here are product expansion candidates, not completion requirements for the original demo.

For the local-first product direction, see `docs/local-first-product-prd.md`.

## V2 Thesis

Move from one-shot install-risk review to continuous agentic attack-surface management.

```text
baseline -> drift watch -> policy action -> candidate packet -> runtime telemetry -> human-approved remediation
```

V2 should also make Agent Surface Map pack-compatible:

```text
target classifier -> scanner pack router -> agent_tool_surface packet -> policy gate -> agent handoff
```

## V2 Requirement Candidates

### Scanner Pack Ecosystem

Status: public doctrine and design doc started in
`docs/scanner-pack-ecosystem.md`.

Purpose:

- Treat ASM as the first scanner pack, `agent_tool_surface`.
- Let streaming agents call ASM when they encounter MCP servers, agent tools,
  package install surfaces, browser/shell/file access, or related config.
- Establish a normalized scanner packet contract before adding more pack
  families.
- Keep public rules sanitized while allowing private learning loops to
  contribute generalized risk shapes and false-positive filters.

Desired next:

- Add `schemas/scanner-packet-v1.schema.json`.
- Add `asm scan --packet-out` or include a `scanner_packet` section in report
  JSON.
- Add a tiny router prototype that maps target fingerprints to
  `agent_tool_surface`.
- Add a public-safe rule-pack contribution guide.
- Keep all target-specific research, attack narratives, disclosure workflow,
  and private pattern labels out of public docs.

### Drift Watcher

Status: v1 implementation started in `drift_watch.py`.

Purpose:

- Save a baseline Agent Surface Map scan.
- Rescan the same target later.
- Compare risk score, install posture, MCP servers, capabilities, category counts, and public rule counts.
- Emit a policy action: `ALLOW`, `REVIEW`, `SANDBOX_FIRST`, or `BLOCK`.

Drift events that should matter:

- new MCP server
- new shell capability
- new browser/session capability
- new network/listener capability
- new filesystem/write capability
- new credential/cloud/database/cluster references
- new Docker socket or host-control surface
- new install script
- prompt-instruction surface changes

### Policy File

Status: v1 implementation started in `drift_watch.py` and `examples/policy.example.yml`.

Implemented:

- Optional policy input for drift checks.
- JSON support.
- Dependency-free simple YAML subset support.
- Policy controls for risk score, risk delta, blocked/review capabilities, blocked/review severities, allowed MCP server names, and denied MCP server names.
- CLI failure gates for configured actions with `--fail-on REVIEW`, `--fail-on SANDBOX_FIRST`, and `--fail-on BLOCK`.
- MCP server extraction now recognizes any JSON config with a top-level `mcpServers` object, not only `mcp.json`.
- `validate_install_plan` and the MCP tool accept optional team policy for MCP server allow/deny checks and risk-score ceilings.
- `validate_install_plan` enforces team-policy allowed/denied paths, allowed browser profiles, and required approvals before config writes.
- The MCP server can load a standing default policy from `ASM_POLICY_FILE` for `validate_install_plan` calls that omit inline `team_policy`.
- Drift checks enforce team-policy denied paths, allowed paths, and allowed browser profiles from newly introduced source evidence and include violations in candidate packets.
- Drift checks enforce team-policy blocked/review severities against newly introduced finding/rule evidence.
- Drift and install-plan path policy are mount-aware for Docker compose evidence: host-side volume sources are checked, while Dockerfile/container-internal absolute paths and compose container targets are not treated as host path grants.
- The scanner emits structured Docker compose volume evidence for short syntax and long `type/source/target` syntax, and drift packets include added structured evidence alongside line-based findings.
- The scanner emits structured devcontainer JSON evidence for host mounts, Docker run volume args, features, and lifecycle commands; drift policy checks can block new devcontainer host mounts.
- The scanner emits structured MCP client settings evidence for JSON files with `mcpServers`, including inferred client family, command, args, env keys, and risk hints.
- Drift CLI can write CI artifacts with `--artifact-dir`: `drift-result.json`, `candidate-packet.json`, and a human-readable `candidate-packet.md`.
- GitHub Actions support: `--github-step-summary` appends packet markdown to `$GITHUB_STEP_SUMMARY`, and `--github-annotation` prints warning/error annotations for non-`ALLOW` drift.
- `docs/github-actions-drift-watch.md` provides ready-to-copy GitHub Actions workflows for artifact-restored, protected committed, GitHub release-asset, and object-storage baselines.
- Baseline creation can write a sha256 checksum with `--checksum`, and drift checks can verify restored baselines with `--state-sha256` or `--state-sha256-file` before scanning.
- Baseline creation can write a signed provenance manifest with `--provenance`, `--signing-key-env`, and `--signing-identity`; drift checks can verify it with `--provenance`, `--signing-key-env`, and `--require-signing-identity` before scanning.
- `examples/policy.example.yml` includes allowed roots, blocked paths, approved MCP servers, allowed browser profiles, required approvals, risk thresholds, and severity thresholds.

Desired next:

- Public-key/Sigstore signing support for organizations that do not want shared HMAC keys in CI.

### Candidate Packets

Status: v1 implementation started in `drift_watch.py`.

Implemented:

- Non-`ALLOW` drift results include a compact `candidate_packet`.
- CLI can write the packet to a separate JSON file with `--packet`.
- Packets include explicit policy denial reasons when a denied or non-allowlisted MCP server is added.
- Packet evidence includes bounded, redacted source excerpts for new finding categories, public-rule deltas, and added MCP server configs.
- Packet evidence includes `capability_review`: grouped reviewer notes for each changed capability, with a short explanation and relevant source evidence.
- Each capability review includes a machine-consumable `remediation_prompt` with objective, constraints, suggested changes, patch intents, human-approval requirement, and expected output schema.
- Every `REVIEW`, `SANDBOX_FIRST`, or `BLOCK` drift result can generate a compact packet for review.
- Packets include prior state, current state, evidence, exact question, and proposed next step.
- `remediation_renderer.py` converts approved patch intents into reviewable dry-run operations and markdown notes.

Desired next:

- Add a delegated cheap-agent review prompt template that consumes candidate packets without exposing internal pipeline details.

### Runtime Telemetry

Status: v1 implementation started in `runtime_telemetry.py`.

Implemented:

- Runtime event schema for supplied tool-call logs: timestamp, session id, tool name, redacted args, working directory, network destinations, files touched, approval status, and metadata.
- Deterministic detections for shell-like calls without approval, denied path access, path access outside allowlists, network destinations outside allowlists, Docker socket references, and write-then-shell sequences.
- CLI analysis mode for JSON event arrays with optional policy and `--fail-on REVIEW|BLOCK`.
- `drift_watch.py check --runtime-events` attaches runtime telemetry analysis to drift results and candidate packets; CI artifact mode writes `runtime-telemetry.json`.
- Runtime detections are correlated to likely capability, MCP server when available, relation to newly added vs known surface, and confidence.

Desired:

- Agent/runtime integrations that capture events automatically instead of requiring supplied JSON logs.
- Capture richer MCP metadata from runtime integrations so server matching does not rely on optional event metadata or tool-name heuristics.

### Remediation Suggestions

Status: v1 implementation started in `remediation_renderer.py`.

Implemented:

- Dry-run renderer consumes candidate-packet `remediation_prompt.patch_intents`.
- Renderer emits JSON Patch-style operations and markdown review notes without writing target config.
- Renderer supports explicit prompt approval selection with `--approve`; omitted approvals render all prompts for review.
- `drift_watch.py check --remediation-approve` can write remediation dry-run JSON and markdown artifacts in CI artifact mode after a candidate packet is produced.
- Renderer supports an MCP JSON adapter with `--config <file> --config-type mcp-json`, targeting matching `mcpServers` entries and an `x-agent-surface` advisory namespace.
- Renderer supports a devcontainer JSON adapter with `--config <file> --config-type devcontainer-json`, targeting risky mounts, lifecycle-command review metadata, and `customizations.agent-surface` advisory fields.
- Renderer supports a Docker compose adapter with `--config <file> --config-type compose-yaml`, targeting risky host volume lines and `x-agent-surface` advisory metadata without rewriting YAML.
- Drift checks can pass `--remediation-config` and `--remediation-config-type` through to the renderer so CI artifacts include config-aware dry-run operations.
- `docs/github-actions-drift-watch.md` includes a manually dispatched remediation signoff workflow using a protected GitHub environment, explicit prompt IDs, config adapter selection, and dry-run artifact upload.
- `remediation_approval.py` creates and verifies approval manifests that bind reviewer identity, prompt IDs, operation counts, adapter summary, and sha256 to the exact remediation dry-run artifact.
- `remediation_apply.py` applies verified `mcp-json`, `devcontainer-json`, and PyYAML-backed `compose-yaml` adapter operations to an explicit output file only after approval-manifest verification.
- `docs/github-actions-drift-watch.md` includes a separate protected remediation PR workflow that downloads a signoff artifact, verifies/applies remediation, and opens a pull request for review.
- `remediation_pr_body.py` generates PR body markdown from remediation and approval artifacts, including reviewer, digest, prompt IDs, exact operations, adapter type, and residual risk.
- `requirements.txt` pins the PyYAML major version needed for parser-backed compose remediation.

Desired:

- Add package metadata if the project graduates from script-based demo to installable package.
- Add optional signed PR attestations if a deployment environment needs stronger provenance than GitHub protected environments.

## Non-Goals For V2

- Full EDR/SIEM replacement.
- Autonomous production remediation.
- Malware certification.
- Private disclosure workflow exposure.

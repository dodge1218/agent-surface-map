# Agent Surface Map Local-First Product PRD

## Product Thesis

Agent Surface Map should graduate from a web demo into a local-first guardrail
for developers and coding agents.

The product is not "a website that scans repos." The product is:

```text
pre-install firewall for coding agents, MCP servers, skills, plugins, and tool configs
```

The local product must work without a hosted account, without sending private
repo contents to a public service, and without depending on any single model.

## Core Positioning

Agent Surface Map answers one install-time question:

```text
What should my agent be allowed to do with this tool?
```

It returns:

- install posture: `add_carefully`, `sandbox_first`, or `do_not_add`
- top 1-3 risk signals
- parsed tool access: commands, args, env key names, mounts, listeners, browser/session hints
- copyable constraints for a coding agent
- optional model review when a reviewer backend is configured
- final install-plan validation before config is written

## Product Surfaces

### 0. Scanner Pack Contract: Ecosystem Bridge

Agent Surface Map should be usable as a standalone product and as a scanner pack
inside a broader local-first scanner ecosystem.

The public pack identity is:

```text
pack: agent_tool_surface
execution tier: static-local
scope: MCP servers, agent tools, skills, plugins, package/config surfaces
```

Pack requirements:

- keep deterministic scan and policy validation first-class
- emit stable, bounded evidence a streaming agent can consume
- preserve existing `report`, `validation`, and `drift` contracts
- add a normalized `scanner_packet` contract before adding more pack families
- expose only sanitized, generalized risk patterns in public docs and rules
- avoid target-specific attack, disclosure, queue, or private workflow language

Acceptance:

- a streaming agent can call ASM when it encounters an MCP/tool repo and receive
  constraints before it installs or modifies config
- a future scanner router can treat ASM as `agent_tool_surface` without scraping
  human-only output
- private pattern learning can improve public rules only after sanitization

### 1. CLI: Primary Developer Surface

The CLI is the main product. It should be installable, scriptable, and CI-safe.

Target commands:

```bash
asm scan https://github.com/org/mcp-server
asm scan ./local-tool --out report.json
asm review report.json --model gemma
asm validate ./mcp.json --report report.json --policy agent-surface-policy.yml
asm baseline ./repo --state .agent-surface/baseline.json
asm check ./repo --state .agent-surface/baseline.json --fail-on BLOCK
```

CLI requirements:

- run fully local by default
- never execute target repo code
- produce stable JSON output and readable terminal output
- support `--json`, `--out`, `--policy`, `--fail-on`, and `--no-model`
- exit nonzero for configured policy gates
- redact secret values before output, logs, or model calls
- support local paths and public GitHub repo URLs
- make the fallback/deterministic path feel first-class, not degraded

Acceptance:

- a developer can install and scan a local MCP config in under two minutes
- CI can block an unsafe config without calling a model
- reports are useful even when no model backend is configured

### 2. MCP Server: Agent-Native Surface

The MCP server is the strongest product moat. It lets coding agents ask for
constraints before they install or modify tools.

Target tools:

```text
scan_local_tool(path, policy?)
scan_github_tool(url, policy?)
review_surface_map(report, reviewer?)
validate_install_plan(report, proposed_config, team_policy?)
explain_install_constraints(report)
```

MCP requirements:

- default local scan scope to the server working directory
- require `ASM_ALLOWED_ROOTS` for wider local access
- reject credential/profile/root paths
- return bounded, redacted responses
- expose deterministic posture and evidence even when no model is configured
- let the agent validate final config before writing persistent MCP/client config
- make "scan before install" easy to include in agent instructions

Acceptance:

- a coding agent can call Agent Surface Map before adding a new MCP server
- the returned constraints are concrete enough to shape the install plan
- `validate_install_plan` blocks common unsafe plans without model help

### 3. GitHub Action / CI Gate

CI is the team adoption path. It should catch risky changes to MCP configs,
devcontainers, compose files, package scripts, and repo instructions.

Target usage:

```yaml
- uses: agent-surface-map/action@v1
  with:
    policy: agent-surface-policy.yml
    fail-on: BLOCK
```

CI requirements:

- compare current surface against a signed or checksummed baseline
- emit `ALLOW`, `REVIEW`, `SANDBOX_FIRST`, or `BLOCK`
- upload candidate packets as artifacts
- write GitHub step summaries and annotations
- support protected remediation review without automatic production writes

Acceptance:

- a team can block new broad filesystem mounts, shell access, browser profile reuse,
  Docker socket exposure, or denied MCP servers in pull requests
- reviewers get compact evidence, not raw scanner dumps

### 4. Local HTTP API: Optional Local Integration

The local HTTP API is useful for editor plugins, local dashboards, and agent
control planes that cannot call the CLI or stdio MCP directly. It is still a
local-first surface and must use the same scanner, schemas, policy validation,
and reviewer metadata as the CLI.

Implemented endpoints:

```http
GET /healthz
POST /v1/scan
POST /v1/validate
GET /v1/schema/report
GET /v1/schema/policy
GET /v1/schema/validation
GET /v1/schema/drift
```

Local API requirements:

- bind to `127.0.0.1` by default
- allow local directory scans only under explicit allowed roots
- keep public GitHub URL scans optional
- expose report/policy/validation/drift schemas
- support optional API-key auth for non-health endpoints
- apply per-client request limits for protected endpoints
- label deterministic vs model-reviewed output
- require `--gemma` before model-backed review is used

Acceptance:

- local plugins can scan and validate without shelling out
- callers get the same report contract as CLI, MCP, and CI
- a misconfigured local API does not grant arbitrary filesystem scan access
- small internal/demo deployments can require a bearer key and basic per-client
  throttling before an external gateway is added

### 5. Hosted API: Optional Infrastructure

The hosted API is useful for demos, integrations, and low-friction trials, but
it is not the trust anchor.

Future hosted endpoints:

```http
POST /v1/scans
POST /v1/reviews
POST /v1/validations
GET /v1/scans/{id}
```

Hosted API requirements:

- API keys and rate limits
- bounded public repo retrieval
- no private repo scanning until auth, retention, and privacy controls exist
- no raw model prompt preview in public responses
- provider-side spend caps for model-backed review
- clear labels for deterministic vs model-reviewed output
- abuse controls for public GitHub scanning

Acceptance:

- public users can test a small repo safely
- paid/team users can integrate without exposing more data than the contract says
- hosted failures do not undermine local CLI/MCP use

## Model Strategy

Models are reviewer backends, not the product foundation.

Supported review modes:

- `deterministic`: public rules and policy logic only
- `gemma`: Gemma-backed narrative judgment
- `openai-compatible`: configurable OpenAI-compatible endpoint
- `local-llm`: optional local model endpoint
- `none`: scan and policy output only

The deterministic scanner must always produce:

- risk score
- install posture
- top risk signals
- evidence
- install constraints
- policy validation result

A model may improve prioritization, wording, and combined-risk judgment, but it
must not be required for policy enforcement.

Doctrine:

- never say "Gemma is required"
- say "Gemma was used for the challenge review path"
- say "any configured reviewer backend can consume the redacted surface map"
- keep model output bounded by deterministic evidence and schema
- clearly label reviewer source: `deterministic`, `gemma`, `openai_compatible`,
  `local_llm`, or `fallback`

## Packaging Requirements

Target package shape:

```text
agent_surface_map/
  cli.py
  scanner.py
  reviewers/
  mcp/
  policy/
  reports/
```

Install paths:

```bash
pipx install agent-surface-map
python -m pip install agent-surface-map
docker run --rm -v "$PWD:/work" agent-surface-map scan /work
```

Package requirements:

- `pyproject.toml`
- console script: `asm`
- pinned optional extras:
  - `asm[gemma]`
  - `asm[yaml]`
  - `asm[mcp]`
  - `asm[all]`
- generated schema docs for report JSON
- versioned report format
- backwards-compatible policy file format

## Default Local Workflow

The ideal first-run path:

```bash
pipx install agent-surface-map
asm scan https://github.com/org/mcp-server
asm init-policy
asm validate ~/.config/claude/mcp.json --last-report
```

The ideal agent path:

```text
1. Agent wants to add a tool.
2. Agent calls scan_github_tool(url).
3. Agent reads install constraints.
4. Agent drafts config.
5. Agent calls validate_install_plan(report, proposed_config).
6. Agent writes config only if validation returns allow/needs_changes accepted by the user.
```

## Trust Boundaries

Local:

- trusted to inspect user-selected paths
- never executes scanned code
- stores reports only where the user asks

MCP:

- bounded by allowed roots
- returns compact evidence
- refuses sensitive paths

Hosted:

- public GitHub repos only until private auth and retention controls exist
- strict size limits
- no secrets or prompt previews in responses

Model:

- receives redacted surface maps only
- cannot override hard policy blocks
- cannot invent evidence

## Pricing And Adoption Direction

Open-source/free:

- CLI scanner
- deterministic rules
- MCP server
- basic policy validation
- GitHub Action

Paid/team:

- hosted API
- shared policy management
- scan history
- organization baselines
- signed reports
- reviewer backend management
- dashboard for drift and candidate packets

## Non-Goals

- malware verdicts
- exploit generation
- autonomous config remediation without human approval
- private repo hosted scanning before enterprise-grade data controls
- forcing all users through Gemma or any single model provider

## Success Metrics

- local scan completes on a typical MCP repo in under 60 seconds
- zero target-code execution during scan
- deterministic mode produces useful constraints without model credentials
- MCP workflow can prevent an unsafe agent install plan
- CI gate catches risky config drift with concise evidence
- hosted demo remains a proof path, not the only product path

## Near-Term Build Order

1. Package the CLI with `pyproject.toml` and `asm` console entrypoint. Status: implemented initial package metadata and installed `asm` smoke tests.
2. Normalize report schema and document it. Status: implemented `agent-surface-map.report.v1`, `docs/report-format.md`, and JSON schemas.
3. Make deterministic review output first-class in CLI/UI/MCP. Status: implemented deterministic reviewer metadata and default CLI/MCP fallback path.
4. Add reviewer backend abstraction: deterministic, Gemma, OpenAI-compatible, local endpoint. Status: started with `reviewers.py`.
5. Add `asm init-policy` and `asm validate`. Status: implemented.
6. Add install docs for Claude Code, Codex, Cursor, and generic MCP clients. Status: implemented in `docs/mcp-client-configs.md`.
7. Turn drift watch into a documented GitHub Action. Status: implemented initial composite action and `docs/github-action.md`.
8. Add signed report/baseline support to the default docs. Status: documented for CLI and GitHub Action.
9. Treat hosted API as beta after local trust story is solid.

## Remaining Productization Backlog

### Reviewer Abstraction

Goal:

- move review prompt construction, provider calls, deterministic fallback,
  normalization, and reviewer metadata out of the scanner core.

Required backends:

- `deterministic`
- `gemma`
- `openai-compatible`
- `local-llm`
- `none`

Acceptance:

- `surface_map.py` can keep backwards-compatible wrappers, but core reviewer
  logic lives in a dedicated module/package.
- Report output remains compatible with `agent-surface-map.report.v1`.
- Model failures fall back to deterministic review without failing the scan.
- Hard policy validation does not depend on model text.

### Package Layout

Goal:

- move from script-shaped repo to package-shaped repo once the CLI contract is
  stable.

Status: started with an `agent_surface_map/` package facade and legacy top-level
modules kept as compatibility shims.

Target:

```text
agent_surface_map/
  cli.py
  scanner.py
  reviewers/
  policy.py
  reports/
  mcp/
```

Acceptance:

- `asm` remains the public entrypoint.
- legacy script entrypoints keep working or provide clear compatibility shims.
- tests cover both direct module calls and installed CLI use.

### CLI Polish

Required:

- `asm --version`
- `asm scan --format summary|json`
- `asm explain report.json`
- `asm schema`
- better GitHub URL validation before network calls

Status: implemented initial versions.

### Schema Files

Required schemas:

- report v1
- policy
- validation result
- drift result

Status: implemented under `schemas/`.

### GitHub Action

Required:

- `action.yml`
- minimal README example
- default artifact naming
- PR annotations and step summary enabled by default

Status: implemented initial composite action in `action.yml`.

### MCP Client Install Docs

Required clients:

- Claude Code
- Codex
- Cursor
- generic MCP stdio

Status: implemented in `docs/mcp-client-configs.md`.

### Hosted API V1

Define before implementing:

- endpoint contract
- durable API key/rate-limit behavior beyond local in-memory guards
- retention defaults
- public vs private repo boundary
- deterministic vs model-reviewed response labels

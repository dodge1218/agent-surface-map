# Scanner Pack Ecosystem

Agent Surface Map can stay useful as a standalone tool while also becoming the
first scanner pack in a broader local-first scanner ecosystem.

The public product frame is:

```text
scanner packs for agent, tool, and developer-environment risk
```

Agent Surface Map is the first pack:

```text
pack: agent_tool_surface
inputs: local repo, public GitHub repo URL, MCP config, agent plugin/tool repo
outputs: report, validation result, drift result, scanner packet
execution tier: static-local
```

## Why Packs

A single universal scanner becomes noisy and hard to trust. Tool-specific packs
can be smaller, clearer, and easier to validate.

Each pack should know:

- what target shapes it understands
- what files and manifests matter
- which actions are read-only
- what evidence it emits
- which policy decisions it can support
- which deeper review surfaces are intentionally out of scope

## Shared Flow

```text
target encountered
  -> classify target
  -> select applicable scanner packs
  -> run deterministic/static checks first
  -> normalize evidence packet
  -> apply policy gate
  -> hand constraints or next actions to the agent
```

Streaming agents should receive bounded scanner packets, not raw repository
chaos. The packet must tell the agent what was checked, what was found, what was
not checked, and what action is allowed next.

## Public Pack Families

Initial public-safe pack families:

- `agent_tool_surface`: MCP servers, agent tools, skills, plugins, browser/shell/file access.
- `package_install_surface`: package scripts, install hooks, binary downloads, and dependency metadata.
- `container_iac_surface`: Docker, compose, devcontainer, Kubernetes, Terraform, and cloud-permission hints.
- `web_surface_static`: source-visible routes, auth hints, SSRF/CORS/template/path traversal signals.
- `api_surface`: OpenAPI, Postman, route/controller maps, auth boundaries, and risky methods.
- `secrets_config_surface`: env examples, secret references, credential proxy patterns, and logging risks.

These names are intentionally generic. Public packs describe risk shapes, not
private research operations.

## Scanner Packet V1

All packs should eventually emit a normalized scanner packet:

```json
{
  "packet_version": "agent-surface-map.scanner-packet.v1",
  "pack": "agent_tool_surface",
  "pack_version": "0.1.0",
  "target": "examples/demo-agent-stack",
  "target_type": "mcp_repo",
  "execution_tier": "static-local",
  "authorization": {
    "class": "local_static",
    "allowed_actions": ["read_source", "scan_static", "validate_config"],
    "forbidden_actions": ["execute_target_code", "touch_live_third_party"]
  },
  "verdict": "sandbox_first",
  "risk_score": 63,
  "evidence": [],
  "constraints": [],
  "next_actions": [],
  "untrusted_content_notes": []
}
```

The packet is a bridge between product surfaces:

- CLI can write it as JSON.
- MCP can return it to an agent.
- CI can upload it as an artifact.
- A local orchestrator can route it into the next review stage.

## Learning Loop

The ecosystem should improve by turning repeated, generalized risk patterns into
rules. The public rule catalog should stay sanitized:

```text
observed pattern -> generalized rule -> false-positive filter -> scanner packet field -> policy gate
```

Rules that are safe to publish:

- broad filesystem grants
- browser profile reuse
- unauthenticated local service exposure
- all-interface bind defaults
- Docker socket or host-control exposure
- Kubernetes/cloud credential references
- install hooks and shell execution paths
- environment secret references and credential proxy behavior
- path containment mistakes described generically

Rules that should not be published:

- target-specific attack narratives
- private disclosure or program details
- proof payloads for live systems
- internal prioritization or submission workflow
- private pattern names before they are intentionally sanitized

## Doctrine

Public Agent Surface Map can say:

```text
We build local-first scanner packs from generalized agent/tool risk patterns.
```

It should not frame itself as a public mirror of any non-public workflow.

Non-public workflows may learn from confirmed findings, killed paths, negative
controls, and streaming-agent experience. Public ASM should only receive
sanitized rule shapes and the false-positive lessons needed to make developer
guardrails better.

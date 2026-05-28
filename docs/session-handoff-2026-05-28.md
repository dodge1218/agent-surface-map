# Session Handoff: 2026-05-28

## Current Public State

Agent Surface Map is now public as a productized local-first tool.

- Repository: `https://github.com/dodge1218/agent-surface-map`
- Merged PR: `https://github.com/dodge1218/agent-surface-map/pull/1`
- Release: `https://github.com/dodge1218/agent-surface-map/releases/tag/v0.1.0`
- Current local branch: `main`
- Current release tag: `v0.1.0`
- Submitted DEV/Gemma article remains published from the original challenge work.

Public install:

```bash
python3 -m pip install "git+https://github.com/dodge1218/agent-surface-map.git@v0.1.0"
asm mcp
```

## What Shipped

- `asm` CLI:
  - `scan`
  - `validate`
  - `init-policy`
  - `baseline`
  - `check`
  - `explain`
  - `schema`
  - `mcp`
  - `api`
- MCP stdio server:
  - `scan_local_tool`
  - `scan_github_tool`
  - `generate_safe_install_context`
  - `validate_install_plan`
- Local HTTP API:
  - `/healthz`
  - `/v1/scan`
  - `/v1/validate`
  - `/v1/schema/report`
  - `/v1/schema/policy`
  - `/v1/schema/validation`
  - `/v1/schema/drift`
- Composite GitHub Action: `action.yml`
- CI workflow: `.github/workflows/ci.yml`
- Packaged schemas under `agent_surface_map/schemas/`
- Public docs:
  - `docs/cli.md`
  - `docs/api.md`
  - `docs/report-format.md`
  - `docs/github-action.md`
  - `docs/mcp-client-configs.md`
  - `docs/local-first-product-prd.md`
  - `docs/scanner-pack-ecosystem.md`
  - `docs/release-notes-v0.1.0.md`

## Public Doctrine

Keep Agent Surface Map framed as:

```text
local-first install-risk reviewer for agent tools and MCP servers
```

Long-term public direction:

```text
Agent Surface Map is the first scanner pack: agent_tool_surface.
Future scanner packs should use normalized evidence packets and public-safe risk patterns.
```

Safe public language:

- scanner packs
- risk patterns
- install surfaces
- policy gates
- evidence packets
- drift checks
- local-first guardrails
- sanitized rule catalog

Avoid public language that makes the project look like a private research system
or target-specific offensive workflow.

## Private Boundary

Do not publish:

- private workflow details
- target-specific attack narratives
- private pattern labels
- internal scoring or prioritization logic
- private disclosure workflow details
- proof payloads for live systems
- local private positioning notes

Private learning can inform public rules only after it is generalized into
sanitized risk shapes and false-positive lessons.

## Useful Verification Commands

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile asm_cli.py reviewers.py remediation_pr_body.py remediation_apply.py remediation_approval.py remediation_renderer.py drift_watch.py runtime_telemetry.py policy.py surface_map.py server.py api/scan.py mcp_server.py agent_surface_map/http_api.py scripts/mcp_workflow_smoke.py
python3 scripts/mcp_workflow_smoke.py
```

Clean install smoke:

```bash
tmpdir=$(mktemp -d)
python3 -m venv "$tmpdir/venv"
"$tmpdir/venv/bin/python" -m pip install "git+https://github.com/dodge1218/agent-surface-map.git@v0.1.0"
"$tmpdir/venv/bin/asm" --version
"$tmpdir/venv/bin/asm" schema report
"$tmpdir/venv/bin/asm" api --help
rm -rf "$tmpdir"
```

## Recommended Next Steps

Highest ROI:

1. Create a short demo video or GIF:
   - install from GitHub
   - run `asm mcp`
   - scan the demo MCP fixture
   - show `validate_install_plan` blocking a bad config
2. Add a safe/negative-control demo fixture so users see both risky and safer
   outcomes.
3. Add `scanner-packet-v1.schema.json`.
4. Add `asm scan --packet-out packet.json`.
5. Add a tiny target classifier/router prototype:
   - MCP/tool repo -> `agent_tool_surface`
   - package/install surface -> future pack
   - container/IaC surface -> future pack
6. Consider PyPI only after there is actual user pull. GitHub tag install is
   enough for now.

## Resume Project Framing

Strong framing:

```text
Built a local-first scanner and MCP server that lets coding agents review MCP/tool install risk before modifying local config. It ships with CLI, MCP, local API, CI action, JSON schemas, policy validation, drift checks, and a scanner-pack roadmap.
```

Avoid framing it as a universal safety scanner or a private research platform.

## Important Status Notes

- `main` contains the productized release.
- `v0.1.0` points at the merged productization commit.
- The original submitted challenge project is still represented by the DEV post
  and hosted demo.
- Hosted public API remains demo-grade. Public multi-tenant API work still needs
  durable auth, rate limits, audit logs, retention/privacy policy, abuse
  controls, private repo policy, and spend controls.

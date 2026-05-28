# Agent Surface Map v0.1.0 Release Notes

Agent Surface Map v0.1.0 is the first local-first product release.

## What Ships

- `asm` CLI for scan, validate, baseline, check, schema, explain, MCP, and local
  HTTP API workflows
- deterministic scan and policy review that works without model credentials
- optional Gemma/OpenAI-compatible reviewer backend
- MCP stdio server with safe local scan boundaries
- local HTTP API with allowed-root scanning, optional API keys, and per-client
  in-memory rate limits
- GitHub composite action for drift checks, annotations, and artifacts
- versioned JSON schemas for reports, policy, validation, and drift results
- package facade under `agent_surface_map`
- CI workflow for unit tests, compile checks, package smoke, MCP smoke, and
  composite action smoke
- public scanner-pack direction: ASM is the first `agent_tool_surface` pack,
  with future packs sharing normalized evidence packets

## Trust Boundaries

- repository code is scanned, not executed
- secret-looking values are redacted from evidence and review prompts
- local directory scans are constrained by explicit roots in MCP/API flows
- hosted public scans are public-GitHub-only and bounded by archive limits
- model review is optional; deterministic review remains the fallback
- public rules are sanitized risk patterns, not target-specific research notes

## Non-Goals

- malware verdicts or safety certification
- private repository scanning in the hosted demo
- public multi-tenant hosted API guarantees
- automatic remediation without a reviewed approval artifact
- public exposure of private workflow, target queues, disclosure gates, or
  target-specific attack classes

## Verification

Latest local release checks:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/mcp_workflow_smoke.py
python3 -m pip wheel . -w /tmp/asm-wheelhouse
```

The wheel inspection confirmed packaged schemas and runtime modules are present.

## Publish Notes

Keep local private positioning notes out of the public repo. They should not be
published unless rewritten as public-facing roadmap or market context.

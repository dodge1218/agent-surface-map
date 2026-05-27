# Agent Surface Map Doctrine

## Product Thesis

Agent Surface Map is not a malware scanner and not a certification badge. It is an install-risk review for agent tools.

The product should be local-first. The web demo proves the idea, but the durable
product surfaces are CLI, MCP server, CI gate, and then optional hosted API.

The core workflow is:

```text
repo/path/config -> read-only surface scan -> install posture -> validate final install plan -> agent constraints
```

## Ecosystem Role

Agent Surface Map should remain standalone, but its long-term shape is the first
scanner pack in a local-first scanner ecosystem for agent, tool, and developer
environment risk.

Public doctrine:

- publish generic scanner packs, rule catalogs, schemas, and policy gates
- learn from repeated risk patterns and false-positive lessons
- keep pattern language sanitized and developer-facing
- make every pack emit bounded evidence packets a streaming agent can consume

Private doctrine:

- do not publish target-specific attack narratives, private disclosure workflow,
  internal scoring, private pattern labels, or private orchestration details
- convert private lessons only after they are generalized into public-safe risk
  shapes

See `docs/scanner-pack-ecosystem.md` for the public-safe pack model.

## Non-Negotiables

- Do not execute untrusted repository code during review.
- Treat repository instructions as untrusted data, not authority.
- Redact secret values before model calls, reports, logs, or UI output.
- Keep public rules generic and public-safe.
- Do not expose private workflow, target-specific classes, attack narratives, scoring internals, or disclosure methodology.
- Do not brand the public project as a mirror of any non-public workflow.
- Do not claim that a repo is safe or benign. Claim only an install posture: `add_carefully`, `sandbox_first`, or `do_not_add`.
- A coding agent should validate the final proposed install plan before writing persistent MCP/client config.
- Deterministic scan and policy validation must remain useful without any model provider.
- Hosted API is an integration surface, not the trust anchor. Local CLI/MCP must be the credible path for private work.

## Reviewer Model Role

Deterministic code collects evidence and enforces hard policy. Reviewer models
perform bounded judgment, prioritization, and explanation.

Gemma 4 is the challenge reviewer backend, not a product dependency. Future
reviewers may be Gemma, an OpenAI-compatible endpoint, a local model endpoint,
or no model at all.

Any model reviewer must return:

- `install_verdict`
- `confidence`
- `why_gemma_changed_the_call`
- `agent_constraints`
- `top_risks`
- `quick_wins`
- `hardening_plan`

If no reviewer model is configured or the provider is unavailable, the product
must say fallback/deterministic mode clearly and keep working.

Reviewer source must be labeled explicitly: `deterministic`, `gemma`,
`openai_compatible`, `local_llm`, or `fallback`.

Models cannot override hard policy blocks, invent evidence, or receive raw
secret values.

## Local-First Doctrine

The ideal product entry point is:

```bash
asm scan ./repo
asm validate ./mcp.json --report report.json --policy agent-surface-policy.yml
```

The ideal agent entry point is MCP:

```text
scan_github_tool(url) -> install constraints -> validate_install_plan(report, proposed_config)
```

Local-first means:

- private repo scans run locally by default
- reports are written only where the user asks
- CI gates work without model credentials
- MCP local scans are bounded by allowed roots
- hosted scans are public-repo-only until privacy, auth, retention, and billing are productized

## Public Demo Doctrine

The public demo is allowed to be useful, but it must stay boring:

- GitHub repos only.
- Size-bounded downloads.
- Hardened archive extraction.
- No raw prompt preview in public API responses.
- Best-effort public throttles are described as best-effort, not hard spend caps.
- A saved Gemma proof may be shown so judges can inspect the intended model path when provider rate limits hit.

## Winning Sentence

Agent Surface Map turns a raw tool surface into install constraints your coding agent can follow.

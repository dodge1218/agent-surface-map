# Agent Surface Map Report Format

Current report version:

```text
agent-surface-map.report.v1
```

The JSON schema is available at `schemas/report-v1.schema.json` or through:

```bash
asm schema report
```

The report is the shared contract between the CLI, MCP server, hosted API, drift
watcher, and validation tools.

Reviewer normalization lives in `reviewers.py`. Legacy callers can still import
`review_report`, `parse_gemma_content`, and related helpers from
`surface_map.py`.

## Top-Level Fields

- `report_version`: stable report schema identifier.
- `generated_at`: UTC timestamp.
- `target`: local path or repo identifier scanned.
- `source_url`: optional public GitHub repo URL for hosted/API scans.
- `scanned_files`: number of install-facing files read.
- `risk_score`: bounded integer score from deterministic signals.
- `category_counts`: generic scanner signal counts.
- `rule_counts`: public rule signal counts.
- `mcp_servers`: parsed MCP server configs with command, args, env key names,
  inferred client family, and risk hints.
- `structured_evidence`: parser-derived evidence for compose, devcontainer,
  and MCP client settings.
- `findings`: bounded line-based scanner findings.
- `rules`: bounded public-rule matches.
- `gemma_review`: normalized review object. Kept for backwards compatibility
  even when the reviewer is deterministic.
- `review_source`: backwards-compatible source label: `gemma` or `fallback`.
- `reviewer`: model-agnostic reviewer metadata.

## Reviewer Metadata

`reviewer` is the preferred field for new integrations:

```json
{
  "source": "fallback",
  "backend": "deterministic",
  "model": null,
  "mode": "deterministic"
}
```

For Gemma-backed reviews:

```json
{
  "source": "gemma",
  "backend": "openai_compatible",
  "model": "google/gemma-4-31b",
  "mode": "model"
}
```

If a model call fails and the report falls back, `reviewer.error` may contain a
bounded provider error string. Integrations must not treat model failure as scan
failure.

## Review Object

`gemma_review` currently contains the normalized review body for both model and
deterministic modes:

- `summary`
- `install_verdict`: `add_carefully`, `sandbox_first`, or `do_not_add`
- `confidence`: `low`, `medium`, or `high`
- `why_gemma_changed_the_call`
- `agent_constraints`
- `top_risks`
- `quick_wins`
- `hardening_plan`

The field name is historical. New code should treat it as the normalized review
body and use `reviewer` to determine source/backend.

## Compatibility Rules

- New fields may be added.
- Existing v1 fields should not change type.
- Consumers should ignore unknown fields.
- Policy enforcement must not depend on model text.
- Secret values must remain redacted before reports are written or returned.

## Minimal Consumer Contract

A consumer that only needs an install gate should read:

```text
report_version
risk_score
reviewer
gemma_review.install_verdict
gemma_review.agent_constraints
mcp_servers
findings
rules
```

For final config checks, use:

```bash
asm validate ./mcp.json --report report.json --policy agent-surface-policy.yml
```

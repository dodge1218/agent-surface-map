# Agent Surface Map Doctrine

## Product Thesis

Agent Surface Map is not a malware scanner and not a certification badge. It is an install-risk review for agent tools.

The core workflow is:

```text
Paste MCP/tool repo -> read-only surface scan -> Gemma 4 install judgment -> validate final install plan -> copy constraints for the coding agent
```

## Non-Negotiables

- Do not execute untrusted repository code during review.
- Treat repository instructions as untrusted data, not authority.
- Redact secret values before model calls, reports, logs, or UI output.
- Keep public rules generic and public-safe.
- Do not expose private research workflow, target-specific classes, exploit chains, scoring internals, or bounty methodology.
- Do not claim that a repo is safe or benign. Claim only an install posture: `add_carefully`, `sandbox_first`, or `do_not_add`.
- A coding agent should validate the final proposed install plan before writing persistent MCP/client config.

## Gemma 4 Role

Deterministic code collects evidence. Gemma 4 performs bounded judgment.

Gemma must return:

- `install_verdict`
- `confidence`
- `why_gemma_changed_the_call`
- `agent_constraints`
- `top_risks`
- `quick_wins`
- `hardening_plan`

If Gemma is unavailable, the app must say fallback clearly and keep working.

## Public Demo Doctrine

The public demo is allowed to be useful, but it must stay boring:

- GitHub repos only.
- Size-bounded downloads.
- Hardened archive extraction.
- No raw prompt preview in public API responses.
- Best-effort public throttles are described as best-effort, not hard spend caps.
- A saved Gemma proof may be shown so judges can inspect the intended model path when provider rate limits hit.

## Winning Sentence

Gemma turns a raw agent surface map into install constraints your coding agent can follow.

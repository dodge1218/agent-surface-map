# Public Readiness Review

Date: 2026-05-24

Latest productization update: 2026-05-26

## Links

- Live demo: https://gemma-agent-surface-map.vercel.app
- DEV post: https://dev.to/vonb/agent-surface-map-gemma-4-review-before-you-install-an-mcp-1nbn
- Code repo: https://github.com/dodge1218/agent-surface-map
- Demo MCP fixture: https://github.com/dodge1218/agent-surface-demo-mcp

## Voice Pass

The judge-facing draft in `docs/dev-submission-draft.md` was checked against
Ryan's voice profile and voice library.

What changed:

- Kept the concrete premise first: before an agent installs an MCP, ask Gemma
  what it is about to trust.
- Removed soft overclaiming around safety.
- Made the Gemma/fallback boundary explicit.
- Kept the tone direct and technical instead of turning it into a generic
  product pitch.
- Avoided listicle/corporate language and LLM tells.

## Public Caveat

The live hosted route is working, but upstream Gemma can return provider `429`.
When that happens, the API returns `review_source: "fallback"` and attaches the
provider error. The article and proof docs now describe that honestly.

This should be framed as:

> The product has a live Gemma path and a saved verified Gemma proof, while the
> public demo degrades to a labeled deterministic fallback when the provider is
> rate-limited.

Do not frame it as:

> Every public hosted scan always returns a live Gemma review.

## Verification

Latest local verification during productization:

```bash
python3 -m unittest discover -s tests -v
```

Result: 82 tests passed.

Additional checks run:

- `python3 -m py_compile asm_cli.py reviewers.py remediation_pr_body.py remediation_apply.py remediation_approval.py remediation_renderer.py drift_watch.py runtime_telemetry.py policy.py surface_map.py server.py api/scan.py mcp_server.py scripts/mcp_workflow_smoke.py`
- `python3 scripts/mcp_workflow_smoke.py`
- local `asm baseline` + `asm check --artifact-dir` smoke

Latest hosted demo check:

- Homepage returned HTTP 200.
- `/api/scan` returned HTTP 200 for the demo MCP fixture.
- Current response used `review_source: "fallback"` because the provider
  returned `HTTP Error 429: Too Many Requests`.

## Verdict

Public-ready if the published article matches `docs/dev-submission-draft.md`
and the deployed UI opens on `public/verified-gemma-review.json`.

The remaining risk is not code quality. It is claim control: judges should see
the model path, the fallback behavior, and the saved proof without feeling like
the demo is hiding the provider rate limit.

## Public Commit Scope

Safe to publish:

- CLI/package/productization files: `pyproject.toml`, `asm_cli.py`,
  `reviewers.py`, `schemas/`, `action.yml`
- public product docs: `docs/cli.md`, `docs/report-format.md`,
  `docs/mcp-client-configs.md`, `docs/github-action.md`,
  `docs/local-first-product-prd.md`
- public handoff/readiness docs if desired: `docs/ux-next-agent-handoff.md`,
  `docs/public-readiness-review.md`

Do not publish unless intentionally converted into public positioning:

- local private/internal positioning notes

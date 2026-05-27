# Release Readiness Checklist

Use this before committing or publishing the productized local-first build.

## Public Product Files To Include

- `pyproject.toml`
- `agent_surface_map/`
- `asm_cli.py`
- `reviewers.py`
- `api/__init__.py`
- `schemas/`
- `action.yml`
- `.github/workflows/ci.yml`
- `tests/test_asm_cli.py`
- `docs/cli.md`
- `docs/api.md`
- `docs/report-format.md`
- `docs/mcp-client-configs.md`
- `docs/github-action.md`
- `docs/local-first-product-prd.md`
- `docs/scanner-pack-ecosystem.md`
- `docs/release-notes-v0.1.0.md`
- public UX changes in `public/`
- updated README and existing public docs

## Keep Private Or Rewrite Before Publishing

- local private positioning notes

Reason: internal positioning notes are not product documentation. If any are
published later, rewrite them as public roadmap or market-thesis material
without personal/internal framing.

## Verification Before Commit

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile asm_cli.py reviewers.py remediation_pr_body.py remediation_apply.py remediation_approval.py remediation_renderer.py drift_watch.py runtime_telemetry.py policy.py surface_map.py server.py api/scan.py mcp_server.py agent_surface_map/http_api.py scripts/mcp_workflow_smoke.py
python3 scripts/mcp_workflow_smoke.py
```

Package smoke:

```bash
tmpdir=$(mktemp -d)
python3 -m venv "$tmpdir/venv"
"$tmpdir/venv/bin/python" -m pip install -e .
"$tmpdir/venv/bin/asm" --version
"$tmpdir/venv/bin/asm" schema report
"$tmpdir/venv/bin/asm" scan examples/demo-agent-stack --out "$tmpdir/report.json"
"$tmpdir/venv/bin/asm" explain "$tmpdir/report.json"
"$tmpdir/venv/bin/asm" api --help
rm -rf "$tmpdir"
```

GitHub Action smoke:

```bash
tmpdir=$(mktemp -d)
python3 asm_cli.py baseline examples/demo-agent-stack --state "$tmpdir/baseline.json"
python3 asm_cli.py check examples/demo-agent-stack \
  --state "$tmpdir/baseline.json" \
  --artifact-dir "$tmpdir/artifacts" \
  --github-annotation \
  --fail-on BLOCK
test -f "$tmpdir/artifacts/drift-result.json"
rm -rf "$tmpdir"
```

## Post-Commit Tasks

- Push branch.
- Open PR or merge intentionally.
- Update DEV article button wording if still useful.
- If deploying web changes again, run a live smoke against
  `https://gemma-agent-surface-map.vercel.app`.

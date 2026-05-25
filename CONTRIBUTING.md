# Contributing

Keep changes small, public-safe, and easy to verify.

Before opening a PR, run:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
python3 -m unittest discover -s tests -v
python3 -m py_compile remediation_pr_body.py remediation_apply.py remediation_approval.py remediation_renderer.py drift_watch.py runtime_telemetry.py policy.py surface_map.py server.py api/scan.py mcp_server.py scripts/mcp_workflow_smoke.py
node --check public/app.js
```

Rules for scanner changes:

- do not execute scanned repos
- do not add private bug classes or target-specific logic
- redact values, not just key names
- prefer generic install-risk rules that are explainable to normal developers
- keep Gemma prompts bounded and JSON-shaped

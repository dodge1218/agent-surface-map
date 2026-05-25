# Completion Audit

Current audit date: 2026-05-23

This file records current evidence against `docs/prd.md` and the v2 expansion
tracked in `docs/prd-v2.md`. It is not a safety certification.

## Original PRD

| Requirement | Current evidence |
| --- | --- |
| Local CLI scans | `surface_map.py`; covered by `test_public_rules_detect_common_mcp_risks`, `test_structured_*`, and smoke fixtures. |
| Public GitHub web API scans | `server.py`, `api/scan.py`; traversal and extraction safety covered by `test_safe_extract_rejects_traversal` and URL validation tests. |
| MCP stdio server | `mcp_server.py`; covered by `McpProtocolTests` and `scripts/mcp_workflow_smoke.py`. |
| MCP config parsing | `extracts_mcp_servers_from_any_json_config`, MCP client settings tests, catalog examples, and structured evidence tests. |
| Public risk rules | Shell, browser, filesystem, credential, database, cloud, listener, prompt-instruction, install-script, container, compose, and devcontainer tests. |
| Machine-readable install constraints | `safe_install_context` and MCP workflow smoke output. |
| Final install-plan validation | `validate_install_plan` tests for global installs, broad paths, Docker socket, secrets, team policy, approvals, and severity policy. |
| Common MCP examples | `examples/mcp-catalog/*` and `public/preaudits/*`. |
| Gemma-visible review path and fallback distinction | `review_source` behavior, saved proof artifacts, UI assets/docs, and `test_review_report_marks_fallback_source`. |
| Install-risk wording and non-certification posture | README, doctrine, PRD, rules, and security notes. |

## Security Requirements

| Requirement | Current evidence |
| --- | --- |
| No untrusted code execution | Scanner reads files; GitHub retrieval uses zip/shallow-safe paths; docs and tests enforce scan posture. |
| Archive extraction safety | `safe_extract` rejects traversal, absolute paths, symlinks/devices, too many files, and excessive decompressed size. |
| Hosted API does not return raw prompts | `api/scan.py` returns report shape; prompt internals stay server-side. |
| MCP local path confinement | `assert_allowed_local_path` and MCP protocol tests cover default root/profile/credential refusals. |
| Install-plan blockers | `validate_install_plan` test coverage for broad local paths, embedded secret values, Docker socket, and global install contradictions. |
| Secret redaction coverage | Tests cover env values, bearer tokens, GitHub/OpenAI/npm-style tokens, JWT-like values, URL credentials, and private-key headers. |

## V2 Implemented

| Area | Current evidence |
| --- | --- |
| Drift watcher | `drift_watch.py`; baseline/check CLI, checksum/provenance, policy actions, GitHub annotations, artifacts. |
| Policy file | `policy.py`, `examples/policy.example.yml`, `ASM_POLICY_FILE`, path/browser/MCP/severity controls. |
| Candidate packets | Non-`ALLOW` packets with prior/current state, evidence, exact question, proposed next step, and grouped remediation prompts. |
| Runtime telemetry | `runtime_telemetry.py`; supplied event analysis, redaction, detections, correlation, drift attachment. |
| Remediation dry runs | `remediation_renderer.py`; generic operations plus MCP JSON, devcontainer JSON, and compose YAML adapters. |
| Approval manifests | `remediation_approval.py`; sha256-bound human approval verification. |
| Verified apply | `remediation_apply.py`; approval-gated JSON and PyYAML-backed compose apply to explicit output paths. |
| PR body/workflow | `remediation_pr_body.py`; protected GitHub signoff and PR workflow docs. |
| Dependency manifest | `requirements.txt` pins PyYAML major version for parser-backed compose remediation. |

## Remaining Expansion Items

- Runtime integrations that capture tool-call events automatically instead of requiring supplied JSON logs.
- Richer MCP runtime metadata capture, reducing reliance on optional metadata or tool-name heuristics.
- Public-key/Sigstore signing for organizations that do not want shared HMAC baseline keys in CI.
- Optional signed PR attestations for deployments needing stronger provenance than GitHub protected environments.
- Package metadata if this graduates from script-based demo to installable package.

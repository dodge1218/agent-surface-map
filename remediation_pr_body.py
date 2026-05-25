#!/usr/bin/env python3
"""Render a pull request body from remediation and approval artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from remediation_approval import load_json, sha256_file, verify_approval


def operation_line(operation: dict[str, Any]) -> str:
    patch = operation.get("json_patch") if isinstance(operation.get("json_patch"), dict) else {}
    prompt_id = operation.get("prompt_id", "")
    op = patch.get("op", "")
    path = patch.get("path", "")
    intent = operation.get("intent_operation", "")
    return f"- `{op}` `{path}` from `{prompt_id}` / `{intent}`"


def render_pr_body(remediation: dict[str, Any], approval: dict[str, Any], *, signoff_run_id: str = "", config_path: str = "") -> str:
    adapter = remediation.get("config_adapter") if isinstance(remediation.get("config_adapter"), dict) else {}
    operations = adapter.get("operations", []) if isinstance(adapter, dict) else []
    if not isinstance(operations, list):
        operations = []
    generic_operations = remediation.get("operations", [])
    if not isinstance(generic_operations, list):
        generic_operations = []
    lines = [
        "# Agent Surface Remediation",
        "",
        "## Approval",
        "",
        f"- Reviewer: `{approval.get('reviewer', '')}`",
        f"- Decision: `{approval.get('decision', '')}`",
        f"- Remediation sha256: `{approval.get('remediation_sha256', '')}`",
        f"- Approval manifest sha256: `{approval.get('approval_sha256', '')}`",
        f"- Signoff run: `{signoff_run_id}`" if signoff_run_id else "- Signoff run: `not supplied`",
        "",
        "## Target",
        "",
        f"- Config path: `{config_path}`" if config_path else "- Config path: `not supplied`",
        f"- Source policy action: `{remediation.get('source_policy_action', '')}`",
        f"- Prompt IDs: `{', '.join(str(item) for item in remediation.get('selected_prompt_ids', []))}`",
        f"- Adapter: `{adapter.get('config_type', 'none') if isinstance(adapter, dict) else 'none'}`",
        "",
        "## Adapter Operations",
        "",
    ]
    if operations:
        lines.extend(operation_line(operation) for operation in operations if isinstance(operation, dict))
    else:
        lines.append("- No adapter operations were present.")
    lines.extend(["", "## Generic Intent Operations", ""])
    if generic_operations:
        lines.extend(operation_line(operation) for operation in generic_operations if isinstance(operation, dict))
    else:
        lines.append("- No generic operations were present.")
    lines.extend(
        [
            "",
            "## Residual Risk",
            "",
            "- This PR applies only the reviewed JSON adapter operations.",
            "- It does not certify the target tool as safe.",
            "- Compose YAML artifacts remain advisory until parser-backed YAML edits exist.",
            "- Review the uploaded signoff artifacts before merge.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Render a remediation pull request body.")
    parser.add_argument("--remediation", type=Path, required=True, help="remediation-dry-run.json")
    parser.add_argument("--approval", type=Path, required=True, help="remediation-approval.json")
    parser.add_argument("--require-reviewer", help="Require this exact reviewer identity.")
    parser.add_argument("--signoff-run-id", default="")
    parser.add_argument("--config-path", default="")
    parser.add_argument("--out", type=Path, required=True, help="Write pull request body markdown.")
    args = parser.parse_args()
    try:
        failures = verify_approval(args.remediation, args.approval, require_reviewer=args.require_reviewer)
        if failures:
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        remediation = load_json(args.remediation)
        approval = load_json(args.approval)
        approval = dict(approval)
        approval["approval_sha256"] = sha256_file(args.approval)
        body = render_pr_body(remediation, approval, signoff_run_id=args.signoff_run_id, config_path=args.config_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"invalid PR body input: {exc}", file=sys.stderr)
        return 2
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(body, encoding="utf-8")
    print(f"pr_body={args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

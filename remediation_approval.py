#!/usr/bin/env python3
"""Create and verify human approval manifests for remediation dry-run artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def approval_manifest(remediation_path: Path, reviewer: str, decision: str, note: str = "") -> dict[str, Any]:
    remediation = load_json(remediation_path)
    adapter = remediation.get("config_adapter")
    adapter_summary = None
    if isinstance(adapter, dict):
        adapter_summary = {
            "config_type": adapter.get("config_type"),
            "operation_count": len(adapter.get("operations", [])),
        }
    return {
        "schema_version": 1,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "reviewer": reviewer,
        "decision": decision,
        "note": note,
        "remediation_sha256": sha256_file(remediation_path),
        "target": remediation.get("target"),
        "source_policy_action": remediation.get("source_policy_action"),
        "approved_prompt_ids": remediation.get("approved_prompt_ids", []),
        "selected_prompt_ids": remediation.get("selected_prompt_ids", []),
        "operation_count": len(remediation.get("operations", [])),
        "adapter": adapter_summary,
        "dry_run_only": remediation.get("dry_run_only") is True,
        "human_approval_required": remediation.get("human_approval_required") is True,
    }


def verify_approval(
    remediation_path: Path,
    approval_path: Path,
    *,
    require_reviewer: str | None = None,
    require_decision: str = "approved",
) -> list[str]:
    remediation = load_json(remediation_path)
    approval = load_json(approval_path)
    failures: list[str] = []
    if approval.get("schema_version") != 1:
        failures.append("approval schema_version must be 1")
    if remediation.get("dry_run_only") is not True:
        failures.append("remediation artifact must be dry_run_only")
    if remediation.get("human_approval_required") is not True:
        failures.append("remediation artifact must require human approval")
    if approval.get("dry_run_only") is not True:
        failures.append("approval manifest must record dry_run_only=true")
    if approval.get("human_approval_required") is not True:
        failures.append("approval manifest must record human_approval_required=true")
    if approval.get("decision") != require_decision:
        failures.append(f"approval decision must be {require_decision}")
    if not str(approval.get("reviewer", "")).strip():
        failures.append("approval reviewer is required")
    if require_reviewer and approval.get("reviewer") != require_reviewer:
        failures.append(f"approval reviewer must be {require_reviewer}")
    if approval.get("remediation_sha256") != sha256_file(remediation_path):
        failures.append("remediation sha256 does not match approval manifest")
    for key in ("target", "source_policy_action", "approved_prompt_ids", "selected_prompt_ids"):
        if approval.get(key) != remediation.get(key):
            failures.append(f"approval {key} does not match remediation artifact")
    if approval.get("operation_count") != len(remediation.get("operations", [])):
        failures.append("approval operation_count does not match remediation artifact")
    adapter = remediation.get("config_adapter")
    approval_adapter = approval.get("adapter")
    if isinstance(adapter, dict):
        expected_adapter = {
            "config_type": adapter.get("config_type"),
            "operation_count": len(adapter.get("operations", [])),
        }
        if approval_adapter != expected_adapter:
            failures.append("approval adapter summary does not match remediation artifact")
    elif approval_adapter is not None:
        failures.append("approval adapter summary exists but remediation artifact has no config adapter")
    return failures


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def create_command(args: argparse.Namespace) -> int:
    try:
        manifest = approval_manifest(args.remediation, args.reviewer, args.decision, args.note or "")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"invalid remediation artifact: {exc}", file=sys.stderr)
        return 2
    write_json(args.out, manifest)
    print(f"approval={manifest['decision']} reviewer={manifest['reviewer']} sha256={manifest['remediation_sha256']}")
    return 0


def verify_command(args: argparse.Namespace) -> int:
    try:
        failures = verify_approval(
            args.remediation,
            args.approval,
            require_reviewer=args.require_reviewer,
            require_decision=args.require_decision,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"invalid approval input: {exc}", file=sys.stderr)
        return 2
    if failures:
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("approval=verified")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Create or verify remediation approval manifests.")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="Create an approval manifest for a remediation dry-run artifact.")
    create.add_argument("remediation", type=Path, help="remediation-dry-run.json")
    create.add_argument("--reviewer", required=True, help="Human reviewer identity.")
    create.add_argument("--decision", choices=["approved", "rejected"], default="approved")
    create.add_argument("--note", default="")
    create.add_argument("--out", type=Path, required=True, help="Write approval manifest JSON.")
    create.set_defaults(func=create_command)

    verify = sub.add_parser("verify", help="Verify an approval manifest against a remediation dry-run artifact.")
    verify.add_argument("remediation", type=Path, help="remediation-dry-run.json")
    verify.add_argument("--approval", type=Path, required=True, help="Approval manifest JSON.")
    verify.add_argument("--require-reviewer", help="Require this exact reviewer identity.")
    verify.add_argument("--require-decision", default="approved", choices=["approved", "rejected"])
    verify.set_defaults(func=verify_command)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

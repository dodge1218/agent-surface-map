#!/usr/bin/env python3
"""Unified local-first CLI for Agent Surface Map."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

import drift_watch
import mcp_server
from agent_surface_map.http_api import parse_allowed_roots, parse_api_keys, run_server
from agent_surface_map.reports import schema_path as package_schema_path
from api.scan import scan_url
from policy import load_policy
from surface_map import review_report, scan, validate_install_plan


PACKAGE_NAME = "agent-surface-map"
FALLBACK_VERSION = "0.1.0"
SCHEMA_NAMES = {
    "report": "report-v1.schema.json",
    "policy": "policy.schema.json",
    "validation": "validation-result.schema.json",
    "drift": "drift-result.schema.json",
}

DEFAULT_POLICY = """# Example Agent Surface Map drift policy.
#
# This file uses the dependency-free YAML subset supported by Agent Surface Map:
# scalar numbers/strings and top-level string lists.

max_risk_score: 90
max_risk_delta: 10

block_severities:
  - critical

review_severities:
  - high

block_capabilities:
  - container
  - credentials

review_capabilities:
  - shell
  - browser
  - network
  - filesystem
  - install_script
  - instruction

allowed_mcp_server_names:
  - filesystem
  - browser

denied_mcp_server_names:
  - unsafe-shell

allowed_paths:
  - /tmp/review-work
  - ./project

denied_paths:
  - /home
  - /Users
  - /etc
  - /var/run/docker.sock

allowed_browser_profiles:
  - clean-agent-profile

required_approvals:
  - shell_command
  - write_access
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="asm", description="Agent Surface Map local-first CLI.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {package_version()}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser("scan", help="Scan a local directory or public GitHub repo URL.")
    scan_parser.add_argument("target", help="Local directory or simple https://github.com/org/repo URL.")
    scan_parser.add_argument("--out", type=Path, help="Write report JSON to this path.")
    scan_parser.add_argument("--json", action="store_true", help="Print the full report JSON to stdout.")
    scan_parser.add_argument("--format", choices=["summary", "json"], default="summary", help="Output format for stdout.")
    scan_parser.add_argument("--gemma", action="store_true", help="Use Gemma review when configured.")
    scan_parser.add_argument("--no-model", action="store_true", help="Force deterministic local review.")
    scan_parser.set_defaults(func=scan_command)

    validate_parser = sub.add_parser("validate", help="Validate a proposed install config against a scan report.")
    validate_parser.add_argument("config", type=Path, help="Proposed MCP/client config JSON.")
    validate_parser.add_argument("--report", type=Path, required=True, help="Scan report JSON.")
    validate_parser.add_argument("--policy", type=Path, help="Optional team policy JSON or simple YAML.")
    validate_parser.add_argument("--out", type=Path, help="Write validation JSON to this path.")
    validate_parser.add_argument("--json", action="store_true", help="Print validation JSON to stdout.")
    validate_parser.add_argument("--fail-on", choices=["needs_changes", "block"], action="append", default=[], help="Exit nonzero on this decision.")
    validate_parser.set_defaults(func=validate_command)

    init_policy_parser = sub.add_parser("init-policy", help="Copy the example policy into the current project.")
    init_policy_parser.add_argument("--out", type=Path, default=Path("agent-surface-policy.yml"))
    init_policy_parser.add_argument("--force", action="store_true", help="Overwrite an existing policy file.")
    init_policy_parser.set_defaults(func=init_policy_command)

    explain_parser = sub.add_parser("explain", help="Explain an existing scan report.")
    explain_parser.add_argument("report", type=Path)
    explain_parser.add_argument("--json", action="store_true", help="Print a compact explanation JSON.")
    explain_parser.set_defaults(func=explain_command)

    schema_parser = sub.add_parser("schema", help="Print or write JSON schema artifacts.")
    schema_parser.add_argument("name", nargs="?", choices=sorted(SCHEMA_NAMES), help="Schema name to print.")
    schema_parser.add_argument("--out-dir", type=Path, help="Write all schemas to this directory.")
    schema_parser.set_defaults(func=schema_command)

    baseline_parser = sub.add_parser("baseline", help="Save a drift baseline scan.")
    baseline_parser.add_argument("target", type=Path)
    baseline_parser.add_argument("--state", type=Path, required=True)
    baseline_parser.add_argument("--out", type=Path)
    baseline_parser.add_argument("--checksum", type=Path)
    baseline_parser.add_argument("--provenance", type=Path)
    baseline_parser.add_argument("--signing-key-env")
    baseline_parser.add_argument("--signing-identity", default="unknown")
    baseline_parser.add_argument("--gemma", action="store_true")
    baseline_parser.set_defaults(func=baseline_command)

    check_parser = sub.add_parser("check", help="Compare a target against a saved drift baseline.")
    add_check_args(check_parser)
    check_parser.set_defaults(func=check_command)

    mcp_parser = sub.add_parser("mcp", help="Run the MCP stdio server.")
    mcp_parser.set_defaults(func=mcp_command)

    api_parser = sub.add_parser("api", help="Run the local HTTP API server.")
    api_parser.add_argument("--host", default="127.0.0.1")
    api_parser.add_argument("--port", type=int, default=8765)
    api_parser.add_argument(
        "--allowed-root",
        type=Path,
        action="append",
        help="Local root the API may scan. Defaults to ASM_API_ALLOWED_ROOTS or the current directory.",
    )
    api_parser.add_argument("--no-remote-github", action="store_true", help="Disable public GitHub URL scans.")
    api_parser.add_argument("--gemma", action="store_true", help="Allow Gemma review when configured.")
    api_parser.add_argument(
        "--api-key-env",
        default="ASM_API_KEYS",
        help="Environment variable containing comma- or newline-separated API keys. Empty disables auth.",
    )
    api_parser.add_argument(
        "--rate-limit-per-minute",
        type=int,
        default=int(os.environ.get("ASM_API_RATE_LIMIT_PER_MINUTE", "60")),
        help="Per-client request limit for protected endpoints. Use 0 to disable.",
    )
    api_parser.set_defaults(func=api_command)

    args = parser.parse_args(argv)
    return args.func(args)


def scan_command(args: argparse.Namespace) -> int:
    allow_gemma = bool(args.gemma and not args.no_model)
    target = str(args.target).strip()
    try:
        if is_github_url(target):
            validation_error = github_url_error(target)
            if validation_error:
                print(validation_error, file=sys.stderr)
                return 2
            report = scan_url(target, allow_gemma=allow_gemma)
        else:
            root = Path(target).expanduser().resolve()
            if not root.is_dir():
                print(f"target is not a directory or supported GitHub URL: {target}", file=sys.stderr)
                return 2
            report = scan(root)
            review_report(report, allow_gemma=allow_gemma)
    except Exception as exc:  # noqa: BLE001 - CLI should return readable user errors.
        print(f"scan failed: {exc}", file=sys.stderr)
        return 2

    if args.out:
        write_json(args.out, report)
    if args.json or args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print_scan_summary(report, args.out)
    return 0


def validate_command(args: argparse.Namespace) -> int:
    try:
        report = read_json(args.report)
        config_text = args.config.read_text(encoding="utf-8")
        team_policy = load_policy(args.policy)
        result = validate_install_plan(report, config_text, team_policy=team_policy)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"validation failed: {exc}", file=sys.stderr)
        return 2

    if args.out:
        write_json(args.out, result)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_validation_summary(result, args.out)

    fail_on = set(args.fail_on)
    if result["decision"] == "block" and "needs_changes" in fail_on:
        return 1
    return 1 if result["decision"] in fail_on else 0


def init_policy_command(args: argparse.Namespace) -> int:
    source = Path(__file__).resolve().parent / "examples" / "policy.example.yml"
    if args.out.exists() and not args.force:
        print(f"policy already exists: {args.out} (use --force to overwrite)", file=sys.stderr)
        return 2
    args.out.parent.mkdir(parents=True, exist_ok=True)
    if source.exists():
        shutil.copyfile(source, args.out)
    else:
        args.out.write_text(DEFAULT_POLICY, encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


def explain_command(args: argparse.Namespace) -> int:
    try:
        report = read_json(args.report)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"explain failed: {exc}", file=sys.stderr)
        return 2
    explanation = report_explanation(report)
    if args.json:
        print(json.dumps(explanation, indent=2))
    else:
        print_explanation(explanation)
    return 0


def schema_command(args: argparse.Namespace) -> int:
    if args.out_dir:
        args.out_dir.mkdir(parents=True, exist_ok=True)
        for name, filename in SCHEMA_NAMES.items():
            (args.out_dir / filename).write_text(package_schema_path(name).read_text(encoding="utf-8"), encoding="utf-8")
        print(f"wrote {len(SCHEMA_NAMES)} schemas to {args.out_dir}")
        return 0
    if not args.name:
        print("schema name is required unless --out-dir is supplied", file=sys.stderr)
        return 2
    print(package_schema_path(args.name).read_text(encoding="utf-8"), end="")
    return 0


def baseline_command(args: argparse.Namespace) -> int:
    return drift_watch.baseline(args)


def check_command(args: argparse.Namespace) -> int:
    return drift_watch.check(args)


def mcp_command(_args: argparse.Namespace) -> int:
    return mcp_server.main()


def api_command(args: argparse.Namespace) -> int:
    allowed_roots = args.allowed_root or parse_allowed_roots(os.environ.get("ASM_API_ALLOWED_ROOTS"))
    api_keys = parse_api_keys(os.environ.get(args.api_key_env, ""))
    return run_server(
        args.host,
        args.port,
        allowed_roots=allowed_roots,
        allow_remote_github=not args.no_remote_github,
        allow_gemma=args.gemma,
        api_keys=api_keys,
        rate_limit_per_minute=args.rate_limit_per_minute,
    )


def add_check_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("target", type=Path)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--gemma", action="store_true")
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--state-sha256")
    parser.add_argument("--state-sha256-file", type=Path)
    parser.add_argument("--provenance", type=Path)
    parser.add_argument("--signing-key-env")
    parser.add_argument("--require-signing-identity")
    parser.add_argument("--packet", type=Path)
    parser.add_argument("--markdown", type=Path)
    parser.add_argument("--artifact-dir", type=Path)
    parser.add_argument("--runtime-events", type=Path)
    parser.add_argument("--runtime-events-if-exists", action="store_true")
    parser.add_argument("--runtime-out", type=Path)
    parser.add_argument("--remediation-approve", action="append", default=[])
    parser.add_argument("--remediation-config", type=Path)
    parser.add_argument("--remediation-config-type", choices=["mcp-json", "devcontainer-json", "compose-yaml"])
    parser.add_argument("--remediation-out", type=Path)
    parser.add_argument("--remediation-markdown", type=Path)
    parser.add_argument("--github-step-summary", action="store_true")
    parser.add_argument("--github-annotation", action="store_true")
    parser.add_argument("--packet-always", action="store_true")
    parser.add_argument("--update-state", action="store_true")
    parser.add_argument("--fail-on", action="append", choices=["REVIEW", "SANDBOX_FIRST", "BLOCK"])
    parser.add_argument("--fail-on-block", action="store_true")


def is_github_url(value: str) -> bool:
    return value.startswith("https://github.com/")


def github_url_error(value: str) -> str | None:
    if not value.startswith("https://github.com/"):
        return "only https://github.com/org/repo URLs are accepted for remote scans"
    parts = value.removeprefix("https://github.com/").strip("/").split("/")
    if len(parts) != 2:
        return "use the repo URL, not an issue, PR, blob, or branch link"
    if not all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts):
        return "GitHub owner or repo contains unsupported characters"
    return None


def read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"expected JSON object: {path}")
    return data


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def print_scan_summary(report: dict[str, Any], out: Path | None) -> None:
    review = report.get("gemma_review") if isinstance(report.get("gemma_review"), dict) else {}
    verdict = review.get("install_verdict") or report.get("install_context", {}).get("verdict") or "unknown"
    print(f"target={report.get('target', 'unknown')}")
    print(f"install_posture={verdict}")
    print(f"review_source={report.get('review_source', 'fallback')}")
    print(f"risk_score={report.get('risk_score', 0)} findings={len(report.get('findings', []))} rules={len(report.get('rules', []))}")
    signals = sorted(report.get("category_counts", {}).items(), key=lambda item: item[1], reverse=True)[:3]
    if signals:
        print("top_signals=" + ", ".join(f"{name}:{count}" for name, count in signals))
    if out:
        print(f"wrote={out}")


def print_validation_summary(result: dict[str, Any], out: Path | None) -> None:
    print(f"decision={result['decision']} install_posture={result['install_posture']}")
    for key in ("blockers", "required_changes", "warnings"):
        for item in result.get(key, []):
            print(f"- {key[:-1]}: {item}")
    if out:
        print(f"wrote={out}")


def report_explanation(report: dict[str, Any]) -> dict[str, Any]:
    review = report.get("gemma_review") if isinstance(report.get("gemma_review"), dict) else {}
    reviewer = report.get("reviewer") if isinstance(report.get("reviewer"), dict) else {}
    signals = sorted(report.get("category_counts", {}).items(), key=lambda item: item[1], reverse=True)[:3]
    return {
        "target": report.get("source_url") or report.get("target", "unknown"),
        "report_version": report.get("report_version", "unknown"),
        "install_posture": review.get("install_verdict", "unknown"),
        "risk_score": report.get("risk_score", 0),
        "reviewer": reviewer,
        "top_signals": [{"name": name, "count": count} for name, count in signals],
        "top_risks": review.get("top_risks", [])[:3] if isinstance(review.get("top_risks", []), list) else [],
        "agent_constraints": review.get("agent_constraints", [])[:6] if isinstance(review.get("agent_constraints", []), list) else [],
    }


def print_explanation(explanation: dict[str, Any]) -> None:
    reviewer = explanation.get("reviewer") if isinstance(explanation.get("reviewer"), dict) else {}
    print(f"target={explanation['target']}")
    print(f"report_version={explanation['report_version']}")
    print(f"install_posture={explanation['install_posture']}")
    print(f"risk_score={explanation['risk_score']}")
    print(f"reviewer={reviewer.get('backend', 'unknown')} source={reviewer.get('source', 'unknown')}")
    for signal in explanation.get("top_signals", []):
        print(f"- signal: {signal['name']}:{signal['count']}")
    for risk in explanation.get("top_risks", []):
        print(f"- risk: {risk}")
    for constraint in explanation.get("agent_constraints", []):
        print(f"- constraint: {constraint}")


def package_version() -> str:
    try:
        return version(PACKAGE_NAME)
    except PackageNotFoundError:
        return FALLBACK_VERSION


if __name__ == "__main__":
    raise SystemExit(main())

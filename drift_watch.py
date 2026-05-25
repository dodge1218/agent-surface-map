#!/usr/bin/env python3
"""Detect agent-surface drift between two scans.

The base product answers "what install posture should this tool get?"
This module adds the first always-on primitive: save a trusted baseline, rescan
later, and emit a policy action when capabilities drift.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from policy import load_policy
from remediation_renderer import load_config as load_remediation_config
from remediation_renderer import render_patch_intents
from runtime_telemetry import analyze_events, load_events
from surface_map import (
    docker_mount_host_paths,
    local_path_values,
    matching_path_policy,
    planned_browser_profiles,
    policy_string_set,
    review_report,
    safe_install_context,
    scan,
)


CAPABILITY_RULES = {
    "shell": {
        "categories": {"shell_access"},
        "rules": {"shell_tool_exposure"},
    },
    "browser": {
        "categories": {"browser_access"},
        "rules": {"browser_session_surface"},
    },
    "network": {
        "categories": {"network_access"},
        "rules": {"network_exposure", "local_listener"},
    },
    "filesystem": {
        "categories": {"write_access"},
        "rules": {"filesystem_tool_surface", "broad_filesystem_access"},
    },
    "credentials": {
        "categories": {"secret_reference"},
        "rules": {
            "cloud_credential_surface",
            "database_credential_surface",
            "cluster_credential_surface",
        },
    },
    "container": {
        "categories": set(),
        "rules": {"container_escape_surface"},
    },
    "install_script": {
        "categories": set(),
        "rules": {"install_script_execution"},
    },
    "instruction": {
        "categories": {"instruction_file"},
        "rules": {"prompt_injection_surface"},
    },
}


BLOCKING_CAPABILITIES = {
    "container",
    "credentials",
}


def build_snapshot(target: Path, *, allow_gemma: bool = False) -> dict[str, Any]:
    report = scan(target)
    review_report(report, allow_gemma=allow_gemma)
    context = safe_install_context(report)
    return {
        "schema_version": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target": str(target.resolve()),
        "report": report,
        "install_context": context,
        "summary": summarize_report(report, context),
    }


def summarize_report(report: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    category_counts = dict(report.get("category_counts", {}))
    rule_counts = dict(report.get("rule_counts", {}))
    return {
        "risk_score": int(report.get("risk_score", 0)),
        "verdict": str(context.get("verdict", "add_carefully")),
        "capabilities": sorted(capabilities(category_counts, rule_counts)),
        "category_counts": category_counts,
        "rule_counts": rule_counts,
        "mcp_servers": sorted(server_fingerprint(server) for server in report.get("mcp_servers", [])),
        "structured_evidence": sorted(structured_fingerprint(item) for item in report.get("structured_evidence", [])),
    }


def capabilities(category_counts: dict[str, int], rule_counts: dict[str, int]) -> set[str]:
    found: set[str] = set()
    categories = {key for key, count in category_counts.items() if count}
    rules = {key for key, count in rule_counts.items() if count}
    for name, selectors in CAPABILITY_RULES.items():
        if categories & selectors["categories"] or rules & selectors["rules"]:
            found.add(name)
    return found


def server_fingerprint(server: dict[str, Any]) -> str:
    payload = {
        "name": server.get("name", ""),
        "command": server.get("command", ""),
        "args": server.get("args", []),
        "env_keys": server.get("env_keys", []),
        "risk_hints": server.get("risk_hints", []),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def structured_fingerprint(item: dict[str, Any]) -> str:
    payload = {
        "kind": item.get("kind", ""),
        "path": item.get("path", ""),
        "line": item.get("line", 0),
        "source": item.get("source", ""),
        "target": item.get("target", ""),
        "name": item.get("name", ""),
        "client": item.get("client", ""),
        "command": item.get("command", ""),
        "args": item.get("args", []),
        "env_keys": item.get("env_keys", []),
        "index": item.get("index", ""),
        "syntax": item.get("syntax", ""),
        "risk_hints": item.get("risk_hints", []),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def compare_snapshots(previous: dict[str, Any], current: dict[str, Any], policy: dict[str, Any] | None = None) -> dict[str, Any]:
    prev = previous.get("summary", {})
    cur = current.get("summary", {})
    prev_caps = set(prev.get("capabilities", []))
    cur_caps = set(cur.get("capabilities", []))
    prev_servers = set(prev.get("mcp_servers", []))
    cur_servers = set(cur.get("mcp_servers", []))
    prev_structured = set(prev.get("structured_evidence", []))
    cur_structured = set(cur.get("structured_evidence", []))
    prev_categories = prev.get("category_counts", {})
    cur_categories = cur.get("category_counts", {})
    prev_rules = prev.get("rule_counts", {})
    cur_rules = cur.get("rule_counts", {})

    diff = {
        "risk_score_before": int(prev.get("risk_score", 0)),
        "risk_score_after": int(cur.get("risk_score", 0)),
        "risk_score_delta": int(cur.get("risk_score", 0)) - int(prev.get("risk_score", 0)),
        "verdict_before": prev.get("verdict", "add_carefully"),
        "verdict_after": cur.get("verdict", "add_carefully"),
        "added_capabilities": sorted(cur_caps - prev_caps),
        "removed_capabilities": sorted(prev_caps - cur_caps),
        "added_mcp_servers": sorted(cur_servers - prev_servers),
        "removed_mcp_servers": sorted(prev_servers - cur_servers),
        "added_structured_evidence": sorted(cur_structured - prev_structured),
        "removed_structured_evidence": sorted(prev_structured - cur_structured),
        "category_count_delta": count_delta(prev_categories, cur_categories),
        "rule_count_delta": count_delta(prev_rules, cur_rules),
    }
    diff["policy_violations"] = drift_policy_violations(diff, previous, current, policy or {})
    action, reasons = decide_action(diff, policy or {})
    packet = candidate_packet(action, reasons, diff, prev, cur, previous, current)
    return {
        "schema_version": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target": current.get("target"),
        "action": action,
        "reasons": list(reasons),
        "diff": diff,
        "current_summary": cur,
        "candidate_packet": packet,
    }


def count_delta(before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
    keys = set(before) | set(after)
    return {key: int(after.get(key, 0)) - int(before.get(key, 0)) for key in sorted(keys) if int(after.get(key, 0)) != int(before.get(key, 0))}


def decide_action(diff: dict[str, Any], policy: dict[str, Any] | None = None) -> tuple[str, list[str]]:
    reasons: list[str] = []
    policy = policy or {}
    added_caps = set(diff.get("added_capabilities", []))
    verdict_after = diff.get("verdict_after")
    risk_delta = int(diff.get("risk_score_delta", 0))
    risk_after = int(diff.get("risk_score_after", 0))
    block_caps = set(policy.get("block_capabilities", BLOCKING_CAPABILITIES))
    review_caps = set(policy.get("review_capabilities", []))
    max_risk_score = policy.get("max_risk_score")
    max_risk_delta = policy.get("max_risk_delta")
    allowed_servers = set(policy.get("allowed_mcp_server_names", []))
    denied_servers = set(policy.get("denied_mcp_server_names", []))
    added_server_names = server_names(diff.get("added_mcp_servers", []))

    block_reasons: list[str] = []
    if verdict_after == "do_not_add":
        block_reasons.append("Current install posture is do_not_add.")
    if isinstance(max_risk_score, int) and risk_after > max_risk_score:
        block_reasons.append(f"Current risk score {risk_after} exceeds policy max_risk_score {max_risk_score}.")
    if added_caps & block_caps:
        block_reasons.append("Drift added policy-blocked capability: " + ", ".join(sorted(added_caps & block_caps)) + ".")
    if added_server_names & denied_servers:
        block_reasons.append("Drift added policy-denied MCP server: " + ", ".join(sorted(added_server_names & denied_servers)) + ".")
    if allowed_servers and added_server_names - allowed_servers:
        block_reasons.append("Drift added MCP server outside policy allowlist: " + ", ".join(sorted(added_server_names - allowed_servers)) + ".")
    for violation in diff.get("policy_violations", []):
        if isinstance(violation, dict) and violation.get("severity") == "block":
            block_reasons.append(str(violation.get("message", "Drift violated team policy.")))
    if block_reasons:
        return "BLOCK", block_reasons
    review_reasons: list[str] = []
    for violation in diff.get("policy_violations", []):
        if isinstance(violation, dict) and violation.get("severity") == "review":
            review_reasons.append(str(violation.get("message", "Drift should be reviewed under team policy.")))
    if review_reasons:
        return "REVIEW", review_reasons
    if not material_drift(diff):
        reasons.append("No material agent-surface drift detected.")
        return "ALLOW", reasons
    if verdict_after == "sandbox_first":
        reasons.append("Current install posture is sandbox_first.")
        return "SANDBOX_FIRST", reasons
    if added_caps & review_caps:
        reasons.append("Drift added policy-review capability: " + ", ".join(sorted(added_caps & review_caps)) + ".")
        return "REVIEW", reasons
    if added_caps:
        reasons.append("Drift added capability: " + ", ".join(sorted(added_caps)) + ".")
        return "REVIEW", reasons
    if diff.get("added_mcp_servers"):
        reasons.append("Drift added MCP server configuration.")
        return "REVIEW", reasons
    if isinstance(max_risk_delta, int) and risk_delta > max_risk_delta:
        reasons.append(f"Risk score delta {risk_delta} exceeds policy max_risk_delta {max_risk_delta}.")
        return "REVIEW", reasons
    if risk_delta >= 10:
        reasons.append(f"Risk score increased by {risk_delta}.")
        return "REVIEW", reasons
    if risk_delta > 0:
        reasons.append(f"Risk score increased by {risk_delta}.")
        return "REVIEW", reasons
    reasons.append("No material agent-surface drift detected.")
    return "ALLOW", reasons


def material_drift(diff: dict[str, Any]) -> bool:
    if int(diff.get("risk_score_delta", 0)) != 0:
        return True
    for key in ("added_capabilities", "added_mcp_servers", "added_structured_evidence"):
        if diff.get(key):
            return True
    for key in ("category_count_delta", "rule_count_delta"):
        if any(int(value) > 0 for value in diff.get(key, {}).values() if isinstance(value, int)):
            return True
    return False


def server_names(server_fingerprints: list[str]) -> set[str]:
    names: set[str] = set()
    for raw in server_fingerprints:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            continue
        name = str(payload.get("name", "")).strip()
        if name:
            names.add(name)
    return names


def candidate_packet(
    action: str,
    reasons: list[str],
    diff: dict[str, Any],
    previous_summary: dict[str, Any],
    current_summary: dict[str, Any],
    previous_snapshot: dict[str, Any],
    current_snapshot: dict[str, Any],
) -> dict[str, Any] | None:
    if action == "ALLOW":
        return None
    exact_question = {
        "REVIEW": "Should this drift be allowed with constraints, or should the install posture move to sandbox_first?",
        "SANDBOX_FIRST": "Which constraints must be applied before this changed agent/tool surface is used?",
        "BLOCK": "Is this block justified, and what minimal config change would remove the high-impact capability?",
    }.get(action, "What policy action should this drift receive?")
    excerpts = source_excerpts(diff, previous_snapshot, current_snapshot)
    return {
        "target": current_snapshot.get("target"),
        "policy_action": action,
        "exact_question": exact_question,
        "reasons": reasons,
        "prior_state": {
            "verdict": previous_summary.get("verdict"),
            "risk_score": previous_summary.get("risk_score"),
            "capabilities": previous_summary.get("capabilities", []),
        },
        "current_state": {
            "verdict": current_summary.get("verdict"),
            "risk_score": current_summary.get("risk_score"),
            "capabilities": current_summary.get("capabilities", []),
        },
        "evidence": {
            "risk_score_delta": diff.get("risk_score_delta"),
            "added_capabilities": diff.get("added_capabilities", []),
            "added_mcp_servers": diff.get("added_mcp_servers", []),
            "added_structured_evidence": diff.get("added_structured_evidence", []),
            "rule_count_delta": diff.get("rule_count_delta", {}),
            "category_count_delta": diff.get("category_count_delta", {}),
            "policy_violations": diff.get("policy_violations", []),
            "capability_review": capability_review(diff, excerpts),
            "source_excerpts": excerpts,
        },
        "proposed_next_step": proposed_next_step(action),
    }


def runtime_candidate_packet(result: dict[str, Any]) -> dict[str, Any]:
    telemetry = result.get("runtime_telemetry", {})
    summary = result.get("current_summary", {})
    action = str(telemetry.get("action", "REVIEW"))
    detections = telemetry.get("detections", [])
    return {
        "target": result.get("target"),
        "policy_action": action,
        "exact_question": "Which runtime tool-call detections should block or constrain this agent/tool surface?",
        "reasons": [f"Runtime telemetry action is {action} with {len(detections)} detection(s)."],
        "prior_state": {},
        "current_state": {
            "verdict": summary.get("verdict"),
            "risk_score": summary.get("risk_score"),
            "capabilities": summary.get("capabilities", []),
        },
        "evidence": {
            "runtime_telemetry": telemetry,
            "source_excerpts": [],
        },
        "proposed_next_step": "Review runtime detections, narrow tool permissions, and rerun telemetry before updating the baseline.",
    }


def attach_runtime_telemetry(result: dict[str, Any], telemetry: dict[str, Any]) -> None:
    correlate_runtime_telemetry(result, telemetry)
    result["runtime_telemetry"] = telemetry
    detections = telemetry.get("detections", [])
    if not detections:
        return
    telemetry_action = str(telemetry.get("action", "REVIEW"))
    result.setdefault("reasons", []).append(f"Runtime telemetry action is {telemetry_action} with {len(detections)} detection(s).")
    if result.get("action") == "ALLOW":
        result["action"] = telemetry_action
    elif telemetry_action == "BLOCK":
        result["action"] = "BLOCK"
    packet = result.get("candidate_packet")
    if packet:
        packet.setdefault("evidence", {})["runtime_telemetry"] = telemetry
        packet.setdefault("reasons", []).append(f"Runtime telemetry action is {telemetry_action} with {len(detections)} detection(s).")
    else:
        result["candidate_packet"] = runtime_candidate_packet(result)


def correlate_runtime_telemetry(result: dict[str, Any], telemetry: dict[str, Any]) -> None:
    diff = result.get("diff", {})
    current_summary = result.get("current_summary", {})
    added_caps = set(diff.get("added_capabilities", []))
    current_caps = set(current_summary.get("capabilities", []))
    added_servers = server_names(diff.get("added_mcp_servers", []))
    current_servers = server_names(current_summary.get("mcp_servers", []))
    correlations = []
    for item in telemetry.get("detections", []):
        if not isinstance(item, dict):
            continue
        capability = runtime_detection_capability(item)
        server = runtime_detection_server(item, added_servers | current_servers)
        relation = "uncorrelated"
        confidence = "low"
        if server and server in added_servers and capability and capability in added_caps:
            relation = "new_capability_and_mcp_server"
            confidence = "high"
        elif server and server in added_servers:
            relation = "new_mcp_server"
            confidence = "high"
        elif capability and capability in added_caps:
            relation = "new_capability"
            confidence = "high"
        elif capability and capability in current_caps:
            relation = "known_capability"
            confidence = "medium"
        elif server and server in current_servers:
            relation = "known_mcp_server"
            confidence = "medium"
        correlation = {
            "event_index": item.get("event_index"),
            "detection_type": item.get("type"),
            "likely_capability": capability,
            "matched_mcp_server": server,
            "relation": relation,
            "confidence": confidence,
        }
        item["correlation"] = correlation
        correlations.append(correlation)
    telemetry["correlations"] = correlations


def runtime_detection_capability(item: dict[str, Any]) -> str | None:
    kind = str(item.get("type", ""))
    if kind in {"shell_without_approval", "write_then_shell_sequence"}:
        return "shell"
    if kind in {"denied_path_touched", "outside_allowed_paths"}:
        return "filesystem"
    if kind == "network_destination_outside_allowlist":
        return "network"
    if kind == "docker_socket_runtime_surface":
        return "container"
    text = json.dumps(item, sort_keys=True).lower()
    if "browser" in text or "profile" in text or "cookie" in text:
        return "browser"
    if "credential" in text or "secret" in text or "token" in text:
        return "credentials"
    return None


def runtime_detection_server(item: dict[str, Any], known_servers: set[str]) -> str | None:
    explicit = str(item.get("mcp_server") or "").strip()
    if explicit:
        return explicit
    tool_name = str(item.get("tool_name") or "").strip().lower()
    for server in sorted(known_servers):
        lowered = server.lower()
        if lowered and (lowered == tool_name or lowered in tool_name or tool_name in lowered):
            return server
    return None


def capability_review(diff: dict[str, Any], excerpts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    added = list(diff.get("added_capabilities", []))
    groups: dict[str, dict[str, Any]] = {}
    for capability in added:
        groups[capability] = {
            "capability": capability,
            "why_it_matters": capability_explanation(capability),
            "remediation_prompt": remediation_prompt(capability),
            "evidence": [],
        }
    for item in excerpts:
        capability = capability_for_evidence(item)
        if capability is None:
            continue
        group = groups.setdefault(
            capability,
            {
                "capability": capability,
                "why_it_matters": capability_explanation(capability),
                "remediation_prompt": remediation_prompt(capability),
                "evidence": [],
            },
        )
        group["evidence"].append(item)
    return [groups[key] for key in sorted(groups)]


def capability_explanation(capability: str) -> str:
    return {
        "shell": "The tool can run commands or spawn processes, so failures can become local code execution.",
        "browser": "The tool can touch browser sessions or profiles, so it may inherit logged-in user state.",
        "network": "The tool opens or uses network surfaces, so scope and exposure need review.",
        "filesystem": "The tool can read or write files, so path grants should stay project-scoped.",
        "credentials": "The tool references secrets, cloud credentials, databases, or clusters, so values and privileges need tighter handling.",
        "container": "The tool touches container or Docker socket surfaces, which can become host-level control.",
        "install_script": "The package can execute code during install, before the user has reviewed runtime behavior.",
        "instruction": "The repo contains instruction-like text that should be treated as untrusted model context.",
    }.get(capability, "This capability changes the agent/tool trust boundary and should be reviewed.")


def remediation_prompt(capability: str) -> dict[str, Any]:
    prompts = {
        "shell": {
            "objective": "Remove or tightly gate new shell/process execution surface.",
            "constraints": [
                "Require explicit human approval before every command.",
                "Constrain working directory to the reviewed project.",
                "Add timeouts and command allowlists where possible.",
            ],
            "suggested_changes": [
                "Replace broad command execution with named, parameterized operations.",
                "Document required commands and reject unknown commands by default.",
            ],
            "patch_intents": [
                {"operation": "add_required_approval", "field": "required_approvals", "value": "shell_command"},
                {"operation": "narrow_working_directory", "field": "working_directory", "value": "project_root"},
                {"operation": "add_command_allowlist", "field": "allowed_commands", "value": []},
            ],
        },
        "browser": {
            "objective": "Prevent reuse of personal browser sessions or persistent cookies.",
            "constraints": [
                "Use a clean dedicated browser profile.",
                "Do not mount or reference personal Chrome/Chromium profile directories.",
                "Disable persistent auth unless a human approves the target site.",
            ],
            "suggested_changes": [
                "Set a project-local temporary user-data-dir.",
                "Remove storageState/cookie reuse from default config.",
            ],
            "patch_intents": [
                {"operation": "set_clean_profile", "field": "browser_profile", "value": "clean-agent-profile"},
                {"operation": "remove_personal_profile_mount", "field": "args", "value": "--user-data-dir"},
                {"operation": "remove_cookie_reuse", "field": "storageState", "value": None},
            ],
        },
        "network": {
            "objective": "Reduce new listener or outbound network exposure.",
            "constraints": [
                "Bind local services to 127.0.0.1 unless remote access is required.",
                "Document ports, auth, and expected destinations.",
                "Block unnecessary network access in routine workflows.",
            ],
            "suggested_changes": [
                "Replace 0.0.0.0 binds with localhost.",
                "Add explicit network allowlists for agent tool calls.",
            ],
            "patch_intents": [
                {"operation": "bind_localhost", "field": "host", "value": "127.0.0.1"},
                {"operation": "document_ports", "field": "network_policy.ports", "value": []},
                {"operation": "add_destination_allowlist", "field": "network_policy.allowed_destinations", "value": []},
            ],
        },
        "filesystem": {
            "objective": "Narrow filesystem access to the smallest project-local path set.",
            "constraints": [
                "Avoid home, root, system, Docker socket, and credential directories.",
                "Prefer read-only mounts for review workflows.",
                "Grant write access only to explicit project output directories.",
            ],
            "suggested_changes": [
                "Replace broad mounts with the reviewed project directory.",
                "Split read-only scan access from write-capable execution access.",
            ],
            "patch_intents": [
                {"operation": "replace_broad_mount", "field": "mounts", "value": "project_root"},
                {"operation": "set_read_only", "field": "mounts.read_only", "value": True},
                {"operation": "add_write_allowlist", "field": "allowed_write_paths", "value": []},
            ],
        },
        "credentials": {
            "objective": "Keep secrets and privileged resources out of model/tool context.",
            "constraints": [
                "Pass secret names by reference, never raw values.",
                "Use least-privilege credentials and read-only database users.",
                "Do not grant production cloud, cluster, or database access by default.",
            ],
            "suggested_changes": [
                "Move secret values to environment references or a secret manager.",
                "Use scoped test credentials for agent workflows.",
            ],
            "patch_intents": [
                {"operation": "replace_secret_value_with_reference", "field": "env", "value": "secret_name_only"},
                {"operation": "require_least_privilege_secret", "field": "required_approvals", "value": "credential_access"},
                {"operation": "remove_production_credential_defaults", "field": "env", "value": None},
            ],
        },
        "container": {
            "objective": "Remove host-control paths and container escape surface.",
            "constraints": [
                "Do not expose /var/run/docker.sock to untrusted agent tools.",
                "Avoid privileged containers and host PID/network modes.",
                "Run the tool in an isolated sandbox before baseline approval.",
            ],
            "suggested_changes": [
                "Remove Docker socket mounts.",
                "Use a restricted sidecar or remote builder instead of host Docker access.",
            ],
            "patch_intents": [
                {"operation": "remove_docker_socket_mount", "field": "volumes", "value": "/var/run/docker.sock"},
                {"operation": "drop_privileged_container", "field": "privileged", "value": False},
                {"operation": "sandbox_first", "field": "install_posture", "value": "sandbox_first"},
            ],
        },
        "install_script": {
            "objective": "Prevent surprise code execution during dependency installation.",
            "constraints": [
                "Review install scripts before package installation.",
                "Prefer lockfiles and reproducible installs.",
                "Run installation in a sandbox when scripts are required.",
            ],
            "suggested_changes": [
                "Disable lifecycle scripts for initial review where possible.",
                "Document why each install script is required.",
            ],
            "patch_intents": [
                {"operation": "disable_lifecycle_scripts_for_review", "field": "install_args", "value": "--ignore-scripts"},
                {"operation": "require_install_script_review", "field": "required_approvals", "value": "install_script"},
                {"operation": "document_install_script", "field": "install_script_justification", "value": ""},
            ],
        },
        "instruction": {
            "objective": "Treat new repo instructions as untrusted model context.",
            "constraints": [
                "Do not elevate repo instructions above system/developer policy.",
                "Summarize instruction files before use.",
                "Ignore requests to reveal secrets, disable safety checks, or override policy.",
            ],
            "suggested_changes": [
                "Move trusted workflow instructions into reviewed team config.",
                "Flag prompt-injection language for human review.",
            ],
            "patch_intents": [
                {"operation": "treat_repo_instruction_as_data", "field": "instruction_trust", "value": "untrusted"},
                {"operation": "require_instruction_review", "field": "required_approvals", "value": "instruction_file"},
                {"operation": "remove_policy_override_language", "field": "instructions", "value": None},
            ],
        },
    }
    base = prompts.get(
        capability,
        {
            "objective": "Review and narrow the changed agent/tool trust boundary.",
            "constraints": ["Keep access least-privilege.", "Require human approval for privileged actions."],
            "suggested_changes": ["Remove unnecessary access or move it behind explicit policy."],
            "patch_intents": [
                {"operation": "narrow_access", "field": "policy", "value": "least_privilege"},
                {"operation": "require_human_approval", "field": "required_approvals", "value": "privileged_action"},
            ],
        },
    )
    return {
        "prompt_id": f"remediate_{capability}",
        "capability": capability,
        "objective": base["objective"],
        "constraints": base["constraints"],
        "suggested_changes": base["suggested_changes"],
        "patch_intents": base["patch_intents"],
        "human_approval_required": True,
        "output_schema": {
            "decision": "allow_with_constraints | needs_changes | block",
            "minimal_config_changes": ["string"],
            "approval_requirements": ["string"],
            "residual_risk": "string",
        },
    }


def capability_for_evidence(item: dict[str, Any]) -> str | None:
    category = str(item.get("category", ""))
    for capability, selectors in CAPABILITY_RULES.items():
        if category in selectors["categories"] or category in selectors["rules"]:
            return capability
    hints = " ".join(str(value) for value in item.get("risk_hints", []))
    text = json.dumps(item, sort_keys=True)
    combined = f"{hints} {text}".lower()
    if "broad host path" in combined or "filesystem" in combined or "/home" in combined or "/users" in combined or "write" in combined:
        return "filesystem"
    if "shell" in combined or "command" in combined or "exec" in combined:
        return "shell"
    if "browser" in combined or "profile" in combined or "cookie" in combined:
        return "browser"
    if "secret" in combined or "credential" in combined or "token" in combined or "database" in combined:
        return "credentials"
    if "listen" in combined or "network" in combined or "http" in combined:
        return "network"
    if "docker" in combined or "container" in combined:
        return "container"
    return None


def source_excerpts(diff: dict[str, Any], previous_snapshot: dict[str, Any], current_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    return new_evidence_items(diff, previous_snapshot, current_snapshot, limit=8)


def new_evidence_items(
    diff: dict[str, Any],
    previous_snapshot: dict[str, Any],
    current_snapshot: dict[str, Any],
    *,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    previous_report = previous_snapshot.get("report", {})
    report = current_snapshot.get("report", {})
    categories = positive_delta_keys(diff.get("category_count_delta", {}))
    rule_categories = positive_delta_keys(diff.get("rule_count_delta", {}))
    added_server_names = server_names(diff.get("added_mcp_servers", []))
    previous_finding_signatures = {finding_signature(item) for item in previous_report.get("findings", []) if isinstance(item, dict)}
    previous_rule_signatures = {rule_signature(item) for item in previous_report.get("rules", []) if isinstance(item, dict)}
    excerpts: list[dict[str, Any]] = []

    for finding in report.get("findings", []):
        if not isinstance(finding, dict) or finding.get("category") not in categories:
            continue
        if finding_signature(finding) in previous_finding_signatures:
            continue
        excerpts.append(
            {
                "kind": "finding",
                "category": finding.get("category"),
                "severity": finding.get("severity"),
                "path": finding.get("path"),
                "line": finding.get("line"),
                "evidence": finding.get("evidence"),
                "recommendation": finding.get("recommendation"),
            }
        )
        if limit is not None and len(excerpts) >= limit:
            return excerpts

    for rule in report.get("rules", []):
        if not isinstance(rule, dict) or rule.get("category") not in rule_categories:
            continue
        if rule_signature(rule) in previous_rule_signatures:
            continue
        excerpts.append(
            {
                "kind": "rule",
                "id": rule.get("id"),
                "category": rule.get("category"),
                "severity": rule.get("severity"),
                "path": rule.get("path"),
                "line": rule.get("line"),
                "evidence": rule.get("evidence"),
                "recommendation": rule.get("recommendation"),
            }
        )
        if limit is not None and len(excerpts) >= limit:
            return excerpts

    for server in report.get("mcp_servers", []):
        if not isinstance(server, dict) or server.get("name") not in added_server_names:
            continue
        excerpts.append(
            {
                "kind": "mcp_server",
                "name": server.get("name"),
                "path": server.get("path"),
                "command": server.get("command"),
                "args": server.get("args", []),
                "env_keys": server.get("env_keys", []),
                "risk_hints": server.get("risk_hints", []),
            }
        )
        if limit is not None and len(excerpts) >= limit:
            return excerpts

    previous_structured_signatures = {structured_fingerprint(item) for item in previous_report.get("structured_evidence", []) if isinstance(item, dict)}
    for item in report.get("structured_evidence", []):
        if not isinstance(item, dict):
            continue
        if structured_fingerprint(item) in previous_structured_signatures:
            continue
        excerpts.append(
            {
                "kind": item.get("kind"),
                "path": item.get("path"),
                "line": item.get("line"),
                "source": item.get("source"),
                "target": item.get("target"),
                "name": item.get("name"),
                "client": item.get("client"),
                "command": item.get("command"),
                "args": item.get("args", []),
                "env_keys": item.get("env_keys", []),
                "index": item.get("index"),
                "syntax": item.get("syntax"),
                "evidence": item.get("evidence"),
                "risk_hints": item.get("risk_hints", []),
                "recommendation": item.get("recommendation"),
            }
        )
        if limit is not None and len(excerpts) >= limit:
            return excerpts

    return excerpts


def drift_policy_violations(
    diff: dict[str, Any],
    previous_snapshot: dict[str, Any],
    current_snapshot: dict[str, Any],
    policy: dict[str, Any],
) -> list[dict[str, Any]]:
    if not policy:
        return []
    denied_paths = policy_string_set(policy.get("denied_paths", [])) | policy_string_set(policy.get("blocked_paths", []))
    allowed_paths = policy_string_set(policy.get("allowed_paths", []))
    allowed_browser_profiles = policy_string_set(policy.get("allowed_browser_profiles", []))
    block_severities = policy_string_set(policy.get("block_severities", []))
    review_severities = policy_string_set(policy.get("review_severities", []))
    if not denied_paths and not allowed_paths and not allowed_browser_profiles and not block_severities and not review_severities:
        return []

    violations: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in new_evidence_items(diff, previous_snapshot, current_snapshot):
        text = json.dumps(item, sort_keys=True)
        item_severity = str(item.get("severity", "")).strip().lower()
        if item_severity and item_severity in block_severities:
            key = ("block_severity", item_severity, str(item.get("path", "")))
            if key not in seen:
                violations.append(
                    {
                        "severity": "block",
                        "type": "block_severity",
                        "value": item_severity,
                        "path": item.get("path"),
                        "message": f"Drift introduced {item_severity} severity evidence blocked by team policy.",
                    }
                )
                seen.add(key)
        elif item_severity and item_severity in review_severities:
            key = ("review_severity", item_severity, str(item.get("path", "")))
            if key not in seen:
                violations.append(
                    {
                        "severity": "review",
                        "type": "review_severity",
                        "value": item_severity,
                        "path": item.get("path"),
                        "message": f"Drift introduced {item_severity} severity evidence requiring team review.",
                    }
                )
                seen.add(key)
        for path in sorted(policy_paths_from_evidence(item)):
            denied_match = matching_path_policy(path, denied_paths)
            if denied_match:
                key = ("denied_path", path, denied_match)
                if key not in seen:
                    violations.append(
                        {
                            "severity": "block",
                            "type": "denied_path",
                            "value": path,
                            "matched_policy": denied_match,
                            "message": f"Drift introduced policy-denied path {path}: matched {denied_match}.",
                        }
                    )
                    seen.add(key)
            elif allowed_paths and not matching_path_policy(path, allowed_paths):
                key = ("outside_allowed_paths", path, "")
                if key not in seen:
                    violations.append(
                        {
                            "severity": "block",
                            "type": "outside_allowed_paths",
                            "value": path,
                            "message": f"Drift introduced path outside policy allowed_paths: {path}.",
                        }
                    )
                    seen.add(key)
        for profile in sorted(planned_browser_profiles(text)):
            if allowed_browser_profiles and profile not in allowed_browser_profiles:
                key = ("browser_profile", profile, "")
                if key not in seen:
                    violations.append(
                        {
                            "severity": "block",
                            "type": "browser_profile",
                            "value": profile,
                            "message": f"Drift introduced browser profile outside policy allowlist: {profile}.",
                        }
                    )
                    seen.add(key)
    return violations


def policy_paths_from_evidence(item: dict[str, Any]) -> set[str]:
    kind = str(item.get("kind", ""))
    if kind in {"mcp_server", "mcp_client_server"}:
        return mcp_arg_path_values(item.get("args", []))
    if kind in {"compose_volume", "devcontainer_mount"}:
        source = item.get("source")
        return {str(source)} if isinstance(source, str) and source else set()

    source_path = str(item.get("path", "")).lower()
    evidence = str(item.get("evidence", ""))
    if source_path.endswith((".json", ".jsonc")) and "mcpservers" in evidence.lower():
        return set()
    if source_path.endswith("dockerfile") or "/dockerfile" in source_path:
        return docker_mount_host_paths(evidence)
    if source_path.endswith((".yml", ".yaml")) and ("docker-compose" in source_path or "compose" in source_path):
        return docker_mount_host_paths(evidence) or local_path_values(evidence)
    return local_path_values(evidence)


def mcp_arg_path_values(args: Any) -> set[str]:
    if not isinstance(args, list):
        return set()
    paths: set[str] = set()
    for arg in args:
        if not isinstance(arg, str):
            continue
        if arg.startswith(("/", "~")) or re.match(r"^[A-Za-z]:\\\\", arg):
            paths.add(arg)
    return paths


def finding_signature(finding: dict[str, Any]) -> tuple[str, str, int, str]:
    return (
        str(finding.get("category", "")),
        str(finding.get("path", "")),
        int(finding.get("line", 0) or 0),
        str(finding.get("evidence", "")),
    )


def rule_signature(rule: dict[str, Any]) -> tuple[str, str, str, int, str]:
    return (
        str(rule.get("id", "")),
        str(rule.get("category", "")),
        str(rule.get("path", "")),
        int(rule.get("line", 0) or 0),
        str(rule.get("evidence", "")),
    )


def positive_delta_keys(delta: dict[str, Any]) -> set[str]:
    return {str(key) for key, value in delta.items() if isinstance(value, int) and value > 0}


def proposed_next_step(action: str) -> str:
    if action == "BLOCK":
        return "Remove the new high-impact capability or narrow the config, then rerun drift check before use."
    if action == "SANDBOX_FIRST":
        return "Run only in an isolated workflow with explicit approvals and project-scoped access."
    return "Review the drift packet with a cheap workflow agent or human reviewer before updating the baseline."


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_sha256_file(path: Path, source: Path) -> str:
    digest = sha256_file(source)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{digest}  {source.name}\n", encoding="utf-8")
    return digest


def expected_sha256_from_file(path: Path) -> str:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        raise ValueError(f"checksum file is empty: {path}")
    return text.split()[0]


def verify_state_sha256(state: Path, expected: str) -> tuple[bool, str]:
    actual = sha256_file(state)
    return actual.lower() == expected.lower(), actual


def canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def signing_key_from_env(env_name: str) -> bytes:
    value = os.environ.get(env_name)
    if not value:
        raise ValueError(f"signing key env var is not set: {env_name}")
    return value.encode("utf-8")


def sign_payload(payload: dict[str, Any], key: bytes) -> str:
    return hmac.new(key, canonical_json(payload), hashlib.sha256).hexdigest()


def git_commit_for(path: Path) -> str | None:
    env_sha = os.environ.get("GITHUB_SHA")
    if env_sha:
        return env_sha
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            text=True,
            capture_output=True,
            check=False,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


def baseline_manifest_payload(
    state: Path,
    snapshot: dict[str, Any],
    *,
    identity: str,
    key_id: str,
    target: Path,
) -> dict[str, Any]:
    summary = snapshot.get("summary", {})
    return {
        "schema_version": 1,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "generator": "agent-surface-map drift_watch.py",
        "target": snapshot.get("target"),
        "state_file": state.name,
        "state_sha256": sha256_file(state),
        "signing_identity": identity,
        "key_id": key_id,
        "git_commit": git_commit_for(target),
        "summary": {
            "verdict": summary.get("verdict"),
            "risk_score": summary.get("risk_score"),
            "capabilities": summary.get("capabilities", []),
            "mcp_servers": summary.get("mcp_servers", []),
        },
    }


def write_signed_baseline_manifest(
    path: Path,
    state: Path,
    snapshot: dict[str, Any],
    *,
    identity: str,
    key_env: str,
    target: Path,
) -> dict[str, Any]:
    key = signing_key_from_env(key_env)
    payload = baseline_manifest_payload(state, snapshot, identity=identity, key_id=key_env, target=target)
    manifest = {
        "payload": payload,
        "signature": {
            "algorithm": "hmac-sha256",
            "key_id": key_env,
            "value": sign_payload(payload, key),
        },
    }
    write_json(path, manifest)
    return manifest


def verify_signed_baseline_manifest(
    path: Path,
    state: Path,
    *,
    key_env: str,
    required_identity: str | None = None,
) -> dict[str, Any]:
    manifest = load_json(path)
    payload = manifest.get("payload")
    signature = manifest.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, dict):
        raise ValueError("baseline provenance manifest must contain payload and signature objects")
    if signature.get("algorithm") != "hmac-sha256":
        raise ValueError("unsupported baseline provenance signature algorithm")
    key = signing_key_from_env(key_env)
    expected_signature = sign_payload(payload, key)
    actual_signature = str(signature.get("value", ""))
    if not hmac.compare_digest(expected_signature, actual_signature):
        raise ValueError("baseline provenance signature mismatch")
    expected_sha = str(payload.get("state_sha256", ""))
    if not expected_sha:
        raise ValueError("baseline provenance manifest is missing state_sha256")
    verified, actual_sha = verify_state_sha256(state, expected_sha)
    if not verified:
        raise ValueError(f"baseline provenance digest mismatch: expected {expected_sha.lower()} actual {actual_sha}")
    if required_identity and payload.get("signing_identity") != required_identity:
        raise ValueError(
            f"baseline provenance identity mismatch: expected {required_identity} actual {payload.get('signing_identity')}"
        )
    return manifest


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def packet_markdown(packet: dict[str, Any], result: dict[str, Any] | None = None) -> str:
    result = result or {}
    prior = packet.get("prior_state", {})
    current = packet.get("current_state", {})
    evidence = packet.get("evidence", {})
    lines = [
        f"# Agent Surface Drift: {packet.get('policy_action', 'UNKNOWN')}",
        "",
        f"- Target: `{packet.get('target', '')}`",
        f"- Exact question: {packet.get('exact_question', '')}",
        f"- Proposed next step: {packet.get('proposed_next_step', '')}",
        "",
        "## State Change",
        "",
        f"- Prior: `{prior.get('verdict')}` risk `{prior.get('risk_score')}` capabilities `{', '.join(prior.get('capabilities', []))}`",
        f"- Current: `{current.get('verdict')}` risk `{current.get('risk_score')}` capabilities `{', '.join(current.get('capabilities', []))}`",
        f"- Risk delta: `{evidence.get('risk_score_delta')}`",
        "",
        "## Reasons",
        "",
    ]
    for reason in packet.get("reasons", []):
        lines.append(f"- {reason}")
    policy_violations = evidence.get("policy_violations", [])
    if policy_violations:
        lines.extend(["", "## Policy Violations", ""])
        for item in policy_violations:
            lines.append(f"- `{item.get('type')}` `{item.get('value')}`: {item.get('message')}")
    capability_groups = evidence.get("capability_review", [])
    if capability_groups:
        lines.extend(["", "## Capability Review", ""])
        for group in capability_groups:
            lines.append(f"- `{group.get('capability')}`: {group.get('why_it_matters')}")
            prompt = group.get("remediation_prompt", {})
            if prompt:
                lines.append(f"  - Remediation objective: {prompt.get('objective')}")
            for item in group.get("evidence", [])[:3]:
                location = item.get("path") or ""
                if item.get("line"):
                    location += f":{item.get('line')}"
                detail = item.get("evidence") or item.get("name") or item.get("source") or item.get("command") or ""
                lines.append(f"  - `{location}`: {detail}")
    added_servers = evidence.get("added_mcp_servers", [])
    if added_servers:
        lines.extend(["", "## Added MCP Servers", ""])
        for raw in added_servers[:8]:
            lines.append(f"- `{raw}`")
    added_structured = evidence.get("added_structured_evidence", [])
    if added_structured:
        lines.extend(["", "## Added Structured Evidence", ""])
        for raw in added_structured[:8]:
            lines.append(f"- `{raw}`")
    telemetry = evidence.get("runtime_telemetry") or result.get("runtime_telemetry")
    if isinstance(telemetry, dict) and telemetry.get("detections"):
        lines.extend(["", "## Runtime Telemetry", ""])
        lines.append(f"- Runtime action: `{telemetry.get('action')}`")
        lines.append(f"- Events reviewed: `{telemetry.get('event_count')}`")
        for item in telemetry.get("detections", [])[:8]:
            correlation = item.get("correlation", {}) if isinstance(item.get("correlation"), dict) else {}
            suffix = ""
            if correlation:
                suffix = f" Correlation: `{correlation.get('relation')}`"
                if correlation.get("likely_capability"):
                    suffix += f" `{correlation.get('likely_capability')}`"
                if correlation.get("matched_mcp_server"):
                    suffix += f" server `{correlation.get('matched_mcp_server')}`"
            lines.append(f"- `{item.get('severity')}` `{item.get('type')}`: {item.get('message')}{suffix}")
    excerpts = evidence.get("source_excerpts", [])
    if excerpts:
        lines.extend(["", "## Source Evidence", ""])
        for item in excerpts[:10]:
            location = item.get("path") or ""
            if item.get("line"):
                location += f":{item.get('line')}"
            label = item.get("kind", "evidence")
            detail = item.get("evidence") or item.get("name") or item.get("source") or item.get("command") or ""
            lines.append(f"- `{label}` `{location}`: {detail}")
    if result.get("generated_at"):
        lines.extend(["", f"_Generated at {result['generated_at']}._"])
    return "\n".join(lines).rstrip() + "\n"


def append_github_step_summary(markdown: str, summary_path: Path | None = None) -> bool:
    path = summary_path or github_step_summary_path()
    if path is None:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(markdown.rstrip() + "\n\n")
    return True


def github_step_summary_path() -> Path | None:
    raw = os.environ.get("GITHUB_STEP_SUMMARY")
    return Path(raw) if raw else None


def github_annotation(result: dict[str, Any]) -> str:
    action = str(result.get("action", "UNKNOWN"))
    level = "error" if action == "BLOCK" else "warning"
    reasons = result.get("reasons", [])
    message = "; ".join(str(reason) for reason in reasons[:3]) or f"Agent Surface Map action {action}"
    return f"::{level} title=Agent Surface Map {action}::{escape_github_command(message)}"


def escape_github_command(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A").replace(":", "%3A").replace(",", "%2C")


def baseline(args: argparse.Namespace) -> int:
    target = args.target.resolve()
    if not target.is_dir():
        print(f"target is not a directory: {target}", file=sys.stderr)
        return 2
    if args.provenance:
        if not args.signing_key_env:
            print("--signing-key-env is required with --provenance", file=sys.stderr)
            return 2
        try:
            signing_key_from_env(args.signing_key_env)
        except ValueError as exc:
            print(f"invalid baseline provenance: {exc}", file=sys.stderr)
            return 2
    snapshot = build_snapshot(target, allow_gemma=args.gemma)
    write_json(args.state, snapshot)
    if args.checksum:
        digest = write_sha256_file(args.checksum, args.state)
    else:
        digest = ""
    provenance = None
    if args.provenance:
        try:
            provenance = write_signed_baseline_manifest(
                args.provenance,
                args.state,
                snapshot,
                identity=args.signing_identity,
                key_env=args.signing_key_env,
                target=target,
            )
        except ValueError as exc:
            print(f"invalid baseline provenance: {exc}", file=sys.stderr)
            return 2
    if args.out:
        payload = {"action": "ALLOW", "reasons": ["Baseline saved."], "current_summary": snapshot["summary"]}
        if digest:
            payload["baseline_checksum"] = {"algorithm": "sha256", "value": digest}
        if provenance:
            payload["baseline_provenance"] = {
                "path": str(args.provenance),
                "signing_identity": provenance["payload"].get("signing_identity"),
                "state_sha256": provenance["payload"].get("state_sha256"),
                "signature_algorithm": provenance["signature"].get("algorithm"),
            }
        write_json(args.out, payload)
    print(f"baseline saved: {args.state}")
    if digest:
        print(f"baseline_sha256={digest}")
    if provenance:
        print(f"baseline_provenance={args.provenance}")
        print(f"baseline_signing_identity={provenance['payload'].get('signing_identity')}")
    print(f"verdict={snapshot['summary']['verdict']} risk_score={snapshot['summary']['risk_score']}")
    return 0


def check(args: argparse.Namespace) -> int:
    target = args.target.resolve()
    if not target.is_dir():
        print(f"target is not a directory: {target}", file=sys.stderr)
        return 2
    if not args.state.exists():
        print(f"state file does not exist: {args.state}", file=sys.stderr)
        return 2
    provenance = None
    if args.provenance:
        if not args.signing_key_env:
            print("--signing-key-env is required with --provenance", file=sys.stderr)
            return 2
        try:
            provenance = verify_signed_baseline_manifest(
                args.provenance,
                args.state,
                key_env=args.signing_key_env,
                required_identity=args.require_signing_identity,
            )
        except (OSError, ValueError) as exc:
            print(f"invalid baseline provenance: {exc}", file=sys.stderr)
            return 2
    expected_sha256 = args.state_sha256
    if args.state_sha256_file:
        try:
            expected_sha256 = expected_sha256_from_file(args.state_sha256_file)
        except (OSError, ValueError) as exc:
            print(f"invalid state checksum: {exc}", file=sys.stderr)
            return 2
    baseline_sha256 = sha256_file(args.state)
    if expected_sha256:
        verified, actual_sha256 = verify_state_sha256(args.state, expected_sha256)
        baseline_sha256 = actual_sha256
        if not verified:
            print(
                f"state checksum mismatch: expected {expected_sha256.lower()} actual {actual_sha256}",
                file=sys.stderr,
            )
            return 2
    try:
        policy = load_policy(args.policy)
    except (OSError, ValueError) as exc:
        print(f"invalid policy: {exc}", file=sys.stderr)
        return 2
    previous = load_json(args.state)
    current = build_snapshot(target, allow_gemma=args.gemma)
    result = compare_snapshots(previous, current, policy)
    result["baseline_checksum"] = {
        "algorithm": "sha256",
        "value": baseline_sha256,
        "verified": bool(expected_sha256 or provenance),
    }
    if provenance:
        result["baseline_provenance"] = {
            "verified": True,
            "path": str(args.provenance),
            "signing_identity": provenance["payload"].get("signing_identity"),
            "key_id": provenance["payload"].get("key_id"),
            "state_sha256": provenance["payload"].get("state_sha256"),
            "git_commit": provenance["payload"].get("git_commit"),
            "created_at": provenance["payload"].get("created_at"),
            "signature_algorithm": provenance["signature"].get("algorithm"),
        }
    if policy:
        result["policy"] = policy
    runtime_events_available = bool(args.runtime_events)
    if args.runtime_events and args.runtime_events_if_exists and not args.runtime_events.exists():
        runtime_events_available = False
    if runtime_events_available:
        try:
            runtime_result = analyze_events(load_events(args.runtime_events), policy)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"invalid runtime telemetry: {exc}", file=sys.stderr)
            return 2
        attach_runtime_telemetry(result, runtime_result)
    if args.update_state:
        write_json(args.state, current)
    if args.artifact_dir:
        args.artifact_dir.mkdir(parents=True, exist_ok=True)
        if not args.out:
            args.out = args.artifact_dir / "drift-result.json"
        if not args.packet:
            args.packet = args.artifact_dir / "candidate-packet.json"
        if not args.markdown:
            args.markdown = args.artifact_dir / "candidate-packet.md"
        if runtime_events_available and not args.runtime_out:
            args.runtime_out = args.artifact_dir / "runtime-telemetry.json"
        if args.remediation_approve:
            if not args.remediation_out:
                args.remediation_out = args.artifact_dir / "remediation-dry-run.json"
            if not args.remediation_markdown:
                args.remediation_markdown = args.artifact_dir / "remediation-dry-run.md"
    if args.out:
        write_json(args.out, result)
    if args.runtime_out and result.get("runtime_telemetry"):
        write_json(args.runtime_out, result["runtime_telemetry"])
    if args.packet:
        packet = result.get("candidate_packet")
        if packet:
            write_json(args.packet, packet)
        elif args.packet_always:
            write_json(args.packet, {"policy_action": "ALLOW", "reasons": result["reasons"], "target": result.get("target")})
    packet = result.get("candidate_packet")
    if args.remediation_approve:
        if not packet:
            print("remediation approvals were supplied, but no candidate packet was produced", file=sys.stderr)
            return 2
        if args.remediation_config and not args.remediation_config_type:
            print("--remediation-config-type is required with --remediation-config", file=sys.stderr)
            return 2
        try:
            remediation_config = load_remediation_config(args.remediation_config, args.remediation_config_type) if args.remediation_config else None
            remediation = render_patch_intents(
                packet,
                args.remediation_approve,
                config=remediation_config,
                config_type=args.remediation_config_type,
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"invalid remediation config: {exc}", file=sys.stderr)
            return 2
        adapter = remediation.get("config_adapter")
        result["remediation_dry_run"] = {
            "operation_count": len(remediation.get("operations", [])),
            "approved_prompt_ids": remediation.get("approved_prompt_ids", []),
            "dry_run_only": True,
        }
        if isinstance(adapter, dict):
            result["remediation_dry_run"]["config_adapter"] = {
                "config_type": adapter.get("config_type"),
                "operation_count": len(adapter.get("operations", [])),
            }
        if args.out:
            write_json(args.out, result)
        if args.remediation_out:
            write_json(args.remediation_out, remediation)
        if args.remediation_markdown:
            write_text(args.remediation_markdown, remediation["markdown"])
    if args.markdown:
        if packet:
            markdown = packet_markdown(packet, result)
            write_text(args.markdown, markdown)
        elif args.packet_always:
            markdown = "# Agent Surface Drift: ALLOW\n\n- No material agent-surface drift detected.\n"
            write_text(args.markdown, markdown)
        else:
            markdown = ""
    else:
        packet = result.get("candidate_packet")
        markdown = packet_markdown(packet, result) if packet else ""
    if args.github_step_summary and markdown:
        append_github_step_summary(markdown)
    if args.github_annotation and result["action"] != "ALLOW":
        print(github_annotation(result))
    print(f"action={result['action']} risk_delta={result['diff']['risk_score_delta']}")
    for reason in result["reasons"]:
        print(f"- {reason}")
    fail_actions = set(args.fail_on or [])
    if args.fail_on_block:
        fail_actions.add("BLOCK")
    return 1 if result["action"] in fail_actions else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Watch agent-surface drift between scans.")
    sub = parser.add_subparsers(dest="command", required=True)

    baseline_parser = sub.add_parser("baseline", help="Save a baseline scan.")
    baseline_parser.add_argument("target", type=Path)
    baseline_parser.add_argument("--state", type=Path, required=True)
    baseline_parser.add_argument("--out", type=Path)
    baseline_parser.add_argument("--checksum", type=Path, help="Write a sha256 checksum file for the saved baseline.")
    baseline_parser.add_argument("--provenance", type=Path, help="Write a signed baseline provenance manifest.")
    baseline_parser.add_argument("--signing-key-env", help="Environment variable containing the HMAC signing key for --provenance.")
    baseline_parser.add_argument("--signing-identity", default="unknown", help="Identity to record in the signed provenance manifest.")
    baseline_parser.add_argument("--gemma", action="store_true", help="Use Gemma review if configured.")
    baseline_parser.set_defaults(func=baseline)

    check_parser = sub.add_parser("check", help="Compare current scan with a baseline.")
    check_parser.add_argument("target", type=Path)
    check_parser.add_argument("--state", type=Path, required=True)
    check_parser.add_argument("--out", type=Path)
    check_parser.add_argument("--gemma", action="store_true", help="Use Gemma review if configured.")
    check_parser.add_argument("--policy", type=Path, help="Optional JSON or simple YAML policy file.")
    check_parser.add_argument("--state-sha256", help="Expected sha256 hex digest for the baseline state file.")
    check_parser.add_argument("--state-sha256-file", type=Path, help="File containing the expected baseline state sha256 digest.")
    check_parser.add_argument("--provenance", type=Path, help="Verify a signed baseline provenance manifest before scanning.")
    check_parser.add_argument("--signing-key-env", help="Environment variable containing the HMAC signing key for --provenance.")
    check_parser.add_argument("--require-signing-identity", help="Require the provenance manifest to name this signing identity.")
    check_parser.add_argument("--packet", type=Path, help="Write a candidate packet for non-ALLOW drift.")
    check_parser.add_argument("--markdown", type=Path, help="Write a markdown summary for non-ALLOW drift.")
    check_parser.add_argument("--artifact-dir", type=Path, help="Write CI artifacts: drift-result.json, candidate-packet.json, and candidate-packet.md.")
    check_parser.add_argument("--runtime-events", type=Path, help="Optional runtime telemetry JSON to analyze and attach to drift output.")
    check_parser.add_argument("--runtime-events-if-exists", action="store_true", help="Skip --runtime-events when the file does not exist.")
    check_parser.add_argument("--runtime-out", type=Path, help="Write runtime telemetry analysis JSON.")
    check_parser.add_argument("--remediation-approve", action="append", default=[], help="Approved remediation prompt id to render as a dry-run artifact. Repeat for multiple prompts.")
    check_parser.add_argument("--remediation-config", type=Path, help="Optional config file for adapter-specific remediation dry-run operations.")
    check_parser.add_argument("--remediation-config-type", choices=["mcp-json", "devcontainer-json", "compose-yaml"], help="Config adapter type for --remediation-config.")
    check_parser.add_argument("--remediation-out", type=Path, help="Write remediation dry-run JSON.")
    check_parser.add_argument("--remediation-markdown", type=Path, help="Write remediation dry-run markdown.")
    check_parser.add_argument("--github-step-summary", action="store_true", help="Append the markdown packet to $GITHUB_STEP_SUMMARY when available.")
    check_parser.add_argument("--github-annotation", action="store_true", help="Print a GitHub Actions warning/error annotation for non-ALLOW drift.")
    check_parser.add_argument("--packet-always", action="store_true", help="Write --packet even when action is ALLOW.")
    check_parser.add_argument("--update-state", action="store_true", help="Replace baseline with current scan after checking.")
    check_parser.add_argument(
        "--fail-on",
        action="append",
        choices=["REVIEW", "SANDBOX_FIRST", "BLOCK"],
        help="Exit non-zero when the resulting policy action matches. Repeat for multiple actions.",
    )
    check_parser.add_argument("--fail-on-block", action="store_true", help="Exit non-zero when action is BLOCK.")
    check_parser.set_defaults(func=check)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

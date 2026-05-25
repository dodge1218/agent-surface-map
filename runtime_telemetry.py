#!/usr/bin/env python3
"""Normalize and review runtime tool-call telemetry.

This is a v2 primitive, not a full EDR. It accepts already-captured events,
redacts sensitive args, and emits deterministic detections that can be attached
to drift packets or CI artifacts later.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from policy import load_policy
from surface_map import matching_path_policy, policy_string_set, safe_excerpt


SHELL_WORDS = {"bash", "sh", "zsh", "powershell", "cmd", "exec", "subprocess", "terminal", "run_command"}
WRITE_WORDS = {"write", "edit", "patch", "apply_patch", "delete", "move", "rename"}


def normalize_event(raw: dict[str, Any]) -> dict[str, Any]:
    args = raw.get("args", {})
    return {
        "schema_version": 1,
        "timestamp": raw.get("timestamp") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "session_id": str(raw.get("session_id", "")),
        "tool_name": str(raw.get("tool_name", "")),
        "args": redact_value(args),
        "working_directory": str(raw.get("working_directory", raw.get("cwd", ""))),
        "network_destinations": sorted(str(item) for item in raw.get("network_destinations", []) if item),
        "files_touched": sorted(str(item) for item in raw.get("files_touched", []) if item),
        "approval_status": str(raw.get("approval_status", "unknown")),
        "metadata": redact_value(raw.get("metadata", {})),
    }


def redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): redact_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        return safe_excerpt(value)
    return value


def analyze_events(events: list[dict[str, Any]], policy: dict[str, Any] | None = None) -> dict[str, Any]:
    policy = policy or {}
    normalized = [normalize_event(event) for event in events if isinstance(event, dict)]
    detections: list[dict[str, Any]] = []
    denied_paths = policy_string_set(policy.get("denied_paths", [])) | policy_string_set(policy.get("blocked_paths", []))
    allowed_paths = policy_string_set(policy.get("allowed_paths", []))
    allowed_destinations = policy_string_set(policy.get("allowed_network_destinations", []))

    previous_write: dict[str, Any] | None = None
    for index, event in enumerate(normalized):
        tool_text = f"{event.get('tool_name', '')} {json.dumps(event.get('args', {}), sort_keys=True)}".lower()
        approval = str(event.get("approval_status", "unknown")).lower()

        if any(word in tool_text for word in SHELL_WORDS) and approval not in {"approved", "preapproved"}:
            detections.append(detection(index, event, "shell_without_approval", "block", "Shell-like tool call ran without approval."))

        for path in event.get("files_touched", []):
            denied_match = matching_path_policy(path, denied_paths)
            if denied_match:
                detections.append(
                    detection(index, event, "denied_path_touched", "block", f"Tool touched policy-denied path {path}: matched {denied_match}.", value=path)
                )
            elif allowed_paths and not matching_path_policy(path, allowed_paths):
                detections.append(
                    detection(index, event, "outside_allowed_paths", "block", f"Tool touched path outside policy allowed_paths: {path}.", value=path)
                )

        for destination in event.get("network_destinations", []):
            if allowed_destinations and destination not in allowed_destinations:
                detections.append(
                    detection(index, event, "network_destination_outside_allowlist", "review", f"Tool contacted destination outside allowlist: {destination}.", value=destination)
                )

        if "/var/run/docker.sock" in tool_text:
            detections.append(detection(index, event, "docker_socket_runtime_surface", "block", "Tool call referenced Docker socket at runtime."))

        if any(word in tool_text for word in WRITE_WORDS):
            previous_write = event
        elif previous_write and any(word in tool_text for word in SHELL_WORDS):
            detections.append(
                detection(index, event, "write_then_shell_sequence", "review", "A write-like tool call was followed by shell execution in the same session.")
            )
            previous_write = None

    action = "ALLOW"
    if any(item["severity"] == "block" for item in detections):
        action = "BLOCK"
    elif detections:
        action = "REVIEW"
    return {
        "schema_version": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "action": action,
        "event_count": len(normalized),
        "detections": detections,
        "events": normalized,
    }


def detection(index: int, event: dict[str, Any], kind: str, severity: str, message: str, *, value: str | None = None) -> dict[str, Any]:
    metadata = event.get("metadata", {}) if isinstance(event.get("metadata"), dict) else {}
    return {
        "event_index": index,
        "type": kind,
        "severity": severity,
        "message": message,
        "value": value,
        "tool_name": event.get("tool_name"),
        "session_id": event.get("session_id"),
        "mcp_server": metadata.get("mcp_server") or metadata.get("server_name"),
    }


def load_events(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict) and isinstance(data.get("events"), list):
        return [item for item in data["events"] if isinstance(item, dict)]
    raise ValueError("telemetry input must be a JSON array or an object with an events array")


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize and review runtime agent/tool telemetry.")
    parser.add_argument("events", type=Path, help="JSON array or object with an events array.")
    parser.add_argument("--policy", type=Path, help="Optional JSON or simple YAML policy file.")
    parser.add_argument("--out", type=Path, help="Write analysis JSON.")
    parser.add_argument("--fail-on", choices=["REVIEW", "BLOCK"], action="append", help="Exit non-zero for matching action.")
    args = parser.parse_args()

    try:
        policy = load_policy(args.policy)
        result = analyze_events(load_events(args.events), policy)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"invalid telemetry input: {exc}", file=sys.stderr)
        return 2
    if args.out:
        write_json(args.out, result)
    print(f"action={result['action']} events={result['event_count']} detections={len(result['detections'])}")
    for item in result["detections"]:
        print(f"- {item['severity']} {item['type']}: {item['message']}")
    return 1 if result["action"] in set(args.fail_on or []) else 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Dry-run renderer for approved remediation patch intents.

This module intentionally does not write target config. It turns selected
packet `remediation_prompt.patch_intents` into reviewable JSON Patch-style
operations and markdown notes for a human approval step.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any


def collect_remediation_prompts(packet: dict[str, Any]) -> list[dict[str, Any]]:
    prompts: list[dict[str, Any]] = []
    evidence = packet.get("evidence", {}) if isinstance(packet.get("evidence"), dict) else {}
    for group in evidence.get("capability_review", []):
        if not isinstance(group, dict):
            continue
        prompt = group.get("remediation_prompt")
        if isinstance(prompt, dict):
            prompts.append(prompt)
    return prompts


def render_patch_intents(
    packet: dict[str, Any],
    approved_prompt_ids: list[str] | None = None,
    *,
    config: dict[str, Any] | None = None,
    config_type: str | None = None,
) -> dict[str, Any]:
    approved = set(approved_prompt_ids or [])
    prompts = collect_remediation_prompts(packet)
    selected = [prompt for prompt in prompts if not approved or prompt.get("prompt_id") in approved]
    operations: list[dict[str, Any]] = []
    for prompt in selected:
        for intent in prompt.get("patch_intents", []):
            if not isinstance(intent, dict):
                continue
            operations.append(render_intent(prompt, intent))
    adapter = render_config_adapter(packet, selected, config, config_type)
    return {
        "schema_version": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target": packet.get("target"),
        "source_policy_action": packet.get("policy_action"),
        "approved_prompt_ids": sorted(approved),
        "selected_prompt_ids": [str(prompt.get("prompt_id", "")) for prompt in selected],
        "human_approval_required": True,
        "dry_run_only": True,
        "operations": operations,
        "config_adapter": adapter,
        "markdown": render_markdown(packet, selected, operations),
    }


def render_config_adapter(
    packet: dict[str, Any],
    prompts: list[dict[str, Any]],
    config: dict[str, Any] | None,
    config_type: str | None,
) -> dict[str, Any] | None:
    if config is None or config_type is None:
        return None
    if config_type == "mcp-json":
        return render_mcp_json_adapter(packet, prompts, config)
    if config_type == "devcontainer-json":
        return render_devcontainer_json_adapter(packet, prompts, config)
    if config_type == "compose-yaml":
        return render_compose_yaml_adapter(packet, prompts, config)
    raise ValueError(f"unsupported config type: {config_type}")


def render_mcp_json_adapter(packet: dict[str, Any], prompts: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    raw_servers = config.get("mcpServers", {})
    servers = raw_servers if isinstance(raw_servers, dict) else {}
    packet_servers = mcp_server_names_from_packet(packet)
    target_servers = [name for name in sorted(packet_servers) if name in servers]
    if not target_servers and len(servers) == 1:
        target_servers = [next(iter(servers))]

    operations: list[dict[str, Any]] = []
    for prompt in prompts:
        capability = str(prompt.get("capability", ""))
        for intent in prompt.get("patch_intents", []):
            if not isinstance(intent, dict):
                continue
            operations.extend(render_mcp_intent(prompt, intent, capability, target_servers))
    return {
        "config_type": "mcp-json",
        "target_servers": target_servers,
        "dry_run_only": True,
        "operations": operations,
        "notes": [
            "Adapter operations use an x-agent-surface namespace for policy metadata.",
            "Review client support before applying advisory x-agent-surface fields.",
        ],
    }


def render_mcp_intent(
    prompt: dict[str, Any],
    intent: dict[str, Any],
    capability: str,
    target_servers: list[str],
) -> list[dict[str, Any]]:
    operation = str(intent.get("operation", ""))
    value = intent.get("value")
    operations: list[dict[str, Any]] = []
    if operation == "add_required_approval":
        operations.append(adapter_operation(prompt, intent, "add", "/x-agent-surface/required_approvals/-", value))
        for server in target_servers:
            operations.append(
                adapter_operation(prompt, intent, "add", f"/mcpServers/{json_pointer_part(server)}/x-agent-surface/required_approvals/-", value)
            )
    elif operation == "narrow_working_directory":
        for server in target_servers:
            operations.append(
                adapter_operation(prompt, intent, "replace", f"/mcpServers/{json_pointer_part(server)}/x-agent-surface/working_directory", value)
            )
    elif operation == "add_command_allowlist":
        for server in target_servers:
            operations.append(
                adapter_operation(prompt, intent, "add", f"/mcpServers/{json_pointer_part(server)}/x-agent-surface/allowed_commands", value)
            )
    elif operation in {"set_clean_profile", "remove_personal_profile_mount", "remove_cookie_reuse"}:
        for server in target_servers:
            operations.append(adapter_operation(prompt, intent, "replace", f"/mcpServers/{json_pointer_part(server)}/x-agent-surface/browser_profile", "clean-agent-profile"))
    elif operation in {"replace_broad_mount", "set_read_only", "add_write_allowlist"}:
        for server in target_servers:
            operations.append(adapter_operation(prompt, intent, "replace", f"/mcpServers/{json_pointer_part(server)}/x-agent-surface/filesystem_scope", "project_read_only"))
    elif operation in {"replace_secret_value_with_reference", "require_least_privilege_secret", "remove_production_credential_defaults"}:
        for server in target_servers:
            operations.append(adapter_operation(prompt, intent, "add", f"/mcpServers/{json_pointer_part(server)}/x-agent-surface/secret_policy", "names_only"))
    elif capability:
        operations.append(adapter_operation(prompt, intent, "add", f"/x-agent-surface/capabilities/{json_pointer_part(capability)}", value))
    return operations


def render_devcontainer_json_adapter(packet: dict[str, Any], prompts: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    mount_indices = risky_devcontainer_mount_indices(config)
    lifecycle_keys = [key for key in ("initializeCommand", "onCreateCommand", "postCreateCommand", "postStartCommand", "postAttachCommand") if key in config]
    operations: list[dict[str, Any]] = []
    for prompt in prompts:
        capability = str(prompt.get("capability", ""))
        for intent in prompt.get("patch_intents", []):
            if not isinstance(intent, dict):
                continue
            operations.extend(render_devcontainer_intent(prompt, intent, capability, mount_indices, lifecycle_keys))
    return {
        "config_type": "devcontainer-json",
        "target_mount_indices": mount_indices,
        "target_lifecycle_keys": lifecycle_keys,
        "dry_run_only": True,
        "operations": operations,
        "notes": [
            "Adapter operations use customizations.agent-surface for advisory policy metadata.",
            "Review devcontainer support and repository policy before applying advisory fields.",
        ],
    }


def render_devcontainer_intent(
    prompt: dict[str, Any],
    intent: dict[str, Any],
    capability: str,
    mount_indices: list[int],
    lifecycle_keys: list[str],
) -> list[dict[str, Any]]:
    operation = str(intent.get("operation", ""))
    value = intent.get("value")
    operations: list[dict[str, Any]] = []
    if operation == "add_required_approval":
        operations.append(adapter_operation(prompt, intent, "add", "/customizations/agent-surface/required_approvals/-", value, "devcontainer-json"))
    elif operation == "narrow_working_directory":
        operations.append(adapter_operation(prompt, intent, "replace", "/workspaceFolder", "${localWorkspaceFolder}", "devcontainer-json"))
    elif operation in {"replace_broad_mount", "set_read_only", "add_write_allowlist"}:
        for index in mount_indices:
            operations.append(adapter_operation(prompt, intent, "replace", f"/mounts/{index}", "source=${localWorkspaceFolder},target=/workspace,type=bind,readonly", "devcontainer-json"))
        operations.append(adapter_operation(prompt, intent, "add", "/customizations/agent-surface/filesystem_scope", "project_read_only", "devcontainer-json"))
    elif operation in {"remove_docker_socket_mount", "drop_privileged_container", "sandbox_first"}:
        for index in mount_indices:
            operations.append(adapter_operation(prompt, intent, "remove", f"/mounts/{index}", None, "devcontainer-json"))
        operations.append(adapter_operation(prompt, intent, "replace", "/privileged", False, "devcontainer-json"))
        operations.append(adapter_operation(prompt, intent, "add", "/customizations/agent-surface/install_posture", "sandbox_first", "devcontainer-json"))
    elif operation in {"require_install_script_review", "document_install_script", "disable_lifecycle_scripts_for_review"}:
        for key in lifecycle_keys:
            operations.append(adapter_operation(prompt, intent, "add", f"/customizations/agent-surface/lifecycle_review/{json_pointer_part(key)}", "required", "devcontainer-json"))
    elif capability:
        operations.append(adapter_operation(prompt, intent, "add", f"/customizations/agent-surface/capabilities/{json_pointer_part(capability)}", value, "devcontainer-json"))
    return operations


def risky_devcontainer_mount_indices(config: dict[str, Any]) -> list[int]:
    mounts = config.get("mounts", [])
    if isinstance(mounts, str):
        mounts = [mounts]
    if not isinstance(mounts, list):
        return []
    risky: list[int] = []
    for index, mount in enumerate(mounts):
        if not isinstance(mount, str):
            continue
        lowered = mount.lower()
        if any(token in lowered for token in ("/home", "/users", "/var/run/docker.sock", "docker.sock", "/etc", "source=~", "source=/")):
            risky.append(index)
    return risky


def render_compose_yaml_adapter(packet: dict[str, Any], prompts: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    raw_text = str(config.get("__raw_text", ""))
    volume_lines = risky_compose_volume_lines(raw_text)
    operations: list[dict[str, Any]] = []
    for prompt in prompts:
        capability = str(prompt.get("capability", ""))
        for intent in prompt.get("patch_intents", []):
            if not isinstance(intent, dict):
                continue
            operations.extend(render_compose_intent(prompt, intent, capability, volume_lines))
    return {
        "config_type": "compose-yaml",
        "target_volume_lines": volume_lines,
        "dry_run_only": True,
        "operations": operations,
        "notes": [
            "Adapter operations are line-aware YAML review hints, not an applied YAML patch.",
            "Review service ownership, indentation, and compose version before applying changes.",
            "Use x-agent-surface extension fields only as advisory metadata.",
        ],
    }


def render_compose_intent(
    prompt: dict[str, Any],
    intent: dict[str, Any],
    capability: str,
    volume_lines: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    operation = str(intent.get("operation", ""))
    value = intent.get("value")
    operations: list[dict[str, Any]] = []
    if operation == "add_required_approval":
        operations.append(adapter_operation(prompt, intent, "add", "/x-agent-surface/required_approvals/-", value, "compose-yaml"))
    elif operation == "narrow_working_directory":
        operations.append(adapter_operation(prompt, intent, "add", "/x-agent-surface/working_directory", "./", "compose-yaml"))
    elif operation in {"replace_broad_mount", "set_read_only", "add_write_allowlist"}:
        targets = [line for line in volume_lines if not line.get("docker_socket")]
        for line in targets:
            operations.append(compose_line_operation(prompt, intent, "replace", line, "./project:/workspace:ro"))
        operations.append(adapter_operation(prompt, intent, "add", "/x-agent-surface/filesystem_scope", "project_read_only", "compose-yaml"))
    elif operation in {"remove_docker_socket_mount", "drop_privileged_container", "sandbox_first"}:
        targets = [line for line in volume_lines if line.get("docker_socket")] or volume_lines
        for line in targets:
            operations.append(compose_line_operation(prompt, intent, "remove", line, None))
        operations.append(adapter_operation(prompt, intent, "replace", "/services/*/privileged", False, "compose-yaml"))
        operations.append(adapter_operation(prompt, intent, "add", "/x-agent-surface/install_posture", "sandbox_first", "compose-yaml"))
    elif operation in {"require_install_script_review", "document_install_script", "disable_lifecycle_scripts_for_review"}:
        operations.append(adapter_operation(prompt, intent, "add", "/x-agent-surface/lifecycle_review", "required", "compose-yaml"))
    elif capability:
        operations.append(adapter_operation(prompt, intent, "add", f"/x-agent-surface/capabilities/{json_pointer_part(capability)}", value, "compose-yaml"))
    return operations


def compose_line_operation(prompt: dict[str, Any], intent: dict[str, Any], op: str, line: dict[str, Any], value: Any) -> dict[str, Any]:
    path = f"/services/*/volumes[line={line.get('line_number')}]"
    operation = adapter_operation(prompt, intent, op, path, value, "compose-yaml")
    operation["target_line"] = line
    operation["review_note"] = f"Config-aware compose-yaml dry-run for `{intent.get('operation')}` at line {line.get('line_number')}."
    return operation


def risky_compose_volume_lines(text: str) -> list[dict[str, Any]]:
    risky: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        parsed = parse_compose_volume_line(line)
        if parsed is None:
            continue
        source = str(parsed.get("source", ""))
        if is_risky_compose_source(source):
            parsed["line_number"] = line_number
            parsed["line"] = line.strip()
            parsed["docker_socket"] = "docker.sock" in source.lower() or "docker.sock" in line.lower()
            risky.append(parsed)
    return risky


def parse_compose_volume_line(line: str) -> dict[str, Any] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    source_match = re.match(r"^source:\s*(.+?)\s*$", stripped)
    if source_match:
        return {"syntax": "long", "source": unquote_yaml_scalar(source_match.group(1))}
    if not stripped.startswith("- "):
        return None
    value = unquote_yaml_scalar(stripped[2:].strip())
    if not value:
        return None
    if value.startswith("type="):
        fields = {}
        for part in value.split(","):
            key, _, raw_value = part.partition("=")
            fields[key.strip()] = raw_value.strip()
        source = fields.get("source") or fields.get("src")
        target = fields.get("target") or fields.get("dst") or fields.get("destination")
        if source:
            return {"syntax": "short-keyvalue", "source": source, "target": target}
    if ":" not in value:
        return None
    source, target = split_compose_short_volume(value)
    return {"syntax": "short", "source": source, "target": target}


def split_compose_short_volume(value: str) -> tuple[str, str | None]:
    if re.match(r"^[A-Za-z]:[\\/]", value):
        parts = value.split(":")
        source = ":".join(parts[:2])
        target = parts[2] if len(parts) > 2 else None
        return source, target
    parts = value.split(":")
    source = parts[0]
    target = parts[1] if len(parts) > 1 else None
    return source, target


def unquote_yaml_scalar(value: str) -> str:
    value = value.strip()
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    return value


def is_risky_compose_source(source: str) -> bool:
    normalized = source.strip().lower()
    if not normalized:
        return False
    return (
        normalized.startswith("/")
        or normalized.startswith("~/")
        or normalized.startswith("$home")
        or normalized.startswith("${home}")
        or normalized.startswith("~")
        or "docker.sock" in normalized
    )


def adapter_operation(prompt: dict[str, Any], intent: dict[str, Any], op: str, path: str, value: Any, adapter: str = "mcp-json") -> dict[str, Any]:
    patch = {"op": op, "path": path}
    if op != "remove":
        patch["value"] = value
    return {
        "prompt_id": prompt.get("prompt_id"),
        "capability": prompt.get("capability"),
        "intent_operation": intent.get("operation"),
        "json_patch": patch,
        "review_note": f"Config-aware {adapter} dry-run for `{intent.get('operation')}`.",
    }


def mcp_server_names_from_packet(packet: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    evidence = packet.get("evidence", {}) if isinstance(packet.get("evidence"), dict) else {}
    for item in evidence.get("source_excerpts", []):
        if isinstance(item, dict) and item.get("kind") in {"mcp_server", "mcp_client_server"} and item.get("name"):
            names.add(str(item["name"]))
    for raw in evidence.get("added_mcp_servers", []):
        if not isinstance(raw, str):
            continue
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if payload.get("name"):
            names.add(str(payload["name"]))
    telemetry = evidence.get("runtime_telemetry", {})
    if isinstance(telemetry, dict):
        for detection in telemetry.get("detections", []):
            if isinstance(detection, dict) and detection.get("mcp_server"):
                names.add(str(detection["mcp_server"]))
            correlation = detection.get("correlation") if isinstance(detection, dict) else None
            if isinstance(correlation, dict) and correlation.get("matched_mcp_server"):
                names.add(str(correlation["matched_mcp_server"]))
    return names


def render_intent(prompt: dict[str, Any], intent: dict[str, Any]) -> dict[str, Any]:
    field = str(intent.get("field", "")).strip()
    operation = str(intent.get("operation", "")).strip()
    value = intent.get("value")
    patch_op = "add"
    if operation.startswith(("remove_", "drop_")) or value is None:
        patch_op = "remove"
    elif operation.startswith(("replace_", "set_", "bind_", "narrow_")):
        patch_op = "replace"
    return {
        "prompt_id": prompt.get("prompt_id"),
        "capability": prompt.get("capability"),
        "intent_operation": operation,
        "json_patch": {
            "op": patch_op,
            "path": json_pointer(field),
            **({} if patch_op == "remove" else {"value": value}),
        },
        "review_note": review_note(prompt, intent),
    }


def json_pointer(field: str) -> str:
    if not field:
        return "/"
    parts = [part.replace("~", "~0").replace("/", "~1") for part in field.split(".") if part]
    return "/" + "/".join(parts)


def json_pointer_part(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def review_note(prompt: dict[str, Any], intent: dict[str, Any]) -> str:
    operation = intent.get("operation", "")
    capability = prompt.get("capability", "")
    field = intent.get("field", "")
    return f"Review `{operation}` for `{capability}` before changing `{field}`."


def render_markdown(packet: dict[str, Any], prompts: list[dict[str, Any]], operations: list[dict[str, Any]]) -> str:
    lines = [
        "# Remediation Dry Run",
        "",
        f"- Target: `{packet.get('target', '')}`",
        f"- Source action: `{packet.get('policy_action', '')}`",
        f"- Human approval required: `true`",
        f"- Operations: `{len(operations)}`",
        "",
    ]
    for prompt in prompts:
        lines.append(f"## {prompt.get('prompt_id')}")
        lines.append("")
        lines.append(f"- Capability: `{prompt.get('capability')}`")
        lines.append(f"- Objective: {prompt.get('objective')}")
        lines.append("")
        for operation in [item for item in operations if item.get("prompt_id") == prompt.get("prompt_id")]:
            patch = operation.get("json_patch", {})
            lines.append(f"- `{patch.get('op')}` `{patch.get('path')}`: {operation.get('review_note')}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def load_packet(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("candidate packet must be a JSON object")
    return data


def load_config(path: Path, config_type: str | None) -> dict[str, Any]:
    if config_type == "compose-yaml":
        return {"__raw_text": path.read_text(encoding="utf-8")}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("config must be a JSON object")
    return data


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Render approved remediation patch intents without applying them.")
    parser.add_argument("packet", type=Path, help="candidate-packet.json")
    parser.add_argument("--approve", action="append", default=[], help="Approved remediation prompt id. Repeat to approve multiple prompts. Omit to render all prompts.")
    parser.add_argument("--config", type=Path, help="Optional config file to render adapter-specific dry-run operations against.")
    parser.add_argument("--config-type", choices=["mcp-json", "devcontainer-json", "compose-yaml"], help="Config adapter type for --config.")
    parser.add_argument("--out", type=Path, help="Write dry-run JSON.")
    parser.add_argument("--markdown", type=Path, help="Write dry-run markdown.")
    args = parser.parse_args()
    try:
        if args.config and not args.config_type:
            raise ValueError("--config-type is required with --config")
        config = load_config(args.config, args.config_type) if args.config else None
        result = render_patch_intents(load_packet(args.packet), args.approve, config=config, config_type=args.config_type)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"invalid remediation packet: {exc}", file=sys.stderr)
        return 2
    if args.out:
        write_json(args.out, result)
    if args.markdown:
        write_text(args.markdown, result["markdown"])
    print(f"operations={len(result['operations'])} dry_run_only={str(result['dry_run_only']).lower()}")
    adapter = result.get("config_adapter")
    if isinstance(adapter, dict):
        print(f"adapter={adapter.get('config_type')} adapter_operations={len(adapter.get('operations', []))}")
    for operation in result["operations"]:
        patch = operation["json_patch"]
        print(f"- {patch['op']} {patch['path']}: {operation['review_note']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

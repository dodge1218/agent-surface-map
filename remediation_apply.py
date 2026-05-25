#!/usr/bin/env python3
"""Apply verified remediation adapter operations to a copied config file.

This tool refuses to run unless the remediation dry-run artifact is bound to a
valid approval manifest. JSON configs use JSON Patch-style adapter operations.
Compose YAML uses PyYAML-backed semantic edits and fails closed if PyYAML is not
available.
"""

from __future__ import annotations

import argparse
import json
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

from remediation_approval import load_json, verify_approval


SUPPORTED_CONFIG_TYPES = {"mcp-json", "devcontainer-json", "compose-yaml"}
JSON_CONFIG_TYPES = {"mcp-json", "devcontainer-json"}


def json_pointer_parts(path: str) -> list[str]:
    if not path.startswith("/"):
        raise ValueError(f"JSON pointer must start with /: {path}")
    if path == "/":
        return []
    return [part.replace("~1", "/").replace("~0", "~") for part in path[1:].split("/")]


def ensure_container(root: dict[str, Any], parts: list[str]) -> Any:
    current: Any = root
    for index, part in enumerate(parts):
        next_part = parts[index + 1] if index + 1 < len(parts) else None
        if isinstance(current, dict):
            if part not in current or current[part] is None:
                current[part] = [] if next_part == "-" or (next_part or "").isdigit() else {}
            current = current[part]
        elif isinstance(current, list):
            if part == "-":
                raise ValueError("cannot traverse through append marker")
            index = int(part)
            current = current[index]
        else:
            raise ValueError(f"cannot traverse through scalar at {part}")
    return current


def apply_json_patch_operation(document: dict[str, Any], patch: dict[str, Any]) -> None:
    op = patch.get("op")
    path = str(patch.get("path", ""))
    parts = json_pointer_parts(path)
    if not parts:
        raise ValueError("refusing to replace document root")
    key = parts[-1]
    if key == "-" and parts[:-1]:
        grandparent = ensure_container(document, parts[:-2])
        parent_key = parts[-2]
        if isinstance(grandparent, dict):
            if parent_key not in grandparent or grandparent[parent_key] is None:
                grandparent[parent_key] = []
            parent = grandparent[parent_key]
        elif isinstance(grandparent, list):
            parent = grandparent[int(parent_key)]
        else:
            raise ValueError(f"cannot apply patch beneath scalar at {path}")
    else:
        parent = ensure_container(document, parts[:-1])
    if isinstance(parent, dict):
        if op in {"add", "replace"}:
            parent[key] = deepcopy(patch.get("value"))
        elif op == "remove":
            parent.pop(key, None)
        else:
            raise ValueError(f"unsupported json patch op: {op}")
    elif isinstance(parent, list):
        if key == "-":
            if op != "add":
                raise ValueError("list append marker only supports add")
            parent.append(deepcopy(patch.get("value")))
            return
        index = int(key)
        if op == "add":
            parent.insert(index, deepcopy(patch.get("value")))
        elif op == "replace":
            parent[index] = deepcopy(patch.get("value"))
        elif op == "remove":
            parent.pop(index)
        else:
            raise ValueError(f"unsupported json patch op: {op}")
    else:
        raise ValueError(f"cannot apply patch beneath scalar at {path}")


def adapter_operations(remediation: dict[str, Any], expected_config_type: str) -> list[dict[str, Any]]:
    adapter = remediation.get("config_adapter")
    if not isinstance(adapter, dict):
        raise ValueError("remediation artifact has no config_adapter")
    config_type = adapter.get("config_type")
    if config_type != expected_config_type:
        raise ValueError(f"config type mismatch: artifact={config_type} requested={expected_config_type}")
    if config_type not in SUPPORTED_CONFIG_TYPES:
        raise ValueError(f"unsupported apply config type: {config_type}")
    operations = adapter.get("operations", [])
    if not isinstance(operations, list):
        raise ValueError("config_adapter.operations must be a list")
    return [operation for operation in operations if isinstance(operation, dict)]


def apply_remediation_config(config: dict[str, Any], remediation: dict[str, Any], config_type: str) -> tuple[dict[str, Any], int]:
    result = deepcopy(config)
    applied = 0
    for operation in adapter_operations(remediation, config_type):
        patch = operation.get("json_patch")
        if not isinstance(patch, dict):
            continue
        apply_json_patch_operation(result, patch)
        applied += 1
    return result, applied


def compose_source_target(value: Any) -> tuple[str, str | None]:
    if isinstance(value, dict):
        source = str(value.get("source") or value.get("src") or "")
        target = value.get("target") or value.get("dst") or value.get("destination")
        return source, str(target) if target is not None else None
    if not isinstance(value, str):
        return "", None
    if value.startswith("type="):
        fields = {}
        for part in value.split(","):
            key, _, raw_value = part.partition("=")
            fields[key.strip()] = raw_value.strip()
        source = fields.get("source") or fields.get("src") or ""
        target = fields.get("target") or fields.get("dst") or fields.get("destination")
        return source, target
    if ":" not in value:
        return "", None
    parts = value.split(":")
    if len(parts) > 2 and len(parts[0]) == 1 and parts[1].startswith(("\\", "/")):
        return ":".join(parts[:2]), parts[2]
    return parts[0], parts[1] if len(parts) > 1 else None


def compose_replacement(value: Any, replacement: str) -> Any:
    source, target = compose_source_target(replacement)
    read_only = replacement.endswith(":ro")
    if isinstance(value, dict):
        return {"type": "bind", "source": source, "target": target, "read_only": read_only}
    return replacement


def apply_compose_volume_operation(document: dict[str, Any], operation: dict[str, Any]) -> bool:
    target_line = operation.get("target_line")
    if not isinstance(target_line, dict):
        return False
    target_source = str(target_line.get("source", ""))
    patch = operation.get("json_patch")
    if not isinstance(patch, dict):
        return False
    services = document.get("services")
    if not isinstance(services, dict):
        return False
    for service in services.values():
        if not isinstance(service, dict):
            continue
        volumes = service.get("volumes")
        if not isinstance(volumes, list):
            continue
        for index, volume in list(enumerate(volumes)):
            source, _ = compose_source_target(volume)
            if source != target_source:
                continue
            if patch.get("op") == "remove":
                volumes.pop(index)
            elif patch.get("op") in {"add", "replace"}:
                volumes[index] = compose_replacement(volume, str(patch.get("value", "")))
            else:
                raise ValueError(f"unsupported compose patch op: {patch.get('op')}")
            return True
    return False


def apply_compose_remediation_config(document: dict[str, Any], remediation: dict[str, Any]) -> tuple[dict[str, Any], int]:
    result = deepcopy(document)
    applied = 0
    for operation in adapter_operations(remediation, "compose-yaml"):
        patch = operation.get("json_patch")
        if not isinstance(patch, dict):
            continue
        path = str(patch.get("path", ""))
        if path.startswith("/services/*/volumes[line="):
            if apply_compose_volume_operation(result, operation):
                applied += 1
            continue
        apply_json_patch_operation(result, patch)
        applied += 1
    return result, applied


def load_config(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("config must be a JSON object")
    return data


def load_compose_config(path: Path) -> dict[str, Any]:
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ValueError("compose-yaml apply requires PyYAML") from exc
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("compose config must be a YAML object")
    return data


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_compose_yaml(path: Path, payload: dict[str, Any]) -> None:
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ValueError("compose-yaml apply requires PyYAML") from exc
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply verified remediation adapter operations to an output config file.")
    parser.add_argument("config", type=Path, help="Input config file.")
    parser.add_argument("--config-type", required=True, choices=sorted(SUPPORTED_CONFIG_TYPES))
    parser.add_argument("--remediation", type=Path, required=True, help="remediation-dry-run.json")
    parser.add_argument("--approval", type=Path, required=True, help="remediation-approval.json")
    parser.add_argument("--require-reviewer", help="Require this exact reviewer identity.")
    parser.add_argument("--out", type=Path, required=True, help="Write the remediated JSON config here.")
    args = parser.parse_args()
    try:
        failures = verify_approval(args.remediation, args.approval, require_reviewer=args.require_reviewer)
        if failures:
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        remediation = load_json(args.remediation)
        if args.config_type in JSON_CONFIG_TYPES:
            config = load_config(args.config)
            result, applied = apply_remediation_config(config, remediation, args.config_type)
            write_json(args.out, result)
        elif args.config_type == "compose-yaml":
            config = load_compose_config(args.config)
            result, applied = apply_compose_remediation_config(config, remediation)
            write_compose_yaml(args.out, result)
        else:
            raise ValueError(f"unsupported apply config type: {args.config_type}")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"invalid apply input: {exc}", file=sys.stderr)
        return 2
    print(f"applied={applied} config_type={args.config_type} out={args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

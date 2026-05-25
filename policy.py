"""Shared policy loading for Agent Surface Map."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_policy(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = parse_simple_yaml(text)
    if not isinstance(data, dict):
        raise ValueError("policy file must contain an object")
    return normalize_policy(data)


def parse_simple_yaml(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    current_key: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if not line.startswith(" ") and ":" in line:
            key, value = line.split(":", 1)
            current_key = key.strip()
            value = value.strip()
            if not value:
                result[current_key] = []
            elif value.lower() in {"true", "false"}:
                result[current_key] = value.lower() == "true"
            elif value.isdigit():
                result[current_key] = int(value)
            else:
                result[current_key] = value.strip("'\"")
            continue
        stripped = line.strip()
        if current_key and stripped.startswith("- "):
            if not isinstance(result.get(current_key), list):
                result[current_key] = []
            result[current_key].append(stripped[2:].strip().strip("'\""))
            continue
        raise ValueError(f"unsupported policy syntax: {raw_line}")
    return result


def normalize_policy(data: dict[str, Any]) -> dict[str, Any]:
    list_fields = {
        "block_capabilities",
        "review_capabilities",
        "allowed_mcp_server_names",
        "denied_mcp_server_names",
        "allowed_paths",
        "denied_paths",
        "blocked_paths",
        "allowed_browser_profiles",
        "required_approvals",
    }
    normalized: dict[str, Any] = {}
    for key, value in data.items():
        if key in list_fields:
            if isinstance(value, str):
                normalized[key] = [value]
            elif isinstance(value, list):
                normalized[key] = [str(item) for item in value]
            else:
                raise ValueError(f"{key} must be a list")
        elif key in {"max_risk_score", "max_risk_delta"}:
            normalized[key] = int(value)
        else:
            normalized[key] = value
    return normalized

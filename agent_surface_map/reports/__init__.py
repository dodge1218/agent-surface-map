"""Report schema helpers."""

from __future__ import annotations

from importlib import resources
from pathlib import Path


SCHEMA_NAMES = {
    "report": "report-v1.schema.json",
    "policy": "policy.schema.json",
    "validation": "validation-result.schema.json",
    "drift": "drift-result.schema.json",
}


def schema_path(name: str) -> Path:
    filename = SCHEMA_NAMES[name]
    packaged = resources.files("agent_surface_map.schemas").joinpath(filename)
    return Path(str(packaged))


__all__ = ["SCHEMA_NAMES", "schema_path"]

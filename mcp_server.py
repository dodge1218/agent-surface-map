#!/usr/bin/env python3
"""MCP stdio server for Agent Surface Map.

This intentionally avoids third-party dependencies so a coding agent can add it
to a local workflow with one Python command.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import os
from pathlib import Path
from urllib.parse import urlparse

from surface_map import review_report, safe_install_context, scan


URL_RE = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?$")
MAX_RESPONSE_BYTES = 180_000
LOCAL_SCAN_ROOTS = [Path(p).expanduser().resolve() for p in os.environ.get("ASM_ALLOWED_ROOTS", "").split(os.pathsep) if p]
DEFAULT_LOCAL_ROOT = Path.cwd().resolve()


TOOLS = [
    {
        "name": "scan_local_tool",
        "description": "Scan a local MCP/tool/agent repository and return install-safety context for the calling agent.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local directory to scan."},
            },
            "required": ["path"],
        },
    },
    {
        "name": "scan_github_tool",
        "description": "Clone a public GitHub repository read-only and return install-safety context before adding it to an agent workflow.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Simple public GitHub repository URL."},
            },
            "required": ["url"],
        },
    },
    {
        "name": "generate_safe_install_context",
        "description": "Convert a previous Agent Surface Map JSON report into concise constraints the coding agent should follow.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "report": {"type": "object", "description": "Report object returned by scan_local_tool or scan_github_tool."},
            },
            "required": ["report"],
        },
    },
]


def respond(message_id, result=None, error=None) -> None:
    payload = {"jsonrpc": "2.0", "id": message_id}
    if error is not None:
        payload["error"] = {"code": -32000, "message": str(error)}
    else:
        payload["result"] = result
    print(json.dumps(payload), flush=True)


def text_result(payload: dict) -> dict:
    payload = trim_report(payload)
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(payload, indent=2),
            }
        ]
    }


def trim_report(report: dict) -> dict:
    report = dict(report)
    if isinstance(report.get("findings"), list):
        report["findings"] = report["findings"][:40]
    encoded = json.dumps(report)
    if len(encoded.encode("utf-8")) <= MAX_RESPONSE_BYTES:
        return report
    report["findings"] = report.get("findings", [])[:15]
    report["truncated"] = True
    return report


def assert_allowed_local_path(root: Path) -> None:
    if root == Path("/"):
        raise ValueError("refusing to scan filesystem root")
    if any(part in {".ssh", ".gnupg", ".aws", ".config", ".npm", ".cache"} for part in root.parts):
        raise ValueError("refusing to scan credential or profile directories")
    allowed_roots = LOCAL_SCAN_ROOTS or [DEFAULT_LOCAL_ROOT]
    if not any(root == allowed or root.is_relative_to(allowed) for allowed in allowed_roots):
        allowed_text = ", ".join(str(path) for path in allowed_roots)
        raise ValueError(f"path is outside ASM_ALLOWED_ROOTS: {allowed_text}")


def scan_local(path: str) -> dict:
    root = Path(path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"path is not a directory: {root}")
    assert_allowed_local_path(root)
    report = scan(root)
    report["target"] = str(root)
    review_report(report)
    report["install_context"] = safe_install_context(report)
    return report


def scan_github(url: str) -> dict:
    clean_url = url.strip().rstrip("/")
    parsed = urlparse(clean_url)
    if parsed.scheme != "https" or parsed.netloc != "github.com" or not URL_RE.match(clean_url):
        raise ValueError("only simple public GitHub repo URLs are accepted")

    with tempfile.TemporaryDirectory(prefix="agent-surface-map-mcp-") as tmp:
        destination = Path(tmp) / "repo"
        subprocess.run(
            [
                "git",
                "-c",
                "protocol.file.allow=never",
                "clone",
                "--depth",
                "1",
                "--no-tags",
                "--recurse-submodules=no",
                clean_url,
                str(destination),
            ],
            env=safe_git_env(),
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=45,
        )
        shutil.rmtree(destination / ".git", ignore_errors=True)
        report = scan(destination)
        report["source_url"] = parsed.geturl().rstrip("/")
        report["target"] = parsed.path.strip("/")
        review_report(report)
        report["install_context"] = safe_install_context(report)
        return report


def safe_git_env() -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": tempfile.gettempdir(),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    env["GIT_CONFIG_COUNT"] = "3"
    env["GIT_CONFIG_KEY_0"] = "protocol.file.allow"
    env["GIT_CONFIG_VALUE_0"] = "never"
    env["GIT_CONFIG_KEY_1"] = "core.hooksPath"
    env["GIT_CONFIG_VALUE_1"] = "/dev/null"
    env["GIT_CONFIG_KEY_2"] = "submodule.recurse"
    env["GIT_CONFIG_VALUE_2"] = "false"
    return env


def call_tool(name: str, arguments: dict) -> dict:
    if name == "scan_local_tool":
        return text_result(scan_local(arguments["path"]))
    if name == "scan_github_tool":
        return text_result(scan_github(arguments["url"]))
    if name == "generate_safe_install_context":
        return text_result(safe_install_context(arguments["report"]))
    raise ValueError(f"unknown tool: {name}")


def handle(message: dict) -> dict | None:
    method = message.get("method")
    if method == "initialize":
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "agent-surface-map", "version": "0.1.0"},
        }
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        params = message.get("params", {})
        return call_tool(params.get("name", ""), params.get("arguments") or {})
    if method == "notifications/initialized":
        return None
    raise ValueError(f"unsupported method: {method}")


def main() -> int:
    sys.stderr.write("agent-surface-map MCP server ready\n")
    sys.stderr.flush()
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
            result = handle(message)
            if "id" in message and result is not None:
                respond(message["id"], result=result)
        except Exception as exc:  # noqa: BLE001 - MCP errors must be returned over stdio.
            respond(message.get("id") if isinstance(locals().get("message"), dict) else None, error=exc)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Exercise the Agent Surface Map MCP server over stdio."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_URL = "https://github.com/dodge1218/agent-surface-demo-mcp"


def main() -> int:
    target_url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "scan_github_tool",
                "arguments": {"url": target_url},
            },
        },
    ]
    process = subprocess.Popen(
        [sys.executable, str(ROOT / "mcp_server.py")],
        cwd=str(ROOT),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout, stderr = process.communicate(
        "".join(json.dumps(message) + "\n" for message in messages),
        timeout=60,
    )
    if process.returncode not in {0, None}:
        raise RuntimeError(stderr.strip() or f"mcp server exited {process.returncode}")

    responses = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    tool_names = [tool["name"] for tool in responses[1]["result"]["tools"]]
    payload = json.loads(responses[2]["result"]["content"][0]["text"])
    context = payload["install_context"]

    proof = {
        "target_url": target_url,
        "tools": tool_names,
        "verdict": context["verdict"],
        "risk_score": context["risk_score"],
        "review_source": payload.get("review_source"),
        "mcp_servers": [server["name"] for server in payload.get("mcp_servers", [])],
        "agent_context": context["agent_context"],
    }
    print(json.dumps(proof, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

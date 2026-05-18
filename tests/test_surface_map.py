import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from surface_map import safe_install_context, scan  # noqa: E402
from mcp_server import assert_allowed_local_path  # noqa: E402


class SurfaceMapTests(unittest.TestCase):
    def test_redacts_env_values_and_flags_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env.example").write_text("SECRET_TOKEN=abc123\n", encoding="utf-8")
            (root / "AGENTS.md").write_text("Use bash only after approval.\n", encoding="utf-8")

            report = scan(root)

        evidence = json.dumps(report["findings"])
        self.assertIn("SECRET_TOKEN=<redacted>", evidence)
        self.assertNotIn("abc123", evidence)
        self.assertIn("shell_access", report["category_counts"])

    def test_install_context_sandbox_first_for_demo_stack(self):
        report = scan(ROOT / "examples/demo-agent-stack")
        context = safe_install_context(report)
        self.assertEqual(context["verdict"], "sandbox_first")
        self.assertIn("risk_signals", context)
        self.assertTrue(any("approval" in item for item in context["agent_context"]))

    def test_refuses_home_profile_paths(self):
        with self.assertRaises(ValueError):
            assert_allowed_local_path(Path.home() / ".ssh")

    def test_public_rules_detect_common_mcp_risks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps(
                    {
                        "scripts": {
                            "postinstall": "node setup.js",
                            "dev": "vite --host 0.0.0.0",
                        }
                    }
                ),
                encoding="utf-8",
            )
            (root / "mcp.json").write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "fs": {
                                "command": "npx",
                                "args": ["@modelcontextprotocol/server-filesystem", "/home/user"],
                                "env": {"AWS_ACCESS_KEY_ID": "value"},
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            report = scan(root)

        self.assertIn("network_exposure", report["rule_counts"])
        self.assertIn("install_script_execution", report["rule_counts"])
        self.assertIn("filesystem_tool_surface", report["rule_counts"])
        self.assertIn("broad_filesystem_access", report["rule_counts"])
        self.assertIn("cloud_credential_surface", report["rule_counts"])
        self.assertGreater(report["risk_score"], 25)

    def test_catalog_profiles_and_database_rule(self):
        report = scan(ROOT / "examples/mcp-catalog/postgres")
        context = safe_install_context(report)

        self.assertEqual(report["profile"]["name"], "Postgres MCP")
        self.assertIn("database_credential_surface", report["rule_counts"])
        self.assertTrue(any("database" in item.lower() for item in context["agent_context"]))


class McpProtocolTests(unittest.TestCase):
    def call_server(self, messages):
        process = subprocess.Popen(
            [sys.executable, str(ROOT / "mcp_server.py")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        request = "".join(json.dumps(message) + "\n" for message in messages)
        stdout, stderr = process.communicate(request, timeout=5)
        responses = [json.loads(line) for line in stdout.splitlines() if line.strip()]
        return responses, stderr

    def test_tools_list(self):
        responses, _ = self.call_server(
            [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            ]
        )
        tool_names = {tool["name"] for tool in responses[1]["result"]["tools"]}
        self.assertIn("scan_local_tool", tool_names)
        self.assertIn("scan_github_tool", tool_names)

    def test_scan_local_tool(self):
        responses, _ = self.call_server(
            [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "scan_local_tool",
                        "arguments": {"path": str(ROOT / "examples/demo-agent-stack")},
                    },
                },
            ]
        )
        text = responses[1]["result"]["content"][0]["text"]
        payload = json.loads(text)
        self.assertEqual(payload["install_context"]["verdict"], "sandbox_first")
        self.assertIn("shell_access", payload["category_counts"])


if __name__ == "__main__":
    unittest.main()

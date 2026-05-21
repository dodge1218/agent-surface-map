import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from surface_map import parse_gemma_content, review_report, safe_excerpt, safe_install_context, scan, validate_install_plan  # noqa: E402
from mcp_server import assert_allowed_local_path  # noqa: E402
from api.scan import URL_RE, safe_extract  # noqa: E402


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

    def test_redacts_url_credentials_in_args(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "mcp.json").write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "db": {
                                "command": "node",
                                "args": ["postgres://user:super-secret@localhost:5432/app"],
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            report = scan(root)

        encoded = json.dumps(report)
        self.assertIn("postgres://user:<redacted>@localhost:5432/app", encoded)
        self.assertNotIn("super-secret", encoded)

    def test_redacts_common_token_formats(self):
        encoded = "\n".join(
            [
                safe_excerpt("Authorization: Bearer abcdefghijklmnopqrstuvwxyz"),
                safe_excerpt("token=ghp_abcdefghijklmnopqrstuvwxyz123456"),
                safe_excerpt("OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz"),
                safe_excerpt("jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature"),
            ]
        )
        self.assertIn("Bearer <redacted>", encoded)
        self.assertIn("token=<redacted>", encoded)
        self.assertIn("<redacted-jwt>", encoded)
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz", encoded)
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz", encoded)

    def test_install_context_sandbox_first_for_demo_stack(self):
        report = scan(ROOT / "examples/demo-agent-stack")
        context = safe_install_context(report)
        self.assertEqual(context["verdict"], "sandbox_first")
        self.assertEqual(context["static_verdict"], "sandbox_first")
        self.assertIn("policy", context)
        self.assertIn("risk_signals", context)
        self.assertTrue(any("approval" in item for item in context["agent_context"]))

    def test_validate_install_plan_blocks_broad_paths_and_secret_values(self):
        report = scan(ROOT / "examples/demo-agent-stack")
        plan = {
            "global_install": True,
            "mcpServers": {
                "browser": {
                    "command": "node",
                    "args": ["server.js", "--user-data-dir", "/home/me/.config/chrome"],
                    "env": {"BROWSER_PROFILE": "default", "GITHUB_TOKEN": "ghp_realvalue1234567890"},
                }
            },
        }

        result = validate_install_plan(report, plan)

        self.assertEqual(result["decision"], "block")
        self.assertTrue(any("global install" in item for item in result["blockers"]))
        self.assertTrue(any("broad local paths" in item for item in result["blockers"]))
        self.assertTrue(any("secret value" in item for item in result["blockers"]))

    def test_validate_install_plan_allows_placeholder_project_scoped_plan(self):
        report = scan(ROOT / "examples/demo-agent-stack")
        plan = {
            "global_install": False,
            "required_approvals": ["shell_command", "write_access"],
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "."],
                    "env": {"BROWSER_PROFILE": "${BROWSER_PROFILE}"},
                }
            },
        }

        result = validate_install_plan(report, plan)

        self.assertNotEqual(result["decision"], "block")

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
        self.assertEqual(report["mcp_servers"][0]["name"], "fs")
        self.assertIn("credential reference", report["mcp_servers"][0]["risk_hints"])
        self.assertIn("broad filesystem path", report["mcp_servers"][0]["risk_hints"])
        self.assertEqual(safe_install_context(report)["mcp_servers"][0]["name"], "fs")
        self.assertGreater(report["risk_score"], 25)

    def test_catalog_profiles_and_database_rule(self):
        report = scan(ROOT / "examples/mcp-catalog/postgres")
        context = safe_install_context(report)

        self.assertEqual(report["profile"]["name"], "Postgres MCP")
        self.assertEqual(report["mcp_servers"][0]["name"], "postgres")
        self.assertIn("database access", report["mcp_servers"][0]["risk_hints"])
        self.assertIn("database_credential_surface", report["rule_counts"])
        self.assertTrue(any("database" in item.lower() for item in context["agent_context"]))

    def test_review_report_marks_fallback_source(self):
        report = scan(ROOT / "examples/demo-agent-stack")
        review_report(report, allow_gemma=False)

        self.assertEqual(report["review_source"], "fallback")
        self.assertIn("summary", report["gemma_review"])
        self.assertIn("install_verdict", report["gemma_review"])
        self.assertNotIn("gemma_prompt_preview", report)

    def test_demo_fixture_url_is_accepted(self):
        self.assertRegex("https://github.com/dodge1218/agent-surface-demo-mcp", URL_RE)

    def test_fenced_gemma_json_is_parsed(self):
        content = '```json\n{"summary":"ok","install_verdict":"sandbox_first","top_risks":[],"quick_wins":[],"hardening_plan":[]}\n```'
        parsed = parse_gemma_content(content)
        self.assertEqual(parsed["summary"], "ok")

    def test_safe_extract_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive_path = root / "bad.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../escape.txt", "bad")

            with zipfile.ZipFile(archive_path) as archive:
                with self.assertRaises(ValueError):
                    safe_extract(archive, root / "out")


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
        self.assertIn("validate_install_plan", tool_names)

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

    def test_validate_install_plan_tool(self):
        report = scan(ROOT / "examples/demo-agent-stack")
        review_report(report, allow_gemma=False)
        responses, _ = self.call_server(
            [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "validate_install_plan",
                        "arguments": {
                            "report": report,
                            "proposed_config": {"global_install": True, "mcpServers": {"bad": {"args": ["/home/me"]}}},
                        },
                    },
                },
            ]
        )
        text = responses[1]["result"]["content"][0]["text"]
        payload = json.loads(text)
        self.assertEqual(payload["decision"], "block")


if __name__ == "__main__":
    unittest.main()

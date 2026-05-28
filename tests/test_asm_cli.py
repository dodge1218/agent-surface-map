from __future__ import annotations

import json
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.server import ThreadingHTTPServer
from io import StringIO
from pathlib import Path
from urllib import request
from urllib.error import HTTPError

import asm_cli
import yaml
from agent_surface_map.http_api import make_handler
from agent_surface_map import __version__
from agent_surface_map.scanner import REPORT_VERSION, scan
from agent_surface_map.reports import schema_path


ROOT = Path(__file__).resolve().parents[1]


class AsmCliTests(unittest.TestCase):
    def test_package_facade_exports_core_scanner(self) -> None:
        self.assertEqual(__version__, "0.1.0")
        self.assertEqual(REPORT_VERSION, "agent-surface-map.report.v1")
        self.assertTrue(schema_path("report").exists())
        report = scan(ROOT / "examples/demo-agent-stack")
        self.assertIn("risk_score", report)

    def test_scan_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.json"
            buffer = StringIO()
            with redirect_stdout(buffer):
                code = asm_cli.main(["scan", str(ROOT / "examples/demo-agent-stack"), "--out", str(out)])

            self.assertEqual(code, 0)
            report = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(report["report_version"], "agent-surface-map.report.v1")
            self.assertEqual(report["reviewer"]["backend"], "deterministic")
            self.assertTrue(report["target"].endswith("demo-agent-stack"))
            self.assertIn("risk_score", report)
            self.assertIn("mcp_servers", report)

    def test_scan_format_json_prints_report(self) -> None:
        buffer = StringIO()
        with redirect_stdout(buffer):
            code = asm_cli.main(["scan", str(ROOT / "examples/demo-agent-stack"), "--format", "json"])

        self.assertEqual(code, 0)
        report = json.loads(buffer.getvalue())
        self.assertEqual(report["report_version"], "agent-surface-map.report.v1")

    def test_explain_summarizes_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.json"
            buffer = StringIO()
            with redirect_stdout(buffer):
                asm_cli.main(["scan", str(ROOT / "examples/demo-agent-stack"), "--out", str(out)])
            buffer = StringIO()
            with redirect_stdout(buffer):
                code = asm_cli.main(["explain", str(out)])

            self.assertEqual(code, 0)
            self.assertIn("install_posture=sandbox_first", buffer.getvalue())

    def test_schema_prints_report_schema(self) -> None:
        buffer = StringIO()
        with redirect_stdout(buffer):
            code = asm_cli.main(["schema", "report"])

        self.assertEqual(code, 0)
        schema = json.loads(buffer.getvalue())
        self.assertEqual(schema["title"], "Agent Surface Map Report v1")

    def test_schema_writes_all_schemas(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "schemas"
            buffer = StringIO()
            with redirect_stdout(buffer):
                code = asm_cli.main(["schema", "--out-dir", str(out_dir)])

            self.assertEqual(code, 0)
            self.assertTrue((out_dir / "report-v1.schema.json").exists())
            self.assertTrue((out_dir / "policy.schema.json").exists())

    def test_version_flag(self) -> None:
        buffer = StringIO()
        with redirect_stdout(buffer), self.assertRaises(SystemExit) as raised:
            asm_cli.main(["--version"])

        self.assertEqual(raised.exception.code, 0)
        self.assertIn("asm ", buffer.getvalue())

    def test_mcp_client_docs_cover_primary_clients(self) -> None:
        text = (ROOT / "docs/mcp-client-configs.md").read_text(encoding="utf-8")

        self.assertIn("Claude Code", text)
        self.assertIn("Codex", text)
        self.assertIn("Cursor", text)
        self.assertIn("Generic MCP JSON", text)
        self.assertIn("ASM_ALLOWED_ROOTS", text)
        self.assertIn("validate_install_plan", text)

    def test_github_action_metadata_is_wired(self) -> None:
        action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))

        self.assertEqual(action["runs"]["using"], "composite")
        self.assertIn("state", action["inputs"])
        self.assertIn("fail-on", action["inputs"])
        self.assertIn("drift-result", action["outputs"])
        run_blocks = "\n".join(step.get("run", "") for step in action["runs"]["steps"])
        self.assertIn("asm check", run_blocks)
        self.assertIn("--github-step-summary", run_blocks)

    def test_github_action_docs_include_minimal_workflow(self) -> None:
        text = (ROOT / "docs/github-action.md").read_text(encoding="utf-8")

        self.assertIn("uses: dodge1218/agent-surface-map@main", text)
        self.assertIn("actions/upload-artifact", text)
        self.assertIn("state-sha256-file", text)

    def test_release_checklist_marks_internal_note_private(self) -> None:
        text = (ROOT / "docs/release-readiness-checklist.md").read_text(encoding="utf-8")
        release_notes = (ROOT / "docs/release-notes-v0.1.0.md").read_text(encoding="utf-8")

        self.assertIn("Keep Private", text)
        self.assertIn("local private positioning notes", text)
        self.assertIn("Agent Surface Map v0.1.0", release_notes)
        self.assertIn("deterministic scan and policy review", release_notes)
        self.assertIn("public multi-tenant hosted API guarantees", release_notes)
        self.assertIn("docs/scanner-pack-ecosystem.md", text)

    def test_scanner_pack_docs_are_public_safe(self) -> None:
        text = (ROOT / "docs/scanner-pack-ecosystem.md").read_text(encoding="utf-8")
        doctrine = (ROOT / "docs/doctrine.md").read_text(encoding="utf-8")
        prd = (ROOT / "docs/local-first-product-prd.md").read_text(encoding="utf-8")
        v2 = (ROOT / "docs/prd-v2.md").read_text(encoding="utf-8")

        self.assertIn("pack: agent_tool_surface", text)
        self.assertIn("scanner packs for agent, tool, and developer-environment risk", text)
        self.assertIn("observed pattern -> generalized rule", text)
        self.assertIn("Do not brand the public project as a mirror of any non-public workflow.", doctrine)
        self.assertIn("Scanner Pack Contract", prd)
        self.assertIn("Scanner Pack Ecosystem", v2)

    def test_readme_leads_with_local_first_product_not_challenge_framing(self) -> None:
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        first_section = text.split("## Why This Exists", 1)[0]

        self.assertIn("local-first install-risk reviewer", first_section)
        self.assertIn("Agent installs with constraints", first_section)
        self.assertNotIn("submission candidate", first_section)
        self.assertNotIn("Gemma decides", first_section)
        self.assertIn("DEV Gemma 4 Submission", text)

    def test_ci_workflow_runs_release_smokes(self) -> None:
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
        steps = workflow["jobs"]["test"]["steps"]
        run_blocks = "\n".join(step.get("run", "") for step in steps)

        self.assertIn("python -m unittest discover -s tests -v", run_blocks)
        self.assertIn("python scripts/mcp_workflow_smoke.py", run_blocks)
        self.assertIn("asm baseline examples/demo-agent-stack", run_blocks)
        self.assertTrue(any(step.get("uses") == "./" for step in steps))

    def test_validate_blocks_broad_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"
            config_path = Path(tmp) / "mcp.json"
            buffer = StringIO()
            with redirect_stdout(buffer):
                asm_cli.main(["scan", str(ROOT / "examples/demo-agent-stack"), "--out", str(report_path)])
            config_path.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "filesystem": {
                                "command": "npx",
                                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home"],
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            with redirect_stdout(buffer):
                code = asm_cli.main(["validate", str(config_path), "--report", str(report_path), "--fail-on", "block"])

            self.assertEqual(code, 1)

    def test_init_policy_writes_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "agent-surface-policy.yml"
            buffer = StringIO()
            with redirect_stdout(buffer):
                code = asm_cli.main(["init-policy", "--out", str(out)])

            self.assertEqual(code, 0)
            text = out.read_text(encoding="utf-8")
            self.assertIn("max_risk_score", text)
            self.assertIn("denied_paths", text)

    def test_scan_invalid_target_returns_usage_error(self) -> None:
        buffer = StringIO()
        with redirect_stdout(buffer), redirect_stderr(buffer):
            code = asm_cli.main(["scan", "/path/that/does/not/exist"])

        self.assertEqual(code, 2)

    def test_local_http_api_scans_allowed_root_and_validates_config(self) -> None:
        server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(allowed_roots=[ROOT], allow_remote_github=False, allow_gemma=False),
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            health = api_get_json(base + "/healthz")
            self.assertTrue(health["ok"])

            report = api_post_json(base + "/v1/scan", {"target": str(ROOT / "examples/demo-agent-stack")})
            self.assertEqual(report["report_version"], "agent-surface-map.report.v1")
            self.assertEqual(report["reviewer"]["backend"], "deterministic")

            validation = api_post_json(
                base + "/v1/validate",
                {
                    "report": report,
                    "config": {
                        "mcpServers": {
                            "filesystem": {
                                "command": "npx",
                                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home"],
                            }
                        }
                    },
                },
            )
            self.assertEqual(validation["decision"], "block")

            schema = api_get_json(base + "/v1/schema/report")
            self.assertEqual(schema["title"], "Agent Surface Map Report v1")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_local_http_api_blocks_paths_outside_allowed_roots(self) -> None:
        with tempfile.TemporaryDirectory() as allowed, tempfile.TemporaryDirectory() as denied:
            server = ThreadingHTTPServer(
                ("127.0.0.1", 0),
                make_handler(allowed_roots=[Path(allowed)], allow_remote_github=False, allow_gemma=False),
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with self.assertRaises(HTTPError) as raised:
                    api_post_json(f"http://127.0.0.1:{server.server_port}/v1/scan", {"target": denied})
                self.assertEqual(raised.exception.code, 403)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_local_http_api_requires_configured_api_key(self) -> None:
        server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(allowed_roots=[ROOT], allow_remote_github=False, allow_gemma=False, api_keys=["test-key"]),
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            self.assertTrue(api_get_json(base + "/healthz")["ok"])
            with self.assertRaises(HTTPError) as missing:
                api_get_json(base + "/v1/schema/report")
            self.assertEqual(missing.exception.code, 401)

            schema = api_get_json(base + "/v1/schema/report", api_key="test-key")
            self.assertEqual(schema["title"], "Agent Surface Map Report v1")

            with self.assertRaises(HTTPError) as wrong:
                api_get_json(base + "/v1/schema/report", api_key="wrong")
            self.assertEqual(wrong.exception.code, 403)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_local_http_api_rate_limits_protected_endpoints(self) -> None:
        server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(allowed_roots=[ROOT], allow_remote_github=False, allow_gemma=False, rate_limit_per_minute=1),
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_port}/v1/schema/report"
        try:
            self.assertEqual(api_get_json(url)["title"], "Agent Surface Map Report v1")
            with self.assertRaises(HTTPError) as raised:
                api_get_json(url)
            self.assertEqual(raised.exception.code, 429)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

def api_get_json(url: str, api_key: str | None = None) -> dict:
    headers = {"authorization": f"Bearer {api_key}"} if api_key else {}
    req = request.Request(url, headers=headers, method="GET")
    with request.urlopen(req, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def api_post_json(url: str, payload: dict, api_key: str | None = None) -> dict:
    body = json.dumps(payload).encode("utf-8")
    headers = {"content-type": "application/json"}
    if api_key:
        headers["authorization"] = f"Bearer {api_key}"
    req = request.Request(url, data=body, headers=headers, method="POST")
    with request.urlopen(req, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


if __name__ == "__main__":
    unittest.main()

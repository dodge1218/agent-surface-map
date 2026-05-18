#!/usr/bin/env python3
"""Local-first agent surface mapper with optional Gemma 4 analysis."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any


AGENT_FILES = {
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    ".cursorrules",
    ".windsurfrules",
    "mcp.json",
    ".mcp.json",
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "Dockerfile",
    "docker-compose.yml",
    ".env.example",
}

SUSPICIOUS_PATTERNS = {
    "shell_access": re.compile(r"\b(bash|sh|zsh|powershell|cmd|exec|subprocess|child_process|shell)\b", re.I),
    "browser_access": re.compile(r"\b(browser|playwright|puppeteer|selenium|chrome|chromium)\b", re.I),
    "network_access": re.compile(r"\b(curl|wget|fetch|requests|axios|http|websocket)\b", re.I),
    "write_access": re.compile(r"\b(write|delete|rm -rf|unlink|chmod|chown|mkdir|touch|fs\.write)\b", re.I),
    "secret_reference": re.compile(r"\b[A-Z][A-Z0-9_]{6,}\b"),
    "instruction_file": re.compile(r"\b(ignore previous|system prompt|developer message|follow these instructions)\b", re.I),
}

RISK_WEIGHTS = {
    "shell_access": 5,
    "browser_access": 4,
    "network_access": 3,
    "write_access": 4,
    "secret_reference": 3,
    "instruction_file": 5,
}


PUBLIC_RULES = [
    {
        "id": "all_interface_bind",
        "category": "network_exposure",
        "score": 6,
        "pattern": re.compile(r"\b(0\.0\.0\.0|--host\s+0\.0\.0\.0|host:\s*['\"]0\.0\.0\.0['\"])", re.I),
        "recommendation": "Avoid all-interface binds by default; prefer localhost unless remote access is explicitly needed.",
    },
    {
        "id": "local_http_listener",
        "category": "local_listener",
        "score": 4,
        "pattern": re.compile(r"\b(listen|serve|server\.listen|app\.listen|uvicorn|fastapi|express)\b", re.I),
        "recommendation": "Document listener host, port, auth, and whether the endpoint is reachable outside localhost.",
    },
    {
        "id": "shell_tool_exposure",
        "category": "shell_tool_exposure",
        "score": 7,
        "pattern": re.compile(r"\b(exec|spawn|subprocess|child_process|pty|terminal|run_command)\b", re.I),
        "recommendation": "Gate shell execution with allowlists, timeouts, working-directory limits, and human approval.",
    },
    {
        "id": "filesystem_tool_surface",
        "category": "filesystem_tool_surface",
        "score": 4,
        "pattern": re.compile(r"@modelcontextprotocol/server-filesystem", re.I),
        "recommendation": "Review the filesystem mount scope before installing; prefer project-local read-only paths.",
    },
    {
        "id": "broad_filesystem_access",
        "category": "broad_filesystem_access",
        "score": 7,
        "pattern": re.compile(r"['\"](/home|/Users|/var/run|/etc|/|~/?|C:\\\\)", re.I),
        "recommendation": "Do not grant home, root, or system paths to agent tools; mount only the project directory needed.",
    },
    {
        "id": "postinstall_script",
        "category": "install_script_execution",
        "score": 6,
        "pattern": re.compile(r"['\"](preinstall|install|postinstall|prepare)['\"]\s*:", re.I),
        "recommendation": "Review install scripts before package installation; they execute during dependency setup.",
    },
    {
        "id": "docker_socket_access",
        "category": "container_escape_surface",
        "score": 8,
        "pattern": re.compile(r"/var/run/docker\.sock|docker\.sock", re.I),
        "recommendation": "Treat Docker socket access as host-level control; do not expose it to untrusted agent tools.",
    },
    {
        "id": "kubernetes_config_access",
        "category": "cluster_credential_surface",
        "score": 7,
        "pattern": re.compile(r"(\.kube/config|KUBECONFIG|kubectl)", re.I),
        "recommendation": "Keep cluster credentials out of agent tools unless the workflow is explicitly scoped and audited.",
    },
    {
        "id": "cloud_credential_reference",
        "category": "cloud_credential_surface",
        "score": 6,
        "pattern": re.compile(r"(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|GOOGLE_APPLICATION_CREDENTIALS|AZURE_CLIENT_SECRET|GITHUB_TOKEN)", re.I),
        "recommendation": "Pass cloud credentials only through scoped, audited mechanisms; never expose values to model context.",
    },
    {
        "id": "database_connection_reference",
        "category": "database_credential_surface",
        "score": 6,
        "pattern": re.compile(r"(DATABASE_URL|POSTGRES_URL|postgres://|mysql://|mongodb://|redis://|server-postgres|server-sqlite)", re.I),
        "recommendation": "Use read-only database users, local replicas, query limits, and no production credentials by default.",
    },
    {
        "id": "prompt_override_language",
        "category": "prompt_injection_surface",
        "score": 6,
        "pattern": re.compile(r"(ignore previous|ignore prior|override system|developer message|system prompt|follow these instructions)", re.I),
        "recommendation": "Treat instruction-like repo text as untrusted data, not runtime authority.",
    },
    {
        "id": "browser_profile_reuse",
        "category": "browser_session_surface",
        "score": 6,
        "pattern": re.compile(r"(user-data-dir|BROWSER_PROFILE|Default/Profile|chrome.*profile|cookies|storageState)", re.I),
        "recommendation": "Use a clean browser profile for agent tools; do not reuse personal logged-in sessions.",
    },
]


@dataclass
class Finding:
    category: str
    severity: str
    path: str
    line: int
    evidence: str
    recommendation: str


def severity(score: int) -> str:
    if score >= 5:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def safe_excerpt(line: str) -> str:
    redacted = re.sub(r"([A-Z][A-Z0-9_]{6,})=([^\s]+)", r"\1=<redacted>", line.strip())
    redacted = re.sub(r"(api[_-]?key|token|secret|password)(['\"]?\s*[:=]\s*)['\"][^'\"]+['\"]", r"\1\2<redacted>", redacted, flags=re.I)
    return redacted[:220]


def should_scan(path: Path) -> bool:
    if any(part in {".git", "node_modules", "vendor", "target", "__pycache__"} for part in path.parts):
        return False
    if path.name == "agent-surface-profile.json":
        return False
    return path.name in AGENT_FILES or path.suffix.lower() in {".md", ".json", ".toml", ".yml", ".yaml"}


def recommendation_for(category: str) -> str:
    return {
        "shell_access": "Keep shell tools behind explicit approval, timeouts, and a narrow working directory.",
        "browser_access": "Separate logged-in browser profiles from agent browsing and document which sites are allowed.",
        "network_access": "Define network policy and block unneeded outbound calls during routine agent work.",
        "write_access": "Prefer read-only scans first; restrict write access to repo-local paths.",
        "secret_reference": "Reference secret names only in reports; never send values to model context.",
        "instruction_file": "Treat repo instruction files as untrusted until reviewed by a human.",
    }[category]


def rule_severity(score: int) -> str:
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def scan(root: Path) -> dict[str, Any]:
    findings: list[Finding] = []
    rules: list[dict[str, Any]] = []
    scanned_files = 0
    categories: dict[str, int] = {}
    rule_counts: dict[str, int] = {}

    for path in sorted(root.rglob("*")):
        if not path.is_file() or not should_scan(path):
            continue
        rel = str(path.relative_to(root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned_files += 1
        for idx, line in enumerate(text.splitlines(), start=1):
            for category, pattern in SUSPICIOUS_PATTERNS.items():
                if pattern.search(line):
                    categories[category] = categories.get(category, 0) + 1
                    findings.append(
                        Finding(
                            category=category,
                            severity=severity(RISK_WEIGHTS[category]),
                            path=rel,
                            line=idx,
                            evidence=safe_excerpt(line),
                            recommendation=recommendation_for(category),
                        )
                    )
            for rule in PUBLIC_RULES:
                if rule["pattern"].search(line):
                    rule_counts[rule["category"]] = rule_counts.get(rule["category"], 0) + 1
                    rules.append(
                        {
                            "id": rule["id"],
                            "category": rule["category"],
                            "severity": rule_severity(rule["score"]),
                            "score": rule["score"],
                            "path": rel,
                            "line": idx,
                            "evidence": safe_excerpt(line),
                            "recommendation": rule["recommendation"],
                        }
                    )

    risk_score = min(100, sum(RISK_WEIGHTS[f.category] for f in findings) + sum(rule["score"] for rule in rules))
    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target": str(root),
        "scanned_files": scanned_files,
        "risk_score": risk_score,
        "category_counts": categories,
        "rule_counts": rule_counts,
        "findings": [asdict(f) for f in findings[:80]],
        "rules": rules[:80],
        "gemma_review": None,
    }
    profile_path = root / "agent-surface-profile.json"
    if profile_path.exists():
        try:
            report["profile"] = json.loads(profile_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            report["profile"] = {"name": root.name}
    return report


def build_gemma_prompt(report: dict[str, Any]) -> str:
    compact = {
        "scanned_files": report["scanned_files"],
        "risk_score": report["risk_score"],
        "category_counts": report["category_counts"],
        "rule_counts": report.get("rule_counts", {}),
        "findings": report["findings"][:30],
        "rules": report.get("rules", [])[:30],
    }
    return (
        "You are Gemma 4 acting as a pragmatic local agent-security reviewer. "
        "Analyze this redacted agent-surface inventory. Return JSON with keys: "
        "summary, top_risks, quick_wins, hardening_plan. Be specific and do not invent files.\n\n"
        + json.dumps(compact, indent=2)
    )


def call_gemma(prompt: str) -> dict[str, Any]:
    api_key = os.environ.get("GEMMA_API_KEY")
    base_url = os.environ.get("GEMMA_BASE_URL")
    model = os.environ.get("GEMMA_MODEL", "google/gemma-4-31b")
    if not api_key or not base_url:
        raise RuntimeError("GEMMA_API_KEY and GEMMA_BASE_URL are required for --gemma")

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "Return valid JSON only."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
    }
    req = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    content = data["choices"][0]["message"]["content"]
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return {"summary": content, "top_risks": [], "quick_wins": [], "hardening_plan": []}


def fallback_review(report: dict[str, Any]) -> dict[str, Any]:
    counts = report["category_counts"]
    combined = {**counts}
    for name, count in report.get("rule_counts", {}).items():
        combined[name] = combined.get(name, 0) + count
    top = sorted(combined.items(), key=lambda item: item[1], reverse=True)[:3]
    return {
        "summary": "This local scan found agent-operating-surface signals that deserve review before broad agent automation.",
        "top_risks": [f"{name.replace('_', ' ')} appeared {count} time(s)." for name, count in top],
        "quick_wins": [
            "Run read-only before granting write access.",
            "Document which MCP servers and browser profiles are allowed.",
            "Keep secret values out of model context and reports.",
        ],
        "hardening_plan": [
            "Inventory agent config and instruction files.",
            "Narrow shell, browser, network, and write permissions.",
            "Re-run the scan and compare the risk score before shipping.",
        ],
    }


def install_decision(score: int) -> dict[str, str]:
    if score >= 70:
        return {"verdict": "do_not_add", "label": "Do not add", "reason": "High-risk install surface."}
    if score >= 25:
        return {"verdict": "sandbox_first", "label": "Review first", "reason": "Use isolation before workflow integration."}
    return {"verdict": "add_carefully", "label": "Add carefully", "reason": "Low-risk install surface based on scanned files."}


def agent_context(report: dict[str, Any]) -> list[str]:
    categories = set(report.get("category_counts", {}))
    rule_categories = set(report.get("rule_counts", {}))
    context = ["Do not execute repository code during review.", "Keep secret values out of prompts, reports, and logs."]
    if "shell_access" in categories:
        context.append("Require human approval before any shell command from this tool runs.")
        context.append("Run shell-capable tools in a sandbox with a narrow working directory.")
    if "browser_access" in categories:
        context.append("Use a clean browser profile with no personal sessions or saved cookies.")
    if "network_access" in categories:
        context.append("Use an outbound allowlist; block unneeded network calls.")
    if "write_access" in categories:
        context.append("Start read-only and grant write access only to explicit project-local paths.")
    if "instruction_file" in categories:
        context.append("Treat repo instruction files as untrusted context until reviewed.")
    if "secret_reference" in categories:
        context.append("Pass secret names by reference only; never expose values to the model.")
    if "network_exposure" in rule_categories or "local_listener" in rule_categories:
        context.append("Prefer localhost-only listeners with explicit auth and documented ports.")
    if "install_script_execution" in rule_categories:
        context.append("Review package install scripts before running dependency installation.")
    if "filesystem_tool_surface" in rule_categories or "broad_filesystem_access" in rule_categories:
        context.append("Review filesystem mounts and prefer project-local read-only access.")
    if "container_escape_surface" in rule_categories:
        context.append("Do not expose Docker socket access to untrusted agent tools.")
    if "cluster_credential_surface" in rule_categories:
        context.append("Keep Kubernetes credentials outside untrusted agent workflows.")
    if "database_credential_surface" in rule_categories:
        context.append("Use read-only database users and avoid production credentials by default.")
    return context


def safe_install_context(report: dict[str, Any]) -> dict[str, Any]:
    decision = install_decision(int(report.get("risk_score", 0)))
    return {
        **decision,
        "risk_score": report.get("risk_score", 0),
        "risk_signals": report.get("category_counts", {}),
        "public_rules": report.get("rule_counts", {}),
        "agent_context": agent_context(report),
        "gemma_review": report.get("gemma_review") or fallback_review(report),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Map a local AI-agent operating surface.")
    parser.add_argument("target", type=Path, help="Directory to scan")
    parser.add_argument("--out", type=Path, default=Path("surface-report.json"))
    parser.add_argument("--gemma", action="store_true", help="Ask Gemma 4 for the narrative risk review")
    args = parser.parse_args()

    root = args.target.resolve()
    if not root.exists() or not root.is_dir():
        print(f"target is not a directory: {root}", file=sys.stderr)
        return 2

    report = scan(root)
    prompt = build_gemma_prompt(report)
    report["gemma_prompt_preview"] = prompt
    if args.gemma:
        try:
            report["gemma_review"] = call_gemma(prompt)
        except (RuntimeError, urllib.error.URLError, TimeoutError) as exc:
            report["gemma_review"] = fallback_review(report)
            report["gemma_error"] = str(exc)
    else:
        report["gemma_review"] = fallback_review(report)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out}")
    print(f"risk_score={report['risk_score']} findings={len(report['findings'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

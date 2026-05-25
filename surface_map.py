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
        "pattern": re.compile(r"(^|[\s:'\"\[-])(/home|/Users|/var/run|/etc)(/|:|\s|$)|['\"]/\s*['\"]|(^|[\s:'\"\[-])~/?(\s|$)|C:\\\\", re.I),
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
    redacted = line.strip()
    redacted = re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*", "-----BEGIN PRIVATE KEY-----<redacted>", redacted, flags=re.I)
    redacted = re.sub(r"\b(Bearer\s+)[A-Za-z0-9._~+/=-]{12,}", r"\1<redacted>", redacted, flags=re.I)
    redacted = re.sub(r"\b(gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b", "<redacted-token>", redacted)
    redacted = re.sub(r"\b(sk-[A-Za-z0-9_-]{16,})\b", "<redacted-token>", redacted)
    redacted = re.sub(r"\b(npm_[A-Za-z0-9]{20,})\b", "<redacted-token>", redacted)
    redacted = re.sub(r"\b(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b", "<redacted-jwt>", redacted)
    redacted = re.sub(r"([A-Za-z_][A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)[A-Za-z0-9_]*)=([^\s]+)", r"\1=<redacted>", redacted, flags=re.I)
    redacted = re.sub(r"(api[_-]?key|token|secret|password|private[_-]?key|credential)(['\"]?\s*[:=]\s*)['\"]?[^'\"\s,}]+['\"]?", r"\1\2<redacted>", redacted, flags=re.I)
    redacted = re.sub(r"([a-z][a-z0-9+.-]*://[^:/\s]+:)([^@\s]+)(@)", r"\1<redacted>\3", redacted, flags=re.I)
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


def extract_mcp_servers(root: Path) -> list[dict[str, Any]]:
    servers: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() != ".json":
            continue
        rel_path = path.relative_to(root)
        if any(part in {".git", "node_modules", "vendor", "target", "__pycache__"} for part in rel_path.parts):
            continue
        rel = str(rel_path)
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        raw_servers = data.get("mcpServers") if isinstance(data, dict) else None
        if not isinstance(raw_servers, dict):
            continue
        for name, config in sorted(raw_servers.items()):
            if not isinstance(config, dict):
                continue
            args = config.get("args", [])
            env = config.get("env", {})
            env_keys = sorted(str(key) for key in env) if isinstance(env, dict) else []
            server = {
                "name": str(name),
                "path": rel,
                "command": str(config.get("command", "")),
                "args": [safe_excerpt(str(arg)) for arg in args] if isinstance(args, list) else [],
                "env_keys": env_keys,
                "risk_hints": mcp_risk_hints(str(config.get("command", "")), args if isinstance(args, list) else [], env_keys),
            }
            servers.append(server)
    return servers[:40]


def mcp_risk_hints(command: str, args: list[Any], env_keys: list[str]) -> list[str]:
    text = " ".join([command, *(str(arg) for arg in args), *env_keys])
    hints: list[str] = []
    if re.search(r"\b(npx|npm|pnpm|yarn|pip|uvx)\b", text, re.I):
        hints.append("package runner")
    if re.search(r"\b(bash|sh|zsh|powershell|cmd|python|node)\b", text, re.I):
        hints.append("local process")
    if re.search(r"(browser|playwright|chrome|chromium|user-data-dir|cookies|storageState)", text, re.I):
        hints.append("browser/session")
    if re.search(r"(^|[\s:'\"\[-])(/home|/Users|/var/run|/etc)(/|:|\s|$)|(^|[\s:'\"\[-])~/?(\s|$)|C:\\\\", text, re.I):
        hints.append("broad filesystem path")
    if re.search(r"(TOKEN|SECRET|PASSWORD|KEY|CREDENTIAL|DATABASE_URL)", text, re.I):
        hints.append("credential reference")
    if re.search(r"(postgres|mysql|mongodb|redis|sqlite|database)", text, re.I):
        hints.append("database access")
    return hints


def extract_structured_evidence(root: Path) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel_path = path.relative_to(root)
        if any(part in {".git", "node_modules", "vendor", "target", "__pycache__"} for part in rel_path.parts):
            continue
        rel = str(rel_path)
        if path.name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            evidence.extend(extract_compose_volumes(text, rel))
        elif path.name == "devcontainer.json":
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(data, dict):
                evidence.extend(extract_devcontainer_evidence(data, rel))
                evidence.extend(extract_mcp_settings_evidence(data, rel))
        elif path.suffix.lower() == ".json":
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(data, dict):
                evidence.extend(extract_mcp_settings_evidence(data, rel))
    return evidence[:80]


def extract_compose_volumes(text: str, rel_path: str) -> list[dict[str, Any]]:
    volumes: list[dict[str, Any]] = []
    in_volumes = False
    volumes_indent = 0
    current_long: dict[str, Any] | None = None

    def flush_current() -> None:
        nonlocal current_long
        if not current_long:
            return
        source = current_long.get("source")
        target = current_long.get("target")
        if isinstance(source, str) and source and is_host_mount_source(source):
            volumes.append(compose_volume_item(rel_path, int(current_long.get("line", 0) or 0), source, target if isinstance(target, str) else "", str(current_long.get("evidence", "")), "long"))
        current_long = None

    for idx, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if stripped == "volumes:":
            flush_current()
            in_volumes = True
            volumes_indent = indent
            continue
        if in_volumes and indent <= volumes_indent and not stripped.startswith("- "):
            flush_current()
            in_volumes = False
        if not in_volumes:
            continue
        if stripped.startswith("- "):
            flush_current()
            payload = stripped[2:].strip()
            if payload.startswith("type:"):
                current_long = {"line": idx, "evidence": raw_line.strip()}
                continue
            item = compose_volume_from_short(rel_path, idx, payload, raw_line.strip())
            if item:
                volumes.append(item)
            continue
        if current_long and ":" in stripped:
            key, value = stripped.split(":", 1)
            key = key.strip()
            value = value.strip().strip("'\"")
            if key in {"source", "src", "target", "dst", "destination"}:
                if key in {"src"}:
                    key = "source"
                if key in {"dst", "destination"}:
                    key = "target"
                current_long[key] = value
                current_long["evidence"] = (str(current_long.get("evidence", "")) + " " + stripped).strip()
    flush_current()
    return volumes


def compose_volume_from_short(rel_path: str, line: int, payload: str, evidence: str) -> dict[str, Any] | None:
    cleaned = payload.strip().strip("'\"")
    if ":" not in cleaned:
        return None
    parts = cleaned.split(":")
    if len(parts) < 2:
        return None
    source = parts[0].strip()
    target = parts[1].strip()
    mode = parts[2].strip() if len(parts) > 2 else ""
    if not is_host_mount_source(source):
        return None
    item = compose_volume_item(rel_path, line, source, target, evidence, "short")
    if mode:
        item["mode"] = safe_excerpt(mode)
    return item


def compose_volume_item(rel_path: str, line: int, source: str, target: str, evidence: str, syntax: str) -> dict[str, Any]:
    return {
        "kind": "compose_volume",
        "path": rel_path,
        "line": line,
        "source": safe_excerpt(source),
        "target": safe_excerpt(target),
        "syntax": syntax,
        "evidence": safe_excerpt(evidence),
        "risk_hints": compose_volume_risk_hints(source),
        "recommendation": "Review host-side compose volume sources before granting an agent access.",
    }


def is_host_mount_source(source: str) -> bool:
    return source.startswith(("/", "~", "./", "../")) or bool(re.match(r"^[A-Za-z]:\\\\", source))


def compose_volume_risk_hints(source: str) -> list[str]:
    hints: list[str] = []
    if is_broad_local_path(source) or source == "/":
        hints.append("broad host path")
    if "docker.sock" in source:
        hints.append("docker socket")
    return hints


def extract_devcontainer_evidence(data: dict[str, Any], rel_path: str) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    mounts = data.get("mounts", [])
    if isinstance(mounts, str):
        mounts = [mounts]
    if isinstance(mounts, list):
        for idx, mount in enumerate(mounts, start=1):
            if not isinstance(mount, str):
                continue
            parsed = parse_devcontainer_mount(mount)
            if parsed:
                evidence.append(devcontainer_mount_item(rel_path, idx, mount, parsed))
    run_args = data.get("runArgs", [])
    if isinstance(run_args, list):
        for idx, value in enumerate(run_args):
            if not isinstance(value, str):
                continue
            mount = ""
            if value in {"-v", "--volume", "--mount"} and idx + 1 < len(run_args) and isinstance(run_args[idx + 1], str):
                mount = run_args[idx + 1]
            elif value.startswith(("-v=", "--volume=", "--mount=")):
                mount = value.split("=", 1)[1]
            elif value.startswith("-v") and len(value) > 2:
                mount = value[2:]
            if not mount:
                continue
            parsed = parse_devcontainer_mount(mount)
            if parsed:
                evidence.append(devcontainer_mount_item(rel_path, idx + 1, mount, parsed))
    features = data.get("features", {})
    if isinstance(features, dict):
        for name in sorted(features):
            evidence.append(
                {
                    "kind": "devcontainer_feature",
                    "path": rel_path,
                    "name": safe_excerpt(str(name)),
                    "risk_hints": devcontainer_feature_risk_hints(str(name)),
                    "recommendation": "Review devcontainer features because they can install tools and alter the runtime before agent use.",
                }
            )
    for key in {"initializeCommand", "onCreateCommand", "postCreateCommand", "postStartCommand", "postAttachCommand"}:
        value = data.get(key)
        if isinstance(value, (str, list, dict)):
            evidence.append(
                {
                    "kind": "devcontainer_lifecycle_command",
                    "path": rel_path,
                    "name": key,
                    "evidence": safe_excerpt(json.dumps(value, sort_keys=True) if not isinstance(value, str) else value),
                    "risk_hints": ["shell command"],
                    "recommendation": "Review devcontainer lifecycle commands before allowing agent-driven setup.",
                }
            )
    return evidence


def parse_devcontainer_mount(mount: str) -> dict[str, str] | None:
    text = mount.strip().strip("'\"")
    if not text:
        return None
    if "," in text and "=" in text:
        fields: dict[str, str] = {}
        for part in text.split(","):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            fields[key.strip()] = value.strip()
        source = fields.get("source") or fields.get("src")
        target = fields.get("target") or fields.get("dst") or fields.get("destination")
        if source and is_host_mount_source(source):
            return {"source": source, "target": target or "", "syntax": "mount"}
        return None
    item = compose_volume_from_short("", 0, text, text)
    if not item:
        return None
    return {"source": str(item.get("source", "")), "target": str(item.get("target", "")), "syntax": "volume"}


def devcontainer_mount_item(rel_path: str, index: int, mount: str, parsed: dict[str, str]) -> dict[str, Any]:
    source = parsed.get("source", "")
    return {
        "kind": "devcontainer_mount",
        "path": rel_path,
        "index": index,
        "source": safe_excerpt(source),
        "target": safe_excerpt(parsed.get("target", "")),
        "syntax": parsed.get("syntax", ""),
        "evidence": safe_excerpt(mount),
        "risk_hints": compose_volume_risk_hints(source),
        "recommendation": "Review devcontainer host mounts before granting an agent access.",
    }


def devcontainer_feature_risk_hints(name: str) -> list[str]:
    hints: list[str] = []
    if re.search(r"(docker|kubectl|kubernetes|aws|gcloud|azure|ghcr|github)", name, re.I):
        hints.append("privileged tooling")
    return hints


def extract_mcp_settings_evidence(data: dict[str, Any], rel_path: str) -> list[dict[str, Any]]:
    raw_servers = data.get("mcpServers")
    if not isinstance(raw_servers, dict):
        return []
    client = mcp_client_name(rel_path)
    evidence: list[dict[str, Any]] = []
    for name, config in sorted(raw_servers.items()):
        if not isinstance(config, dict):
            continue
        args = config.get("args", [])
        env = config.get("env", {})
        env_keys = sorted(str(key) for key in env) if isinstance(env, dict) else []
        command = str(config.get("command", ""))
        safe_args = [safe_excerpt(str(arg)) for arg in args] if isinstance(args, list) else []
        evidence.append(
            {
                "kind": "mcp_client_server",
                "path": rel_path,
                "client": client,
                "name": safe_excerpt(str(name)),
                "command": safe_excerpt(command),
                "args": safe_args,
                "env_keys": env_keys,
                "risk_hints": mcp_risk_hints(command, args if isinstance(args, list) else [], env_keys),
                "recommendation": "Review MCP client settings before enabling new agent tools.",
            }
        )
    return evidence


def mcp_client_name(rel_path: str) -> str:
    lowered = rel_path.lower()
    if ".cursor" in lowered:
        return "cursor"
    if ".windsurf" in lowered:
        return "windsurf"
    if "claude" in lowered:
        return "claude"
    if "continue" in lowered:
        return "continue"
    if "devcontainer" in lowered:
        return "devcontainer"
    if rel_path.endswith(("mcp.json", ".mcp.json")):
        return "mcp"
    return "unknown"


def scan(root: Path) -> dict[str, Any]:
    findings: list[Finding] = []
    rules: list[dict[str, Any]] = []
    scanned_files = 0
    categories: dict[str, int] = {}
    rule_counts: dict[str, int] = {}

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel_path = path.relative_to(root)
        if not should_scan(rel_path):
            continue
        rel = str(rel_path)
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
        "mcp_servers": extract_mcp_servers(root),
        "structured_evidence": extract_structured_evidence(root),
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
    static_decision = install_decision(int(report.get("risk_score", 0)))
    compact = {
        "scanned_files": report["scanned_files"],
        "risk_score": report["risk_score"],
        "static_install_decision": static_decision,
        "category_counts": report["category_counts"],
        "rule_counts": report.get("rule_counts", {}),
        "findings": report["findings"][:30],
        "rules": report.get("rules", [])[:30],
        "mcp_servers": report.get("mcp_servers", [])[:20],
        "structured_evidence": report.get("structured_evidence", [])[:20],
    }
    return (
        "You are Gemma 4 acting as a pragmatic local agent-security reviewer. "
        "Analyze this redacted agent-surface inventory and make the install-policy judgment. "
        "The static scanner is evidence collection, not the final product. Return valid JSON with keys: "
        "summary, install_verdict, confidence, why_gemma_changed_the_call, agent_constraints, "
        "top_risks, quick_wins, hardening_plan. install_verdict must be one of "
        "add_carefully, sandbox_first, do_not_add. confidence must be low, medium, or high. "
        "Be specific, connect combined risks, and do not invent files.\n\n"
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
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": os.environ.get("GEMMA_HTTP_REFERER", "https://gemma-agent-surface-map.vercel.app"),
            "X-Title": os.environ.get("GEMMA_APP_TITLE", "Agent Surface Map"),
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    content = data["choices"][0]["message"]["content"]
    return parse_gemma_content(content)


def parse_gemma_content(content: str) -> dict[str, Any]:
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.S)
        if fenced:
            try:
                return json.loads(fenced.group(1))
            except json.JSONDecodeError:
                pass
        return {"summary": content, "top_risks": [], "quick_wins": [], "hardening_plan": []}


def normalize_review(review: dict[str, Any], report: dict[str, Any], source: str) -> dict[str, Any]:
    static = install_decision(int(report.get("risk_score", 0)))
    verdict = str(review.get("install_verdict") or static["verdict"])
    if verdict not in {"add_carefully", "sandbox_first", "do_not_add"}:
        verdict = static["verdict"]
    confidence = str(review.get("confidence") or ("medium" if source == "gemma" else "low"))
    if confidence not in {"low", "medium", "high"}:
        confidence = "medium" if source == "gemma" else "low"
    constraints = review.get("agent_constraints")
    if not isinstance(constraints, list) or not constraints:
        constraints = agent_context(report)
    normalized = {
        "summary": str(review.get("summary") or "Install posture review completed."),
        "install_verdict": verdict,
        "confidence": confidence,
        "why_gemma_changed_the_call": str(
            review.get("why_gemma_changed_the_call")
            or ("Deterministic fallback used the static install posture because the Gemma route was unavailable." if source == "fallback" else "Gemma kept the static posture and clarified the install constraints.")
        ),
        "agent_constraints": [str(item) for item in constraints[:12]],
        "top_risks": [str(item) for item in review.get("top_risks", [])[:8]] if isinstance(review.get("top_risks", []), list) else [],
        "quick_wins": [str(item) for item in review.get("quick_wins", [])[:8]] if isinstance(review.get("quick_wins", []), list) else [],
        "hardening_plan": [str(item) for item in review.get("hardening_plan", [])[:8]] if isinstance(review.get("hardening_plan", []), list) else [],
    }
    if not normalized["hardening_plan"]:
        normalized["hardening_plan"] = normalized["quick_wins"]
    return normalized


def gemma_configured() -> bool:
    return bool(os.environ.get("GEMMA_API_KEY") and os.environ.get("GEMMA_BASE_URL"))


def fallback_review(report: dict[str, Any]) -> dict[str, Any]:
    counts = report["category_counts"]
    combined = {**counts}
    for name, count in report.get("rule_counts", {}).items():
        combined[name] = combined.get(name, 0) + count
    top = sorted(combined.items(), key=lambda item: item[1], reverse=True)[:3]
    decision = install_decision(int(report.get("risk_score", 0)))
    return {
        "summary": "This local scan found agent-operating-surface signals that deserve review before broad agent automation.",
        "install_verdict": decision["verdict"],
        "confidence": "low",
        "why_gemma_changed_the_call": "Deterministic fallback used the static install posture because the Gemma route was unavailable.",
        "agent_constraints": agent_context(report),
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


def review_report(report: dict[str, Any], *, allow_gemma: bool | None = None) -> dict[str, Any]:
    """Attach a Gemma review when configured, otherwise attach deterministic fallback."""
    if allow_gemma is None:
        allow_gemma = gemma_configured()
    if allow_gemma:
        prompt = build_gemma_prompt(report)
        try:
            report["gemma_review"] = normalize_review(call_gemma(prompt), report, "gemma")
            report["review_source"] = "gemma"
            report.pop("gemma_error", None)
            return report
        except (RuntimeError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError) as exc:
            report["gemma_error"] = str(exc)

    report["gemma_review"] = normalize_review(fallback_review(report), report, "fallback")
    report["review_source"] = "fallback"
    return report


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
    static_decision = install_decision(int(report.get("risk_score", 0)))
    review = report.get("gemma_review") or fallback_review(report)
    review_verdict = review.get("install_verdict") if isinstance(review, dict) else None
    decision = {**static_decision}
    if review_verdict in {"add_carefully", "sandbox_first", "do_not_add"}:
        decision["verdict"] = review_verdict
        decision["label"] = {
            "add_carefully": "Add carefully",
            "sandbox_first": "Sandbox first",
            "do_not_add": "Do not add",
        }[review_verdict]
        decision["reason"] = "Gemma install-policy review." if report.get("review_source") == "gemma" else static_decision["reason"]
    constraints = review.get("agent_constraints") if isinstance(review, dict) else None
    if not isinstance(constraints, list) or not constraints:
        constraints = agent_context(report)
    return {
        **decision,
        "static_verdict": static_decision["verdict"],
        "review_source": report.get("review_source", "fallback"),
        "confidence": review.get("confidence", "low") if isinstance(review, dict) else "low",
        "risk_score": report.get("risk_score", 0),
        "risk_signals": report.get("category_counts", {}),
        "public_rules": report.get("rule_counts", {}),
        "mcp_servers": report.get("mcp_servers", []),
        "agent_context": constraints,
        "policy": policy_block(report, constraints),
        "gemma_review": review,
    }


def validate_install_plan(report: dict[str, Any], proposed_config: Any, team_policy: dict[str, Any] | None = None) -> dict[str, Any]:
    """Check a final proposed MCP/client config against the scan-derived policy."""
    config = parse_plan_config(proposed_config)
    context = safe_install_context(report)
    policy = context["policy"]
    team_policy = team_policy if isinstance(team_policy, dict) else {}
    blockers: list[str] = []
    warnings: list[str] = []
    required_changes: list[str] = []

    if context["verdict"] == "do_not_add":
        blockers.append("Scan posture is do_not_add; do not write this install plan.")
    if config.get("global_install") is True and context["verdict"] == "sandbox_first":
        blockers.append("Plan requests global install while scan posture is sandbox_first.")

    text = json.dumps(config, sort_keys=True)
    plan_paths = policy_path_values(config)
    if any(is_broad_local_path(path) for path in plan_paths):
        blockers.append("Plan includes broad local paths; mount only the project directory.")
    if re.search(r"(docker\.sock|/var/run/docker\.sock)", text, re.I):
        blockers.append("Plan exposes Docker socket access.")
    if re.search(r"(--user-data-dir|BROWSER_PROFILE|Default/Profile|cookies|storageState)", text, re.I):
        required_changes.append("Use a clean browser profile with no personal sessions or saved cookies.")
    if re.search(r"\b(bash|sh|zsh|powershell|cmd|exec|subprocess|child_process|terminal)\b", text, re.I):
        required_changes.append("Require human approval before shell commands from this tool run.")
    if leaks_secret_value(config, set(policy.get("secret_env_keys", []))):
        blockers.append("Plan appears to include a secret value; use env key names or placeholders only.")

    planned_servers = planned_mcp_server_names(config)
    denied_servers = policy_string_set(team_policy.get("denied_mcp_server_names", []))
    allowed_servers = policy_string_set(team_policy.get("allowed_mcp_server_names", []))
    if planned_servers & denied_servers:
        blockers.append("Plan includes policy-denied MCP server: " + ", ".join(sorted(planned_servers & denied_servers)) + ".")
    if allowed_servers and planned_servers - allowed_servers:
        blockers.append("Plan includes MCP server outside policy allowlist: " + ", ".join(sorted(planned_servers - allowed_servers)) + ".")
    max_risk_score = policy_int(team_policy.get("max_risk_score"))
    if max_risk_score is not None and int(report.get("risk_score", 0)) > max_risk_score:
        blockers.append(f"Scan risk score {report.get('risk_score', 0)} exceeds policy max_risk_score {max_risk_score}.")
    report_severities = {
        str(item.get("severity", "")).lower()
        for item in list(report.get("findings", [])) + list(report.get("rules", []))
        if isinstance(item, dict) and item.get("severity")
    }
    block_severities = policy_string_set(team_policy.get("block_severities", []))
    review_severities = policy_string_set(team_policy.get("review_severities", []))
    if report_severities & block_severities:
        blockers.append("Scan includes team-policy blocked severity: " + ", ".join(sorted(report_severities & block_severities)) + ".")
    if report_severities & review_severities:
        warnings.append("Scan includes team-policy review severity: " + ", ".join(sorted(report_severities & review_severities)) + ".")

    denied_paths = policy_string_set(team_policy.get("denied_paths", [])) | policy_string_set(team_policy.get("blocked_paths", []))
    allowed_paths = policy_string_set(team_policy.get("allowed_paths", []))
    for path in sorted(plan_paths):
        denied_match = matching_path_policy(path, denied_paths)
        if denied_match:
            blockers.append(f"Plan includes policy-denied path {path}: matched {denied_match}.")
        elif allowed_paths and not matching_path_policy(path, allowed_paths):
            blockers.append(f"Plan includes path outside policy allowed_paths: {path}.")

    allowed_browser_profiles = policy_string_set(team_policy.get("allowed_browser_profiles", []))
    browser_profiles = planned_browser_profiles(config)
    for profile in sorted(browser_profiles):
        if allowed_browser_profiles and profile not in allowed_browser_profiles:
            blockers.append(f"Plan uses browser profile outside policy allowlist: {profile}.")

    declared_approvals = {str(item) for item in config.get("required_approvals", [])} if isinstance(config.get("required_approvals"), list) else set()
    for approval in policy.get("required_approvals", []):
        if approval not in declared_approvals:
            warnings.append(f"Plan does not declare required approval: {approval}.")
    for approval in policy_string_set(team_policy.get("required_approvals", [])):
        if approval not in declared_approvals:
            warnings.append(f"Plan does not declare team-policy required approval: {approval}.")

    decision = "pass"
    if blockers:
        decision = "block"
    elif required_changes or warnings:
        decision = "needs_changes"

    return {
        "decision": decision,
        "install_posture": context["verdict"],
        "blockers": blockers,
        "required_changes": required_changes,
        "warnings": warnings,
        "policy_checked": {
            "allowed_paths": policy.get("allowed_paths", []),
            "denied_paths": policy.get("denied_paths", []),
            "required_approvals": policy.get("required_approvals", []),
            "browser_profile_policy": policy.get("browser_profile_policy"),
            "network_policy": policy.get("network_policy"),
            "secret_env_keys": policy.get("secret_env_keys", []),
            "team_policy": {
                "allowed_mcp_server_names": sorted(allowed_servers),
                "denied_mcp_server_names": sorted(denied_servers),
                "max_risk_score": max_risk_score,
                "allowed_paths": sorted(allowed_paths),
                "denied_paths": sorted(denied_paths),
                "allowed_browser_profiles": sorted(allowed_browser_profiles),
                "required_approvals": sorted(policy_string_set(team_policy.get("required_approvals", []))),
                "block_severities": sorted(block_severities),
                "review_severities": sorted(review_severities),
            },
        },
    }


def parse_plan_config(proposed_config: Any) -> dict[str, Any]:
    if isinstance(proposed_config, dict):
        return proposed_config
    if isinstance(proposed_config, str):
        try:
            parsed = json.loads(proposed_config)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return {"raw": proposed_config}
    return {"raw": str(proposed_config)}


def planned_mcp_server_names(config: dict[str, Any]) -> set[str]:
    raw_servers = config.get("mcpServers")
    if not isinstance(raw_servers, dict):
        return set()
    return {str(name) for name, value in raw_servers.items() if isinstance(value, dict)}


def local_path_values(config: Any) -> set[str]:
    values: set[str] = set()
    if isinstance(config, dict):
        for value in config.values():
            values |= local_path_values(value)
        return values
    if isinstance(config, list):
        for value in config:
            values |= local_path_values(value)
        return values
    if not isinstance(config, str):
        return values
    for candidate in re.findall(r"(?:~|/[A-Za-z0-9._~+@%=-][^\s\"',}\]]*|[A-Za-z]:\\\\[^\s\"',}\]]+)", config):
        if candidate.startswith(("http://", "https://")):
            continue
        cleaned = candidate.rstrip(":")
        if cleaned.startswith("/") and ":" in cleaned:
            cleaned = cleaned.split(":", 1)[0]
        values.add(cleaned)
    return values


def policy_path_values(config: Any) -> set[str]:
    values: set[str] = set()
    if isinstance(config, dict):
        for key, value in config.items():
            key_text = str(key).lower()
            if key_text in {"dockerfile", "docker_file"} and isinstance(value, str):
                values |= docker_mount_host_paths(value)
            else:
                values |= policy_path_values(value)
        return values
    if isinstance(config, list):
        for value in config:
            values |= policy_path_values(value)
        return values
    if not isinstance(config, str):
        return values
    mount_paths = docker_mount_host_paths(config)
    if mount_paths:
        return mount_paths
    if looks_like_dockerfile_text(config):
        return set()
    return local_path_values(config)


def docker_mount_host_paths(text: str) -> set[str]:
    paths: set[str] = set()
    for raw in text.split():
        candidate = raw.strip().strip(" [],'\"")
        if not candidate or ":" not in candidate:
            continue
        host, _container = candidate.split(":", 1)
        host = host.strip().strip("'\"")
        if host.startswith(("/", "~", "./", "../")) or (len(host) > 2 and host[1:3] == ":\\"):
            paths.add(host)
    return paths


def looks_like_dockerfile_text(text: str) -> bool:
    stripped = text.strip()
    return bool(re.search(r"(?im)^\s*(FROM|RUN|COPY|ADD|WORKDIR|USER|ENV|CMD|ENTRYPOINT|EXPOSE)\b", stripped))


def matching_path_policy(path: str, policies: set[str]) -> str | None:
    normalized = path.rstrip("/")
    for policy in sorted(policies):
        candidate = policy.rstrip("/")
        if not candidate:
            continue
        if normalized == candidate or normalized.startswith(candidate + "/"):
            return policy
    return None


def is_broad_local_path(path: str) -> bool:
    return bool(re.search(r"^(~|/home(?:/|$)|/Users(?:/|$)|/etc(?:/|$)|/var/run(?:/|$)|[A-Za-z]:\\\\)", path))


def planned_browser_profiles(config: Any) -> set[str]:
    profiles: set[str] = set()
    if isinstance(config, str):
        for match in re.findall(r"--user-data-dir(?:=|\s+)([^\s\"',}\]]+)", config):
            profiles.add(match)
        for match in re.findall(r"BROWSER_PROFILE[\"']?\s*[:=]\s*[\"']?([^\"'\s,}]+)", config):
            profiles.add(match)
        return profiles
    if isinstance(config, dict):
        for key, value in config.items():
            key_text = str(key)
            if key_text == "BROWSER_PROFILE" and isinstance(value, str):
                profiles.add(value)
            if key_text in {"browser_profile", "browserProfile", "user_data_dir", "userDataDir"} and isinstance(value, str):
                profiles.add(value)
            profiles |= planned_browser_profiles(value)
        return profiles
    if isinstance(config, list):
        for index, value in enumerate(config):
            if value == "--user-data-dir" and index + 1 < len(config) and isinstance(config[index + 1], str):
                profiles.add(config[index + 1])
            elif isinstance(value, str) and value.startswith("--user-data-dir="):
                profiles.add(value.split("=", 1)[1])
            profiles |= planned_browser_profiles(value)
    return profiles


def policy_string_set(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {str(item) for item in value if str(item)}
    return set()


def policy_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def leaks_secret_value(config: Any, env_keys: set[str]) -> bool:
    if isinstance(config, dict):
        for key, value in config.items():
            key_text = str(key)
            if key_text in env_keys and isinstance(value, str) and value and not is_placeholder(value):
                return True
            if re.search(r"(token|secret|password|api[_-]?key|private[_-]?key|credential)", key_text, re.I):
                if isinstance(value, str) and value and not is_placeholder(value):
                    return True
            if leaks_secret_value(value, env_keys):
                return True
    if isinstance(config, list):
        return any(leaks_secret_value(item, env_keys) for item in config)
    return False


def is_placeholder(value: str) -> bool:
    return bool(re.fullmatch(r"(<[^>]+>|\$\{?[A-Z0-9_]+\}?|[A-Z][A-Z0-9_]{3,}|REDACTED|redacted|xxx+)", value.strip()))


def policy_block(report: dict[str, Any], constraints: list[str]) -> dict[str, Any]:
    categories = set(report.get("category_counts", {}))
    rule_categories = set(report.get("rule_counts", {}))
    requires_approval = []
    if "shell_access" in categories or "shell_tool_exposure" in rule_categories:
        requires_approval.append("shell_command")
    if "write_access" in categories:
        requires_approval.append("write_access")
    return {
        "allowed_paths": ["project directory only"],
        "denied_paths": ["home directory", "filesystem root", "credential/profile directories"],
        "secret_env_keys": sorted({key for server in report.get("mcp_servers", []) for key in server.get("env_keys", [])}),
        "browser_profile_policy": "clean profile only" if "browser_access" in categories or "browser_session_surface" in rule_categories else "not detected",
        "network_policy": "allowlist outbound hosts" if "network_access" in categories else "not detected",
        "required_approvals": requires_approval,
        "constraints": constraints[:12],
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
    review_report(report, allow_gemma=args.gemma)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out}")
    print(f"risk_score={report['risk_score']} findings={len(report['findings'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

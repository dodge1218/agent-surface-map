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


def scan(root: Path) -> dict[str, Any]:
    findings: list[Finding] = []
    scanned_files = 0
    categories: dict[str, int] = {}

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

    risk_score = min(100, sum(RISK_WEIGHTS[f.category] for f in findings))
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target": str(root),
        "scanned_files": scanned_files,
        "risk_score": risk_score,
        "category_counts": categories,
        "findings": [asdict(f) for f in findings[:80]],
        "gemma_review": None,
    }


def build_gemma_prompt(report: dict[str, Any]) -> str:
    compact = {
        "scanned_files": report["scanned_files"],
        "risk_score": report["risk_score"],
        "category_counts": report["category_counts"],
        "findings": report["findings"][:30],
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
    top = sorted(counts.items(), key=lambda item: item[1], reverse=True)[:3]
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


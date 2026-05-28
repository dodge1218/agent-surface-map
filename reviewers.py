"""Reviewer backends for Agent Surface Map reports."""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, Callable


INSTALL_VERDICTS = {"add_carefully", "sandbox_first", "do_not_add"}
CONFIDENCE_LEVELS = {"low", "medium", "high"}


def build_model_prompt(report: dict[str, Any], *, reviewer_name: str = "reviewer") -> str:
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
        f"You are {reviewer_name} acting as a pragmatic local agent-security reviewer. "
        "Analyze this redacted agent-surface inventory and make the install-policy judgment. "
        "The static scanner is evidence collection, not the final product. Return valid JSON with keys: "
        "summary, install_verdict, confidence, why_gemma_changed_the_call, agent_constraints, "
        "top_risks, quick_wins, hardening_plan. install_verdict must be one of "
        "add_carefully, sandbox_first, do_not_add. confidence must be low, medium, or high. "
        "Be specific, connect combined risks, and do not invent files.\n\n"
        + json.dumps(compact, indent=2)
    )


def call_openai_compatible(prompt: str, *, api_key: str, base_url: str, model: str) -> dict[str, Any]:
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
    return parse_model_content(content)


def call_gemma(prompt: str) -> dict[str, Any]:
    api_key = os.environ.get("GEMMA_API_KEY")
    base_url = os.environ.get("GEMMA_BASE_URL")
    model = os.environ.get("GEMMA_MODEL", "google/gemma-4-31b")
    if not api_key or not base_url:
        raise RuntimeError("GEMMA_API_KEY and GEMMA_BASE_URL are required for --gemma")
    return call_openai_compatible(prompt, api_key=api_key, base_url=base_url, model=model)


def parse_model_content(content: str) -> dict[str, Any]:
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


def normalize_review(
    review: dict[str, Any],
    report: dict[str, Any],
    source: str,
    *,
    install_decision_fn: Callable[[int], dict[str, str]],
    agent_context_fn: Callable[[dict[str, Any]], list[str]],
) -> dict[str, Any]:
    static = install_decision_fn(int(report.get("risk_score", 0)))
    verdict = str(review.get("install_verdict") or static["verdict"])
    if verdict not in INSTALL_VERDICTS:
        verdict = static["verdict"]
    confidence = str(review.get("confidence") or ("medium" if source == "gemma" else "low"))
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "medium" if source == "gemma" else "low"
    constraints = review.get("agent_constraints")
    if not isinstance(constraints, list) or not constraints:
        constraints = agent_context_fn(report)
    normalized = {
        "summary": str(review.get("summary") or "Install posture review completed."),
        "install_verdict": verdict,
        "confidence": confidence,
        "why_gemma_changed_the_call": str(
            review.get("why_gemma_changed_the_call")
            or ("Deterministic fallback used the static install posture because the model route was unavailable." if source == "fallback" else "The reviewer kept the static posture and clarified the install constraints.")
        ),
        "agent_constraints": [str(item) for item in constraints[:12]],
        "top_risks": [str(item) for item in review.get("top_risks", [])[:8]] if isinstance(review.get("top_risks", []), list) else [],
        "quick_wins": [str(item) for item in review.get("quick_wins", [])[:8]] if isinstance(review.get("quick_wins", []), list) else [],
        "hardening_plan": [str(item) for item in review.get("hardening_plan", [])[:8]] if isinstance(review.get("hardening_plan", []), list) else [],
    }
    if not normalized["hardening_plan"]:
        normalized["hardening_plan"] = normalized["quick_wins"]
    return normalized


def reviewer_metadata(source: str, *, error: str | None = None) -> dict[str, Any]:
    backend = {
        "gemma": "openai_compatible",
        "fallback": "deterministic",
        "none": "none",
    }.get(source, source)
    model = None
    if source == "gemma":
        model = os.environ.get("GEMMA_MODEL", "google/gemma-4-31b")
    metadata: dict[str, Any] = {
        "source": source,
        "backend": backend,
        "model": model,
        "mode": "model" if source == "gemma" else "deterministic",
    }
    if error:
        metadata["error"] = error
    return metadata


def gemma_configured() -> bool:
    return bool(os.environ.get("GEMMA_API_KEY") and os.environ.get("GEMMA_BASE_URL"))


def deterministic_review(
    report: dict[str, Any],
    *,
    install_decision_fn: Callable[[int], dict[str, str]],
    agent_context_fn: Callable[[dict[str, Any]], list[str]],
) -> dict[str, Any]:
    counts = report["category_counts"]
    combined = {**counts}
    for name, count in report.get("rule_counts", {}).items():
        combined[name] = combined.get(name, 0) + count
    top = sorted(combined.items(), key=lambda item: item[1], reverse=True)[:3]
    decision = install_decision_fn(int(report.get("risk_score", 0)))
    return {
        "summary": "This local scan found agent-operating-surface signals that deserve review before broad agent automation.",
        "install_verdict": decision["verdict"],
        "confidence": "low",
        "why_gemma_changed_the_call": "Deterministic fallback used the static install posture because the model route was unavailable.",
        "agent_constraints": agent_context_fn(report),
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

"""Dependency-free local HTTP API for Agent Surface Map."""

from __future__ import annotations

import json
import os
import re
import secrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from api.scan import scan_url
from surface_map import review_report, scan, validate_install_plan

from .reports import schema_path


MAX_API_BODY = 1024 * 1024
SCHEMA_ENDPOINTS = {
    "/v1/schema/report": "report",
    "/v1/schema/policy": "policy",
    "/v1/schema/validation": "validation",
    "/v1/schema/drift": "drift",
}


class ApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def make_handler(
    *,
    allowed_roots: list[Path] | None = None,
    allow_remote_github: bool = True,
    allow_gemma: bool = False,
    api_keys: list[str] | None = None,
    rate_limit_per_minute: int = 60,
) -> type[BaseHTTPRequestHandler]:
    roots = [root.expanduser().resolve() for root in (allowed_roots or [Path.cwd()])]
    accepted_keys = [key for key in (api_keys or []) if key]
    rate_state: dict[str, list[float]] = {}

    class AgentSurfaceMapApiHandler(BaseHTTPRequestHandler):
        server_version = "AgentSurfaceMapAPI/0.1"

        def do_GET(self) -> None:
            try:
                if self.path == "/healthz":
                    self.send_json(200, {"ok": True, "service": "agent-surface-map"})
                    return
                self.enforce_request_policy()
                if self.path in SCHEMA_ENDPOINTS:
                    name = SCHEMA_ENDPOINTS[self.path]
                    schema = json.loads(schema_path(name).read_text(encoding="utf-8"))
                    self.send_json(200, schema)
                    return
                self.send_json(404, {"error": "not found"})
            except ApiError as exc:
                self.send_json(exc.status, {"error": str(exc)})
            except Exception as exc:  # noqa: BLE001 - API boundary should return JSON errors.
                self.send_json(400, {"error": str(exc)})

        def do_POST(self) -> None:
            try:
                self.enforce_request_policy()
                if self.path == "/v1/scan":
                    self.send_json(200, scan_payload(self.read_payload(), roots, allow_remote_github, allow_gemma))
                    return
                if self.path == "/v1/validate":
                    self.send_json(200, validate_payload(self.read_payload()))
                    return
                self.send_json(404, {"error": "not found"})
            except ApiError as exc:
                self.send_json(exc.status, {"error": str(exc)})
            except Exception as exc:  # noqa: BLE001 - API boundary should return JSON errors.
                self.send_json(400, {"error": str(exc)})

        def do_OPTIONS(self) -> None:
            self.send_response(204)
            self.send_header("access-control-allow-methods", "GET, POST, OPTIONS")
            self.send_header("access-control-allow-headers", "content-type")
            self.end_headers()

        def read_payload(self) -> dict[str, Any]:
            length = int(self.headers.get("content-length", "0"))
            if length <= 0:
                raise ApiError(400, "request body is required")
            if length > MAX_API_BODY:
                raise ApiError(413, "request body is too large")
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(payload, dict):
                raise ApiError(400, "request body must be a JSON object")
            return payload

        def enforce_request_policy(self) -> None:
            enforce_api_key(self.headers, accepted_keys)
            enforce_rate_limit(rate_state, client_identity(self), rate_limit_per_minute, 60)

        def send_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: Any) -> None:
            if os.environ.get("ASM_API_LOG_REQUESTS", "").lower() in {"1", "true", "yes"}:
                super().log_message(_format, *_args)

    return AgentSurfaceMapApiHandler


def scan_payload(payload: dict[str, Any], allowed_roots: list[Path], allow_remote_github: bool, allow_gemma_default: bool) -> dict[str, Any]:
    target = str(payload.get("target") or payload.get("url") or "").strip()
    if not target:
        raise ApiError(400, "target is required")
    allow_gemma = bool(payload.get("allow_gemma", allow_gemma_default))
    if is_github_url(target):
        if not allow_remote_github:
            raise ApiError(403, "remote GitHub scans are disabled")
        return scan_url(target.rstrip("/"), allow_gemma=allow_gemma)

    root = Path(target).expanduser().resolve()
    if not root.is_dir():
        raise ApiError(400, "target must be a local directory or simple GitHub repo URL")
    if not path_allowed(root, allowed_roots):
        allowed = ", ".join(str(path) for path in allowed_roots)
        raise ApiError(403, f"target is outside allowed roots: {allowed}")
    report = scan(root)
    review_report(report, allow_gemma=allow_gemma)
    return report


def validate_payload(payload: dict[str, Any]) -> dict[str, Any]:
    report = payload.get("report")
    config = payload.get("config")
    policy = payload.get("policy")
    if not isinstance(report, dict):
        raise ApiError(400, "report object is required")
    if config is None:
        raise ApiError(400, "config is required")
    if isinstance(config, str):
        config_text = config
    else:
        config_text = json.dumps(config)
    if policy is not None and not isinstance(policy, dict):
        raise ApiError(400, "policy must be an object when supplied")
    return validate_install_plan(report, config_text, team_policy=policy)


def path_allowed(path: Path, allowed_roots: list[Path]) -> bool:
    return any(path == root or root in path.parents for root in allowed_roots)


def enforce_api_key(headers: Any, accepted_keys: list[str]) -> None:
    if not accepted_keys:
        return
    supplied = api_key_from_headers(headers)
    if not supplied:
        raise ApiError(401, "API key is required")
    if not any(secrets.compare_digest(supplied, key) for key in accepted_keys):
        raise ApiError(403, "API key is not authorized")


def api_key_from_headers(headers: Any) -> str:
    auth = headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return headers.get("x-asm-api-key", "").strip()


def enforce_rate_limit(store: dict[str, list[float]], key: str, limit: int, window_seconds: int) -> None:
    if limit <= 0:
        return
    now = time.time()
    cutoff = now - window_seconds
    hits = [hit for hit in store.get(key, []) if hit > cutoff]
    if len(hits) >= limit:
        raise ApiError(429, "rate limit exceeded")
    hits.append(now)
    store[key] = hits


def client_identity(handler: BaseHTTPRequestHandler) -> str:
    forwarded = handler.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",", 1)[0].strip() or "unknown"
    return handler.client_address[0] if handler.client_address else "unknown"


def is_github_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme == "https" and parsed.netloc == "github.com" and re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?", parsed.path) is not None


def parse_allowed_roots(value: str | None) -> list[Path]:
    if not value:
        return [Path.cwd()]
    return [Path(part).expanduser() for part in value.split(os.pathsep) if part.strip()]


def parse_api_keys(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in re.split(r"[\n,]", value) if part.strip()]


def run_server(
    host: str,
    port: int,
    *,
    allowed_roots: list[Path] | None = None,
    allow_remote_github: bool = True,
    allow_gemma: bool = False,
    api_keys: list[str] | None = None,
    rate_limit_per_minute: int = 60,
) -> int:
    handler = make_handler(
        allowed_roots=allowed_roots,
        allow_remote_github=allow_remote_github,
        allow_gemma=allow_gemma,
        api_keys=api_keys,
        rate_limit_per_minute=rate_limit_per_minute,
    )
    server = ThreadingHTTPServer((host, port), handler)
    print(f"Agent Surface Map API listening on http://{host}:{server.server_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 130
    finally:
        server.server_close()
    return 0

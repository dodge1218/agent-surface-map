from __future__ import annotations

import json
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from surface_map import review_report, scan  # noqa: E402


MAX_BODY = 8192
MAX_ZIP_BYTES = 8 * 1024 * 1024
MAX_EXTRACTED_BYTES = 24 * 1024 * 1024
MAX_ARCHIVE_FILES = 800
URL_RE = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?$")
SCAN_RATE: dict[str, list[float]] = {}
GEMMA_RATE: dict[str, list[float]] = {}
GEMMA_BUDGET_PATH = Path(tempfile.gettempdir()) / "agent-surface-map-gemma-budget.json"


class PublicApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        try:
            client_ip = client_ip_from_headers(self.headers)
            enforce_rate_limit(
                SCAN_RATE,
                f"scan:{client_ip}",
                env_int("ASM_SCAN_RATE_LIMIT_PER_HOUR", 30),
                3600,
                "scan rate limit exceeded; try again later",
            )
            length = int(self.headers.get("content-length", "0"))
            if length <= 0 or length > MAX_BODY:
                raise ValueError("request body is too large")
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            url = str(payload.get("url", "")).strip().rstrip("/")
            allow_gemma, skip_reason = gemma_public_gate(client_ip)
            report = scan_url(url, allow_gemma=allow_gemma)
            if skip_reason:
                report["gemma_skip_reason"] = skip_reason
            self.send_json(200, report)
        except PublicApiError as exc:
            self.send_json(exc.status, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001
            self.send_json(400, {"error": str(exc)})

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("access-control-allow-methods", "POST, OPTIONS")
        self.send_header("access-control-allow-headers", "content-type")
        self.end_headers()

    def send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def scan_url(url: str, *, allow_gemma: bool | None = None) -> dict:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc != "github.com" or not URL_RE.match(url):
        raise ValueError("only simple public GitHub repo URLs are accepted in this demo")

    owner, repo = parsed.path.strip("/").split("/", 1)
    with tempfile.TemporaryDirectory(prefix="agent-surface-map-") as tmp:
        tmp_path = Path(tmp)
        zip_path = tmp_path / "repo.zip"
        download_github_zip(owner, repo, zip_path)
        extract_root = tmp_path / "repo"
        extract_root.mkdir()
        with zipfile.ZipFile(zip_path) as archive:
            safe_extract(archive, extract_root)
        roots = [path for path in extract_root.iterdir() if path.is_dir()]
        if not roots:
            raise ValueError("repository archive was empty")
        shutil.rmtree(roots[0] / ".git", ignore_errors=True)
        report = scan(roots[0])
        report["source_url"] = url
        report["target"] = f"{owner}/{repo}"
        review_report(report, allow_gemma=allow_gemma)
        strip_public_report(report)
        return report


def safe_extract(archive: zipfile.ZipFile, destination: Path) -> None:
    destination = destination.resolve()
    total = 0
    files = 0
    for member in archive.infolist():
        name = member.filename
        target = (destination / name).resolve()
        if not str(target).startswith(str(destination) + os.sep):
            raise ValueError("repository archive contains an unsafe path")
        if name.startswith("/") or ".." in Path(name).parts:
            raise ValueError("repository archive contains a path traversal entry")
        mode = member.external_attr >> 16
        if (mode & 0o170000) in {0o120000, 0o020000, 0o060000}:
            raise ValueError("repository archive contains an unsupported special file")
        if not member.is_dir():
            files += 1
            total += member.file_size
            if files > MAX_ARCHIVE_FILES:
                raise ValueError("repository archive has too many files for the demo scanner")
            if total > MAX_EXTRACTED_BYTES:
                raise ValueError("repository archive expands too large for the demo scanner")
    archive.extractall(destination)


def strip_public_report(report: dict) -> None:
    report.pop("gemma_prompt_preview", None)


def client_ip_from_headers(headers) -> str:
    forwarded = headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",", 1)[0].strip() or "unknown"
    return headers.get("x-real-ip", "unknown")


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except ValueError:
        return default


def enforce_rate_limit(store: dict[str, list[float]], key: str, limit: int, window_seconds: int, message: str) -> None:
    if limit <= 0:
        return
    now = time.time()
    cutoff = now - window_seconds
    hits = [hit for hit in store.get(key, []) if hit > cutoff]
    if len(hits) >= limit:
        raise PublicApiError(429, message)
    hits.append(now)
    store[key] = hits


def gemma_public_gate(client_ip: str) -> tuple[bool, str | None]:
    if os.environ.get("ASM_GEMMA_PUBLIC_ENABLED", "").lower() not in {"1", "true", "yes"}:
        return False, "public Gemma review disabled"
    if not os.environ.get("GEMMA_API_KEY") or not os.environ.get("GEMMA_BASE_URL"):
        return False, "Gemma provider not configured"
    try:
        enforce_rate_limit(
            GEMMA_RATE,
            f"gemma:{client_ip}",
            env_int("ASM_GEMMA_RATE_LIMIT_PER_HOUR", 6),
            3600,
            "Gemma review rate limit reached for this IP",
        )
    except PublicApiError as exc:
        return False, str(exc)
    allowed, reason = reserve_gemma_budget()
    return allowed, None if allowed else reason


def reserve_gemma_budget() -> tuple[bool, str]:
    estimated_cost = env_float("ASM_GEMMA_REVIEW_ESTIMATED_USD", 0.02)
    daily_cap = env_float("ASM_GEMMA_DAILY_USD_CAP", 10.0)
    today = time.strftime("%Y-%m-%d", time.gmtime())
    state = {"day": today, "estimated_usd": 0.0, "calls": 0}
    try:
        if GEMMA_BUDGET_PATH.exists():
            state = json.loads(GEMMA_BUDGET_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        state = {"day": today, "estimated_usd": 0.0, "calls": 0}
    if state.get("day") != today:
        state = {"day": today, "estimated_usd": 0.0, "calls": 0}
    next_total = float(state.get("estimated_usd", 0.0)) + estimated_cost
    if next_total > daily_cap:
        return False, "Gemma daily budget cap reached"
    state["estimated_usd"] = round(next_total, 6)
    state["calls"] = int(state.get("calls", 0)) + 1
    try:
        GEMMA_BUDGET_PATH.write_text(json.dumps(state), encoding="utf-8")
    except OSError:
        return False, "Gemma budget state unavailable"
    return True, ""


def download_github_zip(owner: str, repo: str, destination: Path) -> None:
    urls = [
        f"https://api.github.com/repos/{owner}/{repo}/zipball",
        f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/main",
        f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/master",
    ]
    errors: list[str] = []
    for url in urls:
        try:
            if destination.exists():
                destination.unlink()
            download(url, destination)
            return
        except ValueError as exc:
            errors.append(str(exc))
    raise ValueError(f"could not download repository archive: {'; '.join(errors)}")


def download(url: str, destination: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "agent-surface-map"})
    total = 0
    try:
        with urllib.request.urlopen(req, timeout=20) as response, destination.open("wb") as out:
            while True:
                chunk = response.read(1024 * 128)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ZIP_BYTES:
                    raise ValueError("repository archive is too large for the demo scanner")
                out.write(chunk)
    except urllib.error.HTTPError as exc:
        raise ValueError(f"GitHub returned HTTP {exc.code}") from exc

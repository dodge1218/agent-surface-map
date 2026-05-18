from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
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
URL_RE = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?$")


class handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("content-length", "0"))
            if length <= 0 or length > MAX_BODY:
                raise ValueError("request body is too large")
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            url = str(payload.get("url", "")).strip().rstrip("/")
            report = scan_url(url)
            self.send_json(200, report)
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


def scan_url(url: str) -> dict:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc != "github.com" or not URL_RE.match(url):
        raise ValueError("only simple public GitHub repo URLs are accepted in this demo")

    owner, repo = parsed.path.strip("/").split("/", 1)
    zip_url = f"https://api.github.com/repos/{owner}/{repo}/zipball"
    with tempfile.TemporaryDirectory(prefix="agent-surface-map-") as tmp:
        tmp_path = Path(tmp)
        zip_path = tmp_path / "repo.zip"
        download(zip_url, zip_path)
        extract_root = tmp_path / "repo"
        extract_root.mkdir()
        with zipfile.ZipFile(zip_path) as archive:
            archive.extractall(extract_root)
        roots = [path for path in extract_root.iterdir() if path.is_dir()]
        if not roots:
            raise ValueError("repository archive was empty")
        shutil.rmtree(roots[0] / ".git", ignore_errors=True)
        report = scan(roots[0])
        report["source_url"] = url
        report["target"] = f"{owner}/{repo}"
        review_report(report)
        return report


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

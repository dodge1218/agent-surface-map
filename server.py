#!/usr/bin/env python3
"""Tiny local demo server for Agent Surface Map."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from surface_map import review_report, scan


ROOT = Path(__file__).resolve().parent
PUBLIC = ROOT / "public"
MAX_BODY = 8192
URL_RE = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?$")


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(PUBLIC), **kwargs)

    def do_POST(self) -> None:
        if self.path != "/api/scan":
            self.send_error(404)
            return

        try:
            length = int(self.headers.get("content-length", "0"))
            if length <= 0 or length > MAX_BODY:
                raise ValueError("request body is too large")
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            url = str(payload.get("url", "")).strip().rstrip("/")
            report = scan_url(url)
            self.send_json(200, report)
        except Exception as exc:  # noqa: BLE001 - local demo API returns user-readable errors.
            self.send_json(400, {"error": str(exc)})

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

    with tempfile.TemporaryDirectory(prefix="agent-surface-map-") as tmp:
        destination = Path(tmp) / "repo"
        subprocess.run(
            [
                "git",
                "-c",
                "protocol.file.allow=never",
                "clone",
                "--depth",
                "1",
                "--no-tags",
                "--recurse-submodules=no",
                url,
                str(destination),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=45,
        )
        shutil.rmtree(destination / ".git", ignore_errors=True)
        report = scan(destination)
        report["source_url"] = url
        report["target"] = parsed.path.strip("/") or url
        review_report(report)
        return report


def main() -> int:
    server = ThreadingHTTPServer(("0.0.0.0", 8787), Handler)
    print("Agent Surface Map running at http://localhost:8787")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

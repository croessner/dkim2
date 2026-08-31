#!/usr/bin/env python3
"""Serve one deterministic dkim2d response and persist bounded call evidence."""

import argparse
import json
import os
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class State:
    """Own the response bytes and an atomically persisted request counter."""

    def __init__(self, response_path: str, state_path: str) -> None:
        with open(response_path, "r", encoding="utf-8") as source:
            document = json.load(source)
        self.response = json.dumps(document, separators=(",", ":")).encode("utf-8")
        self.state_path = state_path
        self.count = 0
        self.last_request_bytes = 0
        self.persist()

    def record(self, size: int) -> None:
        self.count += 1
        self.last_request_bytes = size
        self.persist()

    def persist(self) -> None:
        directory = os.path.dirname(self.state_path)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".dkim2-stub-", dir=directory)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as target:
                json.dump(
                    {"calls": self.count, "last_request_bytes": self.last_request_bytes},
                    target,
                    sort_keys=True,
                )
                target.write("\n")
            os.replace(temporary, self.state_path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


class Handler(BaseHTTPRequestHandler):
    """Expose only the process, health, and bounded evidence routes."""

    server_version = "dkim2-policy-e2e-stub/1"

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok\n")
            return
        if self.path == "/state":
            body = json.dumps({"calls": self.server.state.count}).encode("ascii")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def do_POST(self) -> None:
        if self.path != "/v1/process":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 34_000_000:
            self.send_error(400)
            return
        request = self.rfile.read(length)
        json.loads(request)
        if not self.headers.get("X-DKIM2-Capability"):
            self.send_error(401)
            return
        self.server.state.record(len(request))
        response = self.server.state.response
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--response", required=True)
    parser.add_argument("--state", required=True)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", 8080), Handler)
    server.state = State(args.response, args.state)
    server.serve_forever()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Serve deterministic dkim2d scenarios and persist bounded call evidence."""

import argparse
import json
import os
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class State:
    """Own the response bytes and an atomically persisted request counter."""

    def __init__(self, response_paths: dict[str, str], state_path: str, control_path: str) -> None:
        self.responses = {}
        for name, response_path in response_paths.items():
            with open(response_path, "r", encoding="utf-8") as source:
                document = json.load(source)
            self.responses[name] = json.dumps(document, separators=(",", ":")).encode("utf-8")
        self.state_path = state_path
        self.control_path = control_path
        self.count = 0
        self.last_request_bytes = 0
        self.last_mode = "default"
        self.persist()

    def mode(self) -> str:
        """Read one closed scenario selector from the runtime control file."""
        try:
            with open(self.control_path, "r", encoding="utf-8") as source:
                mode = json.load(source).get("mode", "default")
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return "default"
        allowed = {"default", "replayed", "two_hop", "malformed", "timeout"}
        return mode if mode in allowed else "default"

    def record(self, size: int, mode: str) -> None:
        self.count += 1
        self.last_request_bytes = size
        self.last_mode = mode
        self.persist()

    def persist(self) -> None:
        directory = os.path.dirname(self.state_path)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".dkim2-stub-", dir=directory)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as target:
                json.dump(
                    {
                        "calls": self.count,
                        "last_mode": self.last_mode,
                        "last_request_bytes": self.last_request_bytes,
                    },
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
        mode = self.server.state.mode()
        self.server.state.record(len(request), mode)
        if mode == "timeout":
            time.sleep(3)
        response = b"{" if mode == "malformed" else self.server.state.responses.get(
            mode, self.server.state.responses["default"]
        )
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
    parser.add_argument("--replayed-response", required=True)
    parser.add_argument("--two-hop-response", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--control", required=True)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", 8080), Handler)
    server.state = State(
        {
            "default": args.response,
            "replayed": args.replayed_response,
            "two_hop": args.two_hop_response,
        },
        args.state,
        args.control,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()

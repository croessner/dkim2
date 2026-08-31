#!/usr/bin/env python3
"""Capture exact Policy requests and forward controlled scenarios over verified TLS."""

import argparse
import copy
import json
import os
import socket
import ssl
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock


class State:
    """Own bounded request evidence and the runtime-only scenario control."""

    def __init__(self, state_path: str, control_path: str) -> None:
        self.state_path = state_path
        self.control_path = control_path
        self.lock = Lock()
        self.calls = 0
        self.forwarded_calls = 0
        self.last_mode = "forward"
        self.last_request = None
        self.last_upstream_status = None
        self.last_upstream_error = None
        self.last_request_id_matches = None
        self.persist()

    def mode(self) -> str:
        """Read a closed observer mode without trusting partial control writes."""
        try:
            with open(self.control_path, "r", encoding="utf-8") as source:
                mode = json.load(source).get("mode", "forward")
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return "forward"
        allowed = {"forward", "invalid_provider", "malformed_response", "timeout"}
        return mode if mode in allowed else "forward"

    def record(self, request: dict, mode: str) -> None:
        """Persist one received request without recording credentials."""
        with self.lock:
            self.calls += 1
            self.last_mode = mode
            self.last_request = copy.deepcopy(request)
            self.persist()

    def record_forward(self) -> None:
        """Count one request that reached the real Nauthilus endpoint."""
        with self.lock:
            self.forwarded_calls += 1
            self.persist()

    def record_upstream_response(
        self, status: int, body: bytes, request_id: object
    ) -> None:
        """Persist bounded status and correlation evidence without retaining successful bodies."""
        with self.lock:
            self.last_upstream_status = status
            self.last_upstream_error = (
                body[:4096].decode("utf-8", errors="replace") if status >= 400 else None
            )
            self.last_request_id_matches = False
            if status < 400:
                try:
                    response = json.loads(body)
                    self.last_request_id_matches = (
                        isinstance(request_id, str)
                        and response.get("request_id") == request_id
                    )
                except (json.JSONDecodeError, AttributeError):
                    pass
            self.persist()

    def persist(self) -> None:
        """Atomically replace bounded observer evidence."""
        directory = os.path.dirname(self.state_path)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".policy-observer-", dir=directory)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as target:
                json.dump(
                    {
                        "calls": self.calls,
                        "forwarded_calls": self.forwarded_calls,
                        "last_mode": self.last_mode,
                        "last_request": self.last_request,
                        "last_upstream_status": self.last_upstream_status,
                        "last_upstream_error": self.last_upstream_error,
                        "last_request_id_matches": self.last_request_id_matches,
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
    """Terminate test TLS, capture Policy JSON, and proxy closed fault modes."""

    server_version = "policy-e2e-observer/1"

    def do_GET(self) -> None:
        if self.path != "/healthz":
            self.send_error(404)
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok\n")

    def do_POST(self) -> None:
        if self.path != "/api/v1/policy/decisions":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 524_288:
            self.send_error(400)
            return
        raw_request = self.rfile.read(length)
        request = json.loads(raw_request)
        mode = self.server.state.mode()
        self.server.state.record(request, mode)
        if mode == "timeout":
            time.sleep(3)
            self.write_json(200, b"{}")
            return
        if mode == "malformed_response":
            self.write_json(200, b"{")
            return
        forwarded = copy.deepcopy(request)
        if mode == "invalid_provider":
            forwarded["environment"]["attributes"]["rspamd.smtp_client_ip"] = {
                "string": "invalid"
            }
        body = json.dumps(forwarded, separators=(",", ":")).encode("utf-8")
        headers = {
            "Accept": "application/json",
            "Authorization": self.headers.get("Authorization", ""),
            "Cache-Control": "no-store",
            "Content-Type": "application/json",
        }
        status, content_type, response_body = self.forward(body, headers)
        self.server.state.record_forward()
        self.server.state.record_upstream_response(
            status, response_body, request.get("request_id")
        )
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

    def forward(self, body: bytes, headers: dict[str, str]) -> tuple[int, str, bytes]:
        """Forward one request with explicit HTTP/1.1 framing over verified TLS 1.3."""
        context = ssl.create_default_context(cafile=self.server.ca_path)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        connection = context.wrap_socket(
            socket.create_connection(("nauthilus-policy", 9443), timeout=5),
            server_hostname="nauthilus-policy",
        )
        lines = [
            f"POST {self.path} HTTP/1.1",
            "Host: nauthilus-policy",
            "Connection: close",
            f"Content-Length: {len(body)}",
        ]
        lines.extend(f"{name}: {value}" for name, value in headers.items())
        connection.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body)
        chunks = []
        while True:
            chunk = connection.recv(65_536)
            if not chunk:
                break
            chunks.append(chunk)
        connection.close()
        raw_headers, separator, response_body = b"".join(chunks).partition(b"\r\n\r\n")
        if not separator:
            raise RuntimeError("upstream response has no header boundary")
        header_lines = raw_headers.decode("iso-8859-1").split("\r\n")
        status = int(header_lines[0].split(" ", 2)[1])
        response_headers = {}
        for line in header_lines[1:]:
            name, value = line.split(":", 1)
            response_headers[name.lower()] = value.strip()
        return status, response_headers.get("content-type", "application/json"), response_body

    def write_json(self, status: int, body: bytes) -> None:
        """Write one bounded synthetic JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            return

    def log_message(self, _format: str, *_args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--control", required=True)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("0.0.0.0", 9444), Handler)
    server.state = State(args.state, args.control)
    server.ca_path = args.ca
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

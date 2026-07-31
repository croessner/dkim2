#!/usr/bin/env python3
"""Provide bounded DNS, SMTP, and HTTP fault services for Linux qualification."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.server
import http.client
import json
import os
import pathlib
import signal
import socket
import struct
import subprocess
import sys
import threading
import time


def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON members before evidence projection."""
    value: dict[str, object] = {}
    for key, member in pairs:
        if key in value:
            raise ValueError("duplicate JSON member")
        value[key] = member
    return value


def stable_exim_message_projection(raw_message: bytes) -> tuple[bytes, bool]:
    """Remove only Exim's first generated Received field from a CRLF message."""
    header_block, separator, body = raw_message.partition(b"\r\n\r\n")
    if not separator:
        raise ValueError("invalid Exim message projection")
    lines = header_block.split(b"\r\n")
    name, delimiter, _ = lines[0].partition(b":") if lines else (b"", b"", b"")
    if not delimiter or not name:
        raise ValueError("invalid Exim message projection")
    if name.lower() != b"received":
        return raw_message, False
    index = 1
    while index < len(lines) and lines[index].startswith((b" ", b"\t")):
        index += 1
    stable_headers = b"\r\n".join(lines[index:])
    return stable_headers + separator + body, True


def build_proxy_record(
    route: str,
    request_body: bytes,
    response_body: bytes,
    status: int,
) -> bytes:
    """Build one independently validated content-free daemon evidence record."""
    if route not in {"process", "sign", "revise"}:
        raise ValueError("invalid daemon route")
    request_document = json.loads(request_body, object_pairs_hook=strict_object)
    response_document = json.loads(response_body, object_pairs_hook=strict_object)
    actions = response_document["actions"]
    outgoing_envelope = request_document["smtp"]
    message = request_document.get("message")
    if (
        not isinstance(actions, list)
        or not isinstance(outgoing_envelope, dict)
        or not isinstance(message, dict)
    ):
        raise ValueError("invalid daemon projection")
    fidelity = message.get("fidelity")
    encoded_message = message.get("raw_rfc5322_base64")
    if (
        not isinstance(fidelity, str)
        or not isinstance(encoded_message, str)
        or fidelity not in {"exim_local_scan_observed_crlf", "exim_transport_filter_crlf"}
    ):
        raise ValueError("invalid message projection")
    try:
        raw_message = base64.b64decode(encoded_message, validate=True)
    except (ValueError, UnicodeEncodeError):
        raise ValueError("invalid protected message encoding") from None
    if route in {"sign", "revise"}:
        if (
            status != 200
            or set(response_document)
            != {
                "actions",
                "api_version",
                "disposition",
                "draft",
                "operation",
                "result",
            }
            or response_document["api_version"] != "v1"
            or response_document["draft"] != "draft-ietf-dkim-dkim2-spec-04"
            or response_document["operation"] != route
            or response_document["result"] != "pass"
            or response_document["disposition"] != "accept"
        ):
            raise ValueError("invalid operation response")
        expected_names = (
            ["Message-Instance", "DKIM2-Signature"]
            if route == "sign"
            else ["DKIM2-Signature"]
            if len(actions) == 1
            else ["Message-Instance", "DKIM2-Signature"]
        )
        if len(actions) != len(expected_names):
            raise ValueError("invalid operation action count")
        for action, expected_name in zip(actions, expected_names, strict=True):
            if (
                not isinstance(action, dict)
                or set(action) != {"type", "name", "value"}
                or action["type"] != "add_header"
                or action["name"] != expected_name
                or not isinstance(action["value"], str)
                or not 1 <= len(action["value"]) <= 65535
                or any(character in action["value"] for character in "\r\n\x00")
            ):
                raise ValueError("invalid operation action plan")
        authorized_fields = "".join(
            f"{action['name']}:{action['value']}\n" for action in actions
        ).encode("utf-8")
    else:
        authorized_fields = b""
    canonical_actions = json.dumps(
        actions, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    canonical_outgoing = json.dumps(
        outgoing_envelope,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    canonical_reverse = json.dumps(
        outgoing_envelope.get("mail_from"),
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    canonical_recipients = json.dumps(
        outgoing_envelope.get("rcpt_to"),
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    fields = [
        f"route={route}",
        f"request_sha256={hashlib.sha256(request_body).hexdigest()}",
        f"response_sha256={hashlib.sha256(response_body).hexdigest()}",
        f"action_plan_sha256={hashlib.sha256(canonical_actions).hexdigest()}",
        (
            "authorized_fields_sha256="
            f"{hashlib.sha256(authorized_fields).hexdigest()}"
        ),
        f"actions={len(actions)}",
        f"message_fidelity={fidelity}",
        f"message_raw_sha256={hashlib.sha256(raw_message).hexdigest()}",
        (
            "outgoing_envelope_sha256="
            f"{hashlib.sha256(canonical_outgoing).hexdigest()}"
        ),
        f"outgoing_reverse_sha256={hashlib.sha256(canonical_reverse).hexdigest()}",
        (
            "outgoing_recipients_sha256="
            f"{hashlib.sha256(canonical_recipients).hexdigest()}"
        ),
    ]
    if route == "process":
        stable_message, first_header_received = stable_exim_message_projection(
            raw_message
        )
        fields.extend(
            (
                "message_stable_sha256="
                f"{hashlib.sha256(stable_message).hexdigest()}",
                f"message_first_header_received={int(first_header_received)}",
            )
        )
    if route == "revise":
        incoming_envelope = request_document["incoming_smtp"]
        if not isinstance(incoming_envelope, dict):
            raise ValueError("invalid incoming envelope projection")
        canonical_incoming = json.dumps(
            incoming_envelope,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        fields.append(
            "incoming_envelope_sha256="
            f"{hashlib.sha256(canonical_incoming).hexdigest()}"
        )
    fields.append(f"status={status}")
    return (" ".join(fields) + "\n").encode("ascii")


def append_fsynced(path: pathlib.Path, record: bytes) -> None:
    """Append one complete evidence record durably before response exposure."""
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "ab", closefd=False) as destination:
            destination.write(record)
            destination.flush()
            os.fsync(destination.fileno())
    finally:
        os.close(descriptor)


def invalid_proxy_projection(
    route: str, request_body: bytes, response_body: bytes, status: int
) -> bytes:
    """Build a content-free diagnostic record for one rejected proxy response."""
    try:
        response = json.loads(response_body, object_pairs_hook=strict_object)
    except (TypeError, ValueError, json.JSONDecodeError):
        return f"route={route} projection=invalid status={status} json=invalid\n".encode(
            "ascii"
        )
    actions = response.get("actions") if isinstance(response, dict) else None
    action_count = len(actions) if isinstance(actions, list) else -1
    operation = response.get("operation") if isinstance(response, dict) else None
    result = response.get("result") if isinstance(response, dict) else None
    disposition = response.get("disposition") if isinstance(response, dict) else None
    if operation not in {"process", "sign", "revise"}:
        operation = "invalid"
    if result not in {"pass", "fail", "permerror", "temperror"}:
        result = "invalid"
    if disposition not in {"accept", "continue", "reject", "tempfail"}:
        disposition = "invalid"
    if route != "revise":
        return (
            f"route={route} projection=invalid status={status} operation={operation} "
            f"result={result} disposition={disposition} actions={action_count}\n"
        ).encode("ascii")
    try:
        request = json.loads(request_body, object_pairs_hook=strict_object)
        incoming = json.dumps(
            request["incoming_smtp"], sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        outgoing = json.dumps(
            request["smtp"], sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        incoming_reverse = json.dumps(
            request["incoming_smtp"]["mail_from"], separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        outgoing_reverse = json.dumps(
            request["smtp"]["mail_from"], separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        incoming_recipients = json.dumps(
            request["incoming_smtp"]["rcpt_to"], separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        outgoing_recipients = json.dumps(
            request["smtp"]["rcpt_to"], separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return b"route=revise projection=invalid request=invalid\n"
    return (
        f"route=revise projection=invalid status={status} operation={operation} "
        f"result={result} disposition={disposition} actions={action_count} "
        f"incoming_envelope_sha256={hashlib.sha256(incoming).hexdigest()} "
        f"outgoing_envelope_sha256={hashlib.sha256(outgoing).hexdigest()} "
        f"incoming_reverse_sha256={hashlib.sha256(incoming_reverse).hexdigest()} "
        f"outgoing_reverse_sha256={hashlib.sha256(outgoing_reverse).hexdigest()} "
        f"incoming_recipients_sha256={hashlib.sha256(incoming_recipients).hexdigest()} "
        f"outgoing_recipients_sha256={hashlib.sha256(outgoing_recipients).hexdigest()}\n"
    ).encode("ascii")


def read_dns_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Decode one uncompressed bounded DNS question name."""
    labels: list[str] = []
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[offset]
        offset += 1
        if length == 0:
            return ".".join(labels).lower() + ".", offset
        if length > 63 or offset + length > len(packet):
            raise ValueError("invalid DNS label")
        label = packet[offset : offset + length]
        if any(value < 0x21 or value > 0x7E for value in label):
            raise ValueError("invalid DNS label byte")
        labels.append(label.decode("ascii"))
        offset += length


def dns_txt_rdata(value: bytes) -> bytes:
    """Encode one TXT answer as bounded concatenated character strings."""
    chunks = [value[index : index + 255] for index in range(0, len(value), 255)]
    if not chunks:
        chunks = [b""]
    return b"".join(bytes([len(chunk)]) + chunk for chunk in chunks)


def run_dns(address: str, port: int, records_path: pathlib.Path) -> None:
    """Serve exact TXT records from a root-owned line-oriented fixture."""
    records: dict[str, bytes] = {}
    for raw_line in records_path.read_bytes().splitlines():
        owner, separator, value = raw_line.partition(b"=")
        if not separator or not owner or not value:
            raise ValueError("invalid DNS record fixture")
        canonical = owner.decode("ascii").lower()
        if not canonical.endswith(".") or canonical in records:
            raise ValueError("invalid DNS record owner")
        records[canonical] = value
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((address, port))
    while True:
        packet, peer = server.recvfrom(4096)
        try:
            if len(packet) < 12:
                continue
            identifier = packet[:2]
            owner, question_end = read_dns_name(packet, 12)
            if question_end + 4 != len(packet):
                continue
            query_type, query_class = struct.unpack("!HH", packet[question_end:])
            question = packet[12:]
            value = records.get(owner)
            if query_type != 16 or query_class != 1 or value is None:
                response = identifier + b"\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00"
                response += question
            else:
                rdata = dns_txt_rdata(value)
                response = identifier + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
                response += question
                response += b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x1e"
                response += struct.pack("!H", len(rdata)) + rdata
            server.sendto(response, peer)
        except (UnicodeDecodeError, ValueError):
            continue


def smtp_reply(stream: socket.SocketIO, line: bytes) -> None:
    """Write one complete SMTP reply and flush it."""
    stream.write(line + b"\r\n")
    stream.flush()


def read_smtp_reply(stream: socket.SocketIO) -> bytes:
    """Read one bounded complete SMTP reply."""
    lines = bytearray()
    code: bytes | None = None
    for _ in range(100):
        line = stream.readline(8192)
        if not line or len(line) > 8192 or not line.endswith(b"\r\n"):
            raise ValueError("invalid SMTP reply")
        if len(line) < 5 or not line[:3].isdigit() or line[3:4] not in {b"-", b" "}:
            raise ValueError("invalid SMTP reply grammar")
        if code is None:
            code = line[:3]
        if line[:3] != code:
            raise ValueError("inconsistent SMTP reply")
        lines.extend(line)
        if line[3:4] == b" ":
            return bytes(lines)
    raise ValueError("overlong SMTP reply")


def encode_smtp_data(message: bytes, wire_format: str) -> bytes:
    """Convert one exact RFC 5322 representation to dot-stuffed SMTP DATA."""
    if wire_format == "lf":
        if b"\r" in message:
            raise ValueError("LF message contains CR")
        message_crlf = message.replace(b"\n", b"\r\n")
    elif wire_format == "crlf":
        if b"\n" in message.replace(b"\r\n", b"") or b"\r" in message.replace(
            b"\r\n", b""
        ):
            raise ValueError("CRLF message contains bare newline")
        message_crlf = message
    else:
        raise ValueError("invalid SMTP message wire format")
    if not message_crlf.endswith(b"\r\n"):
        message_crlf += b"\r\n"
    lines = message_crlf.split(b"\r\n")
    encoded = b"\r\n".join(
        (b"." + line) if line.startswith(b".") else line for line in lines
    )
    return encoded


def require_smtp_code(reply: bytes, expected: bytes) -> None:
    """Require one exact SMTP phase status code."""
    if len(expected) != 3 or not reply.startswith(expected):
        raise ValueError("unexpected SMTP phase status")


def require_smtp_utf8_capabilities(reply: bytes) -> None:
    """Require distinct SMTPUTF8 and 8BITMIME EHLO capabilities."""
    capabilities = {
        line[4:].split(None, 1)[0].upper()
        for line in reply.splitlines()
        if len(line) >= 4 and line[:3] == b"250"
    }
    if b"SMTPUTF8" not in capabilities or b"8BITMIME" not in capabilities:
        raise ValueError("SMTPUTF8 capabilities unavailable")


def run_smtp_client(
    address: str,
    port: int,
    sender: str,
    recipient: str,
    message: pathlib.Path,
    wire_format: str,
    smtp_utf8: bool,
    output: pathlib.Path,
) -> None:
    """Submit one binary-safe message and retain only server replies."""
    mail = message.read_bytes()
    data = encode_smtp_data(mail, wire_format)
    connection = socket.create_connection((address, port), timeout=20)
    connection.settimeout(20)
    stream = connection.makefile("rwb", buffering=0)
    reply = read_smtp_reply(stream)
    require_smtp_code(reply, b"220")
    transcript = bytearray(reply)
    stream.write(b"EHLO matrix.example.test\r\n")
    reply = read_smtp_reply(stream)
    require_smtp_code(reply, b"250")
    if smtp_utf8:
        require_smtp_utf8_capabilities(reply)
    transcript.extend(reply)
    mail_command = f"MAIL FROM:<{sender}>".encode("utf-8")
    if smtp_utf8:
        mail_command += b" SMTPUTF8"
    stream.write(mail_command + b"\r\n")
    reply = read_smtp_reply(stream)
    require_smtp_code(reply, b"250")
    transcript.extend(reply)
    stream.write(f"RCPT TO:<{recipient}>\r\n".encode("utf-8"))
    reply = read_smtp_reply(stream)
    require_smtp_code(reply, b"250")
    transcript.extend(reply)
    stream.write(b"DATA\r\n")
    reply = read_smtp_reply(stream)
    require_smtp_code(reply, b"354")
    transcript.extend(reply)
    stream.write(data + b".\r\n")
    reply = read_smtp_reply(stream)
    require_smtp_code(reply, b"250")
    transcript.extend(reply)
    stream.write(b"QUIT\r\n")
    reply = read_smtp_reply(stream)
    require_smtp_code(reply, b"221")
    transcript.extend(reply)
    stream.close()
    connection.close()
    write_fresh(output, bytes(transcript))


def run_smtp(
    address: str,
    port: int,
    output: pathlib.Path,
    ready_output: pathlib.Path,
    count: int,
) -> None:
    """Capture exactly the requested number of SMTP deliveries."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((address, port))
    server.listen(4)
    write_fresh(ready_output, b"ready\n")
    captures: list[bytes] = []
    while len(captures) < count:
        connection, _ = server.accept()
        connection.settimeout(20)
        stream = connection.makefile("rwb", buffering=0)
        smtp_reply(stream, b"220 qualification ESMTP")
        envelope = bytearray()
        message = bytearray()
        in_data = False
        while True:
            line = stream.readline(1 << 20)
            if not line:
                break
            if in_data:
                if line == b".\r\n":
                    smtp_reply(stream, b"250 accepted")
                    captures.append(bytes(envelope) + bytes(message))
                    in_data = False
                    continue
                if line.startswith(b".."):
                    line = line[1:]
                message.extend(line)
                continue
            upper = line.upper()
            if upper.startswith((b"EHLO ", b"HELO ")):
                smtp_reply(stream, b"250 qualification")
            elif upper.startswith(b"MAIL FROM:"):
                envelope.extend(line)
                smtp_reply(stream, b"250 accepted")
            elif upper.startswith(b"RCPT TO:"):
                envelope.extend(line)
                smtp_reply(stream, b"250 accepted")
            elif upper == b"DATA\r\n":
                smtp_reply(stream, b"354 continue")
                in_data = True
            elif upper == b"RSET\r\n":
                envelope.clear()
                message.clear()
                smtp_reply(stream, b"250 reset")
            elif upper == b"QUIT\r\n":
                smtp_reply(stream, b"221 closing")
                break
            else:
                smtp_reply(stream, b"250 accepted")
        stream.close()
        connection.close()
    with output.open("wb") as destination:
        for capture in captures:
            destination.write(struct.pack("!Q", len(capture)))
            destination.write(capture)
    server.close()


def run_smtp_abort_peer(
    address: str,
    port: int,
    output: pathlib.Path,
    ready_output: pathlib.Path,
) -> None:
    """Measure one SMTP transport that aborts before message completion."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((address, port))
    server.listen(1)
    write_fresh(ready_output, b"ready\n")
    ehlo_count = 0
    mail_count = 0
    recipient_count = 0
    data_count = 0
    delivery_count = 0
    connection, _ = server.accept()
    try:
        connection.settimeout(20)
        stream = connection.makefile("rwb", buffering=0)
        try:
            smtp_reply(stream, b"220 qualification ESMTP")
            in_data = False
            data_octets = 0
            for _ in range(64):
                line = stream.readline(1 << 20)
                if not line:
                    break
                if len(line) >= 1 << 20 or not line.endswith(b"\r\n"):
                    raise ValueError("invalid SMTP abort-peer line")
                if in_data:
                    if line == b".\r\n":
                        delivery_count += 1
                        in_data = False
                        smtp_reply(stream, b"250 accepted")
                        continue
                    data_octets += len(line)
                    if data_octets > 64 * 1024 * 1024:
                        raise ValueError("oversized SMTP abort-peer data")
                    continue
                upper = line.upper()
                if upper.startswith((b"EHLO ", b"HELO ")):
                    ehlo_count += 1
                    stream.write(
                        b"250-qualification\r\n"
                        b"250-8BITMIME\r\n"
                        b"250 SMTPUTF8\r\n"
                    )
                    stream.flush()
                elif upper.startswith(b"MAIL FROM:"):
                    mail_count += 1
                    smtp_reply(stream, b"250 accepted")
                elif upper.startswith(b"RCPT TO:"):
                    recipient_count += 1
                    smtp_reply(stream, b"250 accepted")
                elif upper == b"DATA\r\n":
                    data_count += 1
                    in_data = True
                    smtp_reply(stream, b"354 continue")
                elif upper == b"RSET\r\n":
                    in_data = False
                    data_octets = 0
                    smtp_reply(stream, b"250 reset")
                elif upper == b"QUIT\r\n":
                    smtp_reply(stream, b"221 closing")
                    break
                else:
                    smtp_reply(stream, b"250 accepted")
            else:
                raise ValueError("overlong SMTP abort-peer conversation")
        finally:
            stream.close()
    finally:
        connection.close()
        server.close()
    if ehlo_count != 1:
        raise ValueError("SMTP abort peer requires exactly one greeting")
    measurement = (
        "format=dkim2-exim-smtp-abort-v1\n"
        "connections=1\n"
        f"ehlo={ehlo_count}\n"
        f"mail={mail_count}\n"
        f"rcpt={recipient_count}\n"
        f"data={data_count}\n"
        f"deliveries={delivery_count}\n"
    ).encode("ascii")
    write_fresh(output, measurement)


def inspect_capture_set(capture: pathlib.Path, metadata_output: pathlib.Path) -> None:
    """Measure every framed SMTP delivery without retaining message content."""
    encoded = capture.read_bytes()
    offset = 0
    delivery_count = 0
    recipient_counts: list[int] = []
    bcc_count = 0
    payload_hashes = bytearray()
    while offset < len(encoded):
        if len(encoded) - offset < 8:
            raise ValueError("truncated SMTP capture set")
        payload_length = struct.unpack("!Q", encoded[offset : offset + 8])[0]
        offset += 8
        if payload_length > len(encoded) - offset:
            raise ValueError("invalid SMTP capture set length")
        payload = encoded[offset : offset + payload_length]
        offset += payload_length
        lines = payload.splitlines(keepends=True)
        if not lines or not lines[0].upper().startswith(b"MAIL FROM:"):
            raise ValueError("SMTP capture set omits MAIL FROM")
        index = 1
        recipients = 0
        while index < len(lines) and lines[index].upper().startswith(b"RCPT TO:"):
            recipients += 1
            index += 1
        if recipients == 0:
            raise ValueError("SMTP capture set omits recipients")
        header_block, separator, _ = b"".join(lines[index:]).partition(b"\r\n\r\n")
        if not separator:
            raise ValueError("SMTP capture set has no header boundary")
        bcc_count += sum(
            1
            for line in header_block.split(b"\r\n")
            if line.lower().startswith(b"bcc:")
        )
        recipient_counts.append(recipients)
        payload_hashes.extend(hashlib.sha256(payload).digest())
        delivery_count += 1
    if delivery_count == 0:
        raise ValueError("empty SMTP capture set")
    metadata = (
        "format=dkim2-exim-capture-set-v1\n"
        f"delivery_count={delivery_count}\n"
        f"minimum_recipient_count={min(recipient_counts)}\n"
        f"maximum_recipient_count={max(recipient_counts)}\n"
        f"bcc_marker_count={bcc_count}\n"
        f"payload_set_sha256={hashlib.sha256(payload_hashes).hexdigest()}\n"
    ).encode("ascii")
    write_fresh(metadata_output, metadata)


def run_filter_fault(
    mode: str, result_output: pathlib.Path, command: list[str]
) -> int:
    """Run the real filter, then inject a bounded output/exit fault."""
    if not command or not pathlib.Path(command[0]).is_absolute():
        raise ValueError("filter fault command is not absolute")
    completed = subprocess.run(
        command,
        stdin=sys.stdin.buffer,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if completed.returncode != 0 or not completed.stdout:
        raise ValueError("real filter did not produce successful output")
    if mode == "partial":
        prefix_length = min(64, len(completed.stdout) - 1)
        if prefix_length <= 0:
            raise ValueError("real filter output is too short")
        sys.stdout.buffer.write(completed.stdout[:prefix_length])
        sys.stdout.buffer.flush()
    else:
        prefix_length = 0
    write_fresh(
        result_output,
        f"mode={mode}\nchild_exit=0\noutput_bytes={prefix_length}\n".encode("ascii"),
    )
    return 75


class FaultHandler(http.server.BaseHTTPRequestHandler):
    """Return one bounded configured fault for adapter error-path qualification."""

    protocol_version = "HTTP/1.1"
    mode = "malformed"
    output: pathlib.Path | None = None
    output_lock = threading.Lock()

    def do_POST(self) -> None:
        """Consume a bounded request and return the selected route fault."""
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > 64 * 1024 * 1024:
            self.send_error(413)
            return
        remaining = length
        while remaining:
            chunk = self.rfile.read(min(remaining, 64 * 1024))
            if not chunk:
                return
            remaining -= len(chunk)
        if self.output is not None:
            with self.output_lock:
                append_fsynced(self.output, f"mode={self.mode} calls=1\n".encode("ascii"))
        if self.mode == "close":
            self.connection.close()
            return
        if self.mode == "timeout":
            time.sleep(15)
            return
        if self.mode == "malformed":
            body = b"{"
        elif self.mode == "overflow":
            body = b"{" + (b"x" * (17 * 1024 * 1024))
        elif self.mode == "partial":
            self.connection.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{"
            )
            self.connection.close()
            return
        else:
            self.send_error(500)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        """Suppress request data and ambient peer identifiers."""


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    """Forward bounded daemon requests and retain only sanitized digests."""

    protocol_version = "HTTP/1.1"
    target_address = "127.0.0.1"
    target_port = 18080
    output = pathlib.Path("/dev/null")
    output_lock = threading.Lock()

    def do_POST(self) -> None:
        """Forward one exact POST while binding request and response digests."""
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > 64 * 1024 * 1024:
            self.send_error(413)
            return
        body = self.rfile.read(length)
        if len(body) != length:
            return
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in {"connection", "content-length", "host"}
        }
        connection = http.client.HTTPConnection(
            self.target_address, self.target_port, timeout=10
        )
        connection.request("POST", self.path, body=body, headers=headers)
        response = connection.getresponse()
        response_body = response.read(64 * 1024 * 1024 + 1)
        if len(response_body) > 64 * 1024 * 1024:
            connection.close()
            self.send_error(502)
            return
        try:
            route = self.path.removeprefix("/v1/")
            record = build_proxy_record(route, body, response_body, response.status)
        except (
            KeyError,
            TypeError,
            UnicodeEncodeError,
            ValueError,
            json.JSONDecodeError,
        ):
            append_fsynced(
                self.output,
                invalid_proxy_projection(route, body, response_body, response.status),
            )
            connection.close()
            self.send_error(502)
            return
        with self.output_lock:
            append_fsynced(self.output, record)
        self.send_response(response.status)
        for key, value in response.getheaders():
            if key.lower() not in {
                "connection",
                "content-length",
                "transfer-encoding",
            }:
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)
        self.wfile.flush()
        connection.close()

    def log_message(self, _format: str, *_args: object) -> None:
        """Suppress request data and ambient peer identifiers."""


def run_http(
    address: str, port: int, mode: str, output: pathlib.Path | None
) -> None:
    """Serve one closed fault mode without emitting request material."""
    FaultHandler.mode = mode
    FaultHandler.output = output
    server = http.server.ThreadingHTTPServer((address, port), FaultHandler)
    server.serve_forever()


def run_proxy(
    address: str,
    port: int,
    target_address: str,
    target_port: int,
    output: pathlib.Path,
) -> None:
    """Run one bounded digesting HTTP proxy to the real daemon."""
    ProxyHandler.target_address = target_address
    ProxyHandler.target_port = target_port
    ProxyHandler.output = output
    server = http.server.ThreadingHTTPServer((address, port), ProxyHandler)
    server.serve_forever()


def run_unixgram(path: pathlib.Path, output: pathlib.Path, count: int) -> None:
    """Capture exactly the requested number of bounded adapter result events."""
    if path.exists() or path.is_symlink():
        raise ValueError("Unix datagram path is not fresh")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server.bind(str(path))
    path.chmod(0o600)
    records: list[bytes] = []
    while len(records) < count:
        record = server.recv(4096)
        if not record or len(record) == 4096:
            raise ValueError("invalid Unix datagram record")
        records.append(record)
    output.write_bytes(b"\n".join(records) + b"\n")


def run_local_scan_fault(
    path: pathlib.Path,
    ready_output: pathlib.Path,
    result_output: pathlib.Path,
    mode: str,
) -> None:
    """Fault one real local_scan caller after authenticating its Linux peer PID."""
    if not hasattr(socket, "SO_PEERCRED"):
        raise ValueError("local-scan fault peer requires Linux SO_PEERCRED")
    if path.exists() or path.is_symlink():
        raise ValueError("local-scan fault socket path is not fresh")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(path))
        path.chmod(0o600)
        server.listen(1)
        write_fresh(ready_output, b"ready\n")
        connection, _ = server.accept()
        try:
            credentials = connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
            peer_pid, peer_uid, _ = struct.unpack("3i", credentials)
            if peer_pid <= 1 or peer_uid != os.geteuid():
                raise ValueError("local-scan fault peer identity changed")
            connection.settimeout(10)
            if not connection.recv(1):
                raise ValueError("local-scan fault peer sent no request")
            write_fresh(
                result_output,
                f"mode={mode}\npeer_uid_match=1\nrequest_observed=1\n".encode("ascii"),
            )
            if mode == "timeout":
                time.sleep(15)
            elif mode == "crash":
                os.kill(peer_pid, signal.SIGSEGV)
            elif mode == "close":
                pass
            else:
                raise ValueError("unknown local-scan fault mode")
        finally:
            connection.close()
    finally:
        server.close()
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def mutate_evidence_record(
    record: pathlib.Path, key_file: pathlib.Path, mode: str
) -> None:
    """Apply one same-inode evidence expiry or integrity fault for readback."""
    raw = bytearray(record.read_bytes())
    key = key_file.read_bytes()
    if len(raw) < 79 or raw[:4] != b"DXE1" or len(key) != 32:
        raise ValueError("invalid evidence fault input")
    if mode == "expired":
        raw[6:14] = struct.pack("!Q", 1)
        raw[14:22] = struct.pack("!Q", 2)
        raw[-32:] = hmac.new(key, raw[:-32], hashlib.sha256).digest()
    elif mode == "tampered":
        raw[22] ^= 1
    else:
        raise ValueError("unknown evidence fault mode")
    descriptor = os.open(record, os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.pwrite(descriptor, raw, 0)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_fresh(path: pathlib.Path, data: bytes) -> None:
    """Write one fresh owner-only helper artifact completely."""
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as destination:
            destination.write(data)
            destination.flush()
            os.fsync(destination.fileno())
    finally:
        os.close(descriptor)


def inspect_message(message: pathlib.Path, wire_format: str, metadata_output: pathlib.Path) -> None:
    """Measure bounded RFC 5322 fixture bytes without retaining their content."""
    raw = message.read_bytes()
    if len(raw) > 64 * 1024 * 1024:
        raise ValueError("SMTP message exceeds the inspection bound")
    canonical = encode_smtp_data(raw, wire_format)
    if not canonical.endswith(b"\r\n"):
        raise ValueError("canonical SMTP message has no final CRLF")
    header_block, separator, body = canonical.partition(b"\r\n\r\n")
    if not separator:
        raise ValueError("SMTP message has no header boundary")
    header_lines = header_block.split(b"\r\n")
    header_names: list[bytes] = []
    duplicate_count = 0
    folded_count = 0
    x_duplicate_folded_count = 0
    current_name = b""
    for line in header_lines:
        if line.startswith((b" ", b"\t")):
            folded_count += 1
            if current_name == b"x-duplicate":
                x_duplicate_folded_count += 1
            continue
        name, delimiter, _ = line.partition(b":")
        if not delimiter or not name:
            raise ValueError("SMTP message has malformed header")
        current_name = name.lower()
        header_names.append(current_name)
    if header_names:
        duplicate_count = max(header_names.count(name) for name in set(header_names))
    authentication_results_count = header_names.count(b"authentication-results")
    first_header = header_names[0].decode("ascii") if header_names else "none"
    stable, first_header_received = stable_exim_message_projection(canonical)
    raw_lf_count = raw.count(b"\n")
    raw_crlf_count = raw.count(b"\r\n")
    raw_bare_lf_count = raw_lf_count - raw_crlf_count
    metadata = (
        "format=dkim2-exim-message-inspection-v1\n"
        f"raw_sha256={hashlib.sha256(raw).hexdigest()}\n"
        f"canonical_sha256={hashlib.sha256(canonical).hexdigest()}\n"
        f"stable_sha256={hashlib.sha256(stable).hexdigest()}\n"
        f"body_sha256={hashlib.sha256(body).hexdigest()}\n"
        f"header_order_sha256={hashlib.sha256(b'\\n'.join(header_names) + b'\\n').hexdigest()}\n"
        f"raw_lf_count={raw_lf_count}\n"
        f"raw_crlf_count={raw_crlf_count}\n"
        f"raw_bare_lf_count={raw_bare_lf_count}\n"
        f"duplicate_count={duplicate_count}\n"
        f"folded_count={folded_count}\n"
        f"x_duplicate_count={header_names.count(b'x-duplicate')}\n"
        f"x_duplicate_folded_count={x_duplicate_folded_count}\n"
        f"authentication_results_count={authentication_results_count}\n"
        f"first_header={first_header}\n"
        f"first_header_received={int(first_header_received)}\n"
        f"nul_count={body.count(b'\x00')}\n"
        f"nonascii_octets={sum(value >= 0x80 for value in raw)}\n"
    ).encode("ascii")
    write_fresh(metadata_output, metadata)


def run_unpack(
    capture: pathlib.Path,
    message_output: pathlib.Path,
    metadata_output: pathlib.Path,
    require_owned_fields: bool = False,
) -> None:
    """Validate one framed SMTP capture and recover exact RFC 5322 wire bytes."""
    encoded = capture.read_bytes()
    if len(encoded) < 8:
        raise ValueError("truncated SMTP capture")
    payload_length = struct.unpack("!Q", encoded[:8])[0]
    payload = encoded[8:]
    if payload_length != len(payload):
        raise ValueError("SMTP capture length mismatch")
    lines = payload.splitlines(keepends=True)
    if not lines or not lines[0].upper().startswith(b"MAIL FROM:"):
        raise ValueError("SMTP capture omits MAIL FROM")
    envelope_lines = [lines[0]]
    index = 1
    while index < len(lines) and lines[index].upper().startswith(b"RCPT TO:"):
        envelope_lines.append(lines[index])
        index += 1
    if len(envelope_lines) < 2:
        raise ValueError("SMTP capture omits recipients")
    message_crlf = b"".join(lines[index:])
    if not message_crlf or b"\n" in message_crlf.replace(b"\r\n", b""):
        raise ValueError("SMTP message contains bare LF")
    if b"\r" in message_crlf.replace(b"\r\n", b""):
        raise ValueError("SMTP message contains bare CR")
    header_block, separator, _ = message_crlf.partition(b"\r\n\r\n")
    if not separator:
        raise ValueError("SMTP message has no header boundary")
    header_names: list[bytes] = []
    header_fields: list[bytearray] = []
    bcc_count = 0
    for line in header_block.split(b"\r\n"):
        if line.startswith((b" ", b"\t")):
            if not header_fields:
                raise ValueError("SMTP message starts with continuation")
            header_fields[-1].extend(b"\n" + line)
            continue
        name, delimiter, _ = line.partition(b":")
        if not delimiter or not name:
            raise ValueError("SMTP message has malformed header")
        canonical_name = name.lower()
        if any(value < 0x21 or value > 0x7E for value in canonical_name):
            raise ValueError("SMTP message has non-ASCII field name")
        header_names.append(canonical_name)
        header_fields.append(bytearray(line))
        if canonical_name == b"bcc":
            bcc_count += 1
    message_lf = message_crlf.replace(b"\r\n", b"\n")
    envelope = b"".join(envelope_lines)
    header_order = b"\n".join(header_names) + b"\n"
    owned_indexes = [
        index
        for index, name in enumerate(header_names)
        if name in {b"message-instance", b"dkim2-signature"}
    ]
    owned_names = [header_names[index] for index in owned_indexes]
    owned_sequence = b",".join(owned_names).decode("ascii")
    owned_fields = [
        bytes(field) + b"\n"
        for name, field in zip(header_names, header_fields, strict=True)
        if name in {b"message-instance", b"dkim2-signature"}
    ]
    if require_owned_fields and len(owned_fields) < 2:
        raise ValueError("SMTP message omits required owned fields")
    first_owned_fields = b"".join(owned_fields[:2])
    new_owned_fields = b"".join(owned_fields[-2:])
    last_owned_field = owned_fields[-1] if owned_fields else b""
    metadata = (
        "format=dkim2-exim-capture-inspection-v1\n"
        f"wire_sha256={hashlib.sha256(encoded).hexdigest()}\n"
        f"envelope_sha256={hashlib.sha256(envelope).hexdigest()}\n"
        f"message_lf_sha256={hashlib.sha256(message_lf).hexdigest()}\n"
        f"header_order_sha256={hashlib.sha256(header_order).hexdigest()}\n"
        f"header_field_count={len(header_names)}\n"
        f"owned_field_indexes={','.join(str(index) for index in owned_indexes)}\n"
        f"owned_field_sequence={owned_sequence}\n"
        f"owned_field_count={len(owned_fields)}\n"
        f"first_owned_fields_sha256={hashlib.sha256(first_owned_fields).hexdigest()}\n"
        f"new_owned_fields_sha256={hashlib.sha256(new_owned_fields).hexdigest()}\n"
        f"last_owned_field_sha256={hashlib.sha256(last_owned_field).hexdigest()}\n"
        f"recipient_count={len(envelope_lines) - 1}\n"
        f"bcc_marker_count={bcc_count}\n"
    ).encode("ascii")
    write_fresh(message_output, message_crlf)
    write_fresh(metadata_output, metadata)


def parse_arguments() -> argparse.Namespace:
    """Parse one closed qualification-helper command surface."""
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    dns = subparsers.add_parser("dns")
    dns.add_argument("--address", default="127.0.0.55")
    dns.add_argument("--port", type=int, default=53)
    dns.add_argument("--records", type=pathlib.Path, required=True)
    smtp = subparsers.add_parser("smtp")
    smtp.add_argument("--address", default="127.0.0.1")
    smtp.add_argument("--port", type=int, default=2526)
    smtp.add_argument("--output", type=pathlib.Path, required=True)
    smtp.add_argument("--ready-output", type=pathlib.Path, required=True)
    smtp.add_argument("--count", type=int, required=True)
    smtp_abort = subparsers.add_parser("smtp-abort")
    smtp_abort.add_argument("--address", default="127.0.0.1")
    smtp_abort.add_argument("--port", type=int, default=2526)
    smtp_abort.add_argument("--output", type=pathlib.Path, required=True)
    smtp_abort.add_argument("--ready-output", type=pathlib.Path, required=True)
    smtp_client = subparsers.add_parser("smtp-client")
    smtp_client.add_argument("--address", default="127.0.0.1")
    smtp_client.add_argument("--port", type=int, default=2525)
    smtp_client.add_argument("--sender", required=True)
    smtp_client.add_argument("--recipient", required=True)
    smtp_client.add_argument("--message", type=pathlib.Path, required=True)
    smtp_client.add_argument("--wire-format", choices=("lf", "crlf"), required=True)
    smtp_client.add_argument("--smtp-utf8", action="store_true")
    smtp_client.add_argument("--output", type=pathlib.Path, required=True)
    inspect = subparsers.add_parser("inspect-message")
    inspect.add_argument("--message", type=pathlib.Path, required=True)
    inspect.add_argument("--wire-format", choices=("lf", "crlf"), required=True)
    inspect.add_argument("--metadata-output", type=pathlib.Path, required=True)
    http = subparsers.add_parser("http")
    http.add_argument("--address", default="127.0.0.1")
    http.add_argument("--port", type=int, default=18081)
    http.add_argument(
        "--mode",
        choices=("timeout", "malformed", "overflow", "partial", "close"),
        required=True,
    )
    http.add_argument("--output", type=pathlib.Path)
    proxy = subparsers.add_parser("proxy")
    proxy.add_argument("--address", default="127.0.0.1")
    proxy.add_argument("--port", type=int, default=18079)
    proxy.add_argument("--target-address", default="127.0.0.1")
    proxy.add_argument("--target-port", type=int, default=18080)
    proxy.add_argument("--output", type=pathlib.Path, required=True)
    unixgram = subparsers.add_parser("unixgram")
    unixgram.add_argument("--path", type=pathlib.Path, required=True)
    unixgram.add_argument("--output", type=pathlib.Path, required=True)
    unixgram.add_argument("--count", type=int, required=True)
    local_scan_fault = subparsers.add_parser("local-scan-fault")
    local_scan_fault.add_argument("--path", type=pathlib.Path, required=True)
    local_scan_fault.add_argument("--ready-output", type=pathlib.Path, required=True)
    local_scan_fault.add_argument("--result-output", type=pathlib.Path, required=True)
    local_scan_fault.add_argument(
        "--mode", choices=("timeout", "crash", "close"), required=True
    )
    evidence_fault = subparsers.add_parser("evidence-fault")
    evidence_fault.add_argument("--record", type=pathlib.Path, required=True)
    evidence_fault.add_argument("--key-file", type=pathlib.Path, required=True)
    evidence_fault.add_argument(
        "--mode", choices=("expired", "tampered"), required=True
    )
    unpack = subparsers.add_parser("unpack")
    unpack.add_argument("--capture", type=pathlib.Path, required=True)
    unpack.add_argument("--message-output", type=pathlib.Path, required=True)
    unpack.add_argument("--metadata-output", type=pathlib.Path, required=True)
    unpack.add_argument("--require-owned-fields", action="store_true")
    inspect_set = subparsers.add_parser("inspect-capture-set")
    inspect_set.add_argument("--capture", type=pathlib.Path, required=True)
    inspect_set.add_argument("--metadata-output", type=pathlib.Path, required=True)
    filter_fault = subparsers.add_parser("filter-fault")
    filter_fault.add_argument("--mode", choices=("nonzero", "partial"), required=True)
    filter_fault.add_argument("--result-output", type=pathlib.Path, required=True)
    filter_fault.add_argument("filter_command", nargs=argparse.REMAINDER)
    return parser.parse_args()


def main() -> int:
    """Run the selected bounded qualification service."""
    arguments = parse_arguments()
    if arguments.command == "dns":
        run_dns(arguments.address, arguments.port, arguments.records)
    elif arguments.command == "smtp":
        run_smtp(
            arguments.address,
            arguments.port,
            arguments.output,
            arguments.ready_output,
            arguments.count,
        )
    elif arguments.command == "smtp-abort":
        run_smtp_abort_peer(
            arguments.address,
            arguments.port,
            arguments.output,
            arguments.ready_output,
        )
    elif arguments.command == "smtp-client":
        run_smtp_client(
            arguments.address,
            arguments.port,
            arguments.sender,
            arguments.recipient,
            arguments.message,
            arguments.wire_format,
            arguments.smtp_utf8,
            arguments.output,
        )
    elif arguments.command == "http":
        run_http(arguments.address, arguments.port, arguments.mode, arguments.output)
    elif arguments.command == "proxy":
        run_proxy(
            arguments.address,
            arguments.port,
            arguments.target_address,
            arguments.target_port,
            arguments.output,
        )
    elif arguments.command == "unixgram":
        run_unixgram(arguments.path, arguments.output, arguments.count)
    elif arguments.command == "local-scan-fault":
        run_local_scan_fault(
            arguments.path,
            arguments.ready_output,
            arguments.result_output,
            arguments.mode,
        )
    elif arguments.command == "evidence-fault":
        mutate_evidence_record(
            arguments.record,
            arguments.key_file,
            arguments.mode,
        )
    elif arguments.command == "unpack":
        run_unpack(
            arguments.capture,
            arguments.message_output,
            arguments.metadata_output,
            arguments.require_owned_fields,
        )
    elif arguments.command == "inspect-capture-set":
        inspect_capture_set(arguments.capture, arguments.metadata_output)
    elif arguments.command == "filter-fault":
        command = arguments.filter_command
        if command[:1] == ["--"]:
            command = command[1:]
        return run_filter_fault(arguments.mode, arguments.result_output, command)
    elif arguments.command == "inspect-message":
        inspect_message(
            arguments.message,
            arguments.wire_format,
            arguments.metadata_output,
        )
    else:
        return 2
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"qualification helper failed: {type(error).__name__}", file=sys.stderr)
        raise SystemExit(1) from None
